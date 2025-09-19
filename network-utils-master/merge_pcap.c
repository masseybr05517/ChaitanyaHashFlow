/*
 * merge_pcap.c  —  merge many .pcap files into one, simulating N
 *                  concurrent “sessions / users”.
 *
 *  Build :  gcc -O2 -Wall -o merge_pcap merge_pcap.c -lpcap
 *  Usage :  ./merge_pcap <pcap_dir> <N_sessions> <output.pcap>
 */
#include <dirent.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_FILES 4096
#define MAX_SESS 256

static void die(const char *m) {
  perror(m);
  exit(EXIT_FAILURE);
}

/* ---------- helpers ---------- */
static long usec_diff(const struct timeval *a, const struct timeval *b) {
  return (a->tv_sec - b->tv_sec) * 1000000L + (a->tv_usec - b->tv_usec);
}
static void add_usec(struct timeval *d, long us) {
  d->tv_sec += us / 1000000L;
  d->tv_usec += us % 1000000L;
  if (d->tv_usec >= 1000000L) {
    ++d->tv_sec;
    d->tv_usec -= 1000000L;
  }
}

/* ---------- collect *.pcap ---------- */
static size_t list_pcaps(const char *dir, char *o[], size_t max) {
  DIR *dp = opendir(dir);
  if (!dp) die("opendir");
  struct dirent *d;
  size_t n = 0;
  while ((d = readdir(dp))) {
    if (d->d_type != DT_REG) continue;
    const char *e = strrchr(d->d_name, '.');
    if (!e || strcmp(e, ".pcap")) continue;
    if (n >= max) die("too many pcaps");
    if (asprintf(&o[n++], "%s/%s", dir, d->d_name) == -1) die("asprintf");
  }
  closedir(dp);
  return n;
}

/* ---------- session ---------- */
typedef struct {
  pcap_t *pc;
  char *fname;
  struct timeval first_orig;    /* ts of 1st pkt inside file    */
  struct timeval file_base_abs; /* ts that 1st pkt gets in out  */
  struct timeval last_abs;      /* ts of last pkt output        */
  long start_off_us;            /* 0-2 s random for 1st file    */
  int active;
} session_t;

/* ---------- heap of next packets ---------- */
typedef struct {
  session_t *s;
  struct pcap_pkthdr h;
  const u_char *d;
} item_t;
static int earlier(const item_t *x, const item_t *y) {
  return x->h.ts.tv_sec == y->h.ts.tv_sec ? x->h.ts.tv_usec < y->h.ts.tv_usec
                                          : x->h.ts.tv_sec < y->h.ts.tv_sec;
}
static void swap(item_t *a, item_t *b) {
  item_t t = *a;
  *a = *b;
  *b = t;
}
static void push(item_t *h, int *sz, item_t v) {
  int i = (*sz)++;
  h[i] = v;
  while (i && earlier(&h[i], &h[(i - 1) / 2])) {
    swap(&h[i], &h[(i - 1) / 2]);
    i = (i - 1) / 2;
  }
}
static item_t pop(item_t *h, int *sz) {
  item_t top = h[0];
  h[0] = h[--(*sz)];
  for (int i = 0;;) {
    int l = 2 * i + 1, r = l + 1, s = i;
    if (l < *sz && earlier(&h[l], &h[s])) s = l;
    if (r < *sz && earlier(&h[r], &h[s])) s = r;
    if (s == i) break;
    swap(&h[i], &h[s]);
    i = s;
  }
  return top;
}

/* ---------- open next unused file ---------- */
static void open_next(session_t *s, char **unused, size_t *un, int ltype) {
  while (*un) {
    s->fname = unused[--(*un)];
    s->pc = pcap_open_offline(s->fname, NULL);
    if (!s->pc) {
      fprintf(stderr, "open %s\n", s->fname);
      exit(1);
    }
    if (pcap_datalink(s->pc) != ltype) {
      fprintf(stderr, "linktype mismatch in %s\n", s->fname);
      exit(1);
    }
    struct pcap_pkthdr h;
    if (!pcap_next(s->pc, &h)) {
      pcap_close(s->pc);
      continue;
    }
    s->first_orig = h.ts; /* remember */
    pcap_close(s->pc);    /* rewind */
    s->pc = pcap_open_offline(s->fname, NULL);
    return;
  }
  s->active = 0;
}

/* ---------- main ---------- */
int main(int ac, char **av) {
  if (ac != 4) {
    fprintf(stderr, "usage: %s dir N out.pcap\n", av[0]);
    return 1;
  }
  int N = atoi(av[2]);
  if (N <= 0 || N > MAX_SESS) {
    fprintf(stderr, "bad N\n");
    return 1;
  }
  char *files[MAX_FILES];
  size_t nf = list_pcaps(av[1], files, MAX_FILES);
  if ((size_t)N > nf) {
    fprintf(stderr, "not enough pcaps\n");
    return 1;
  }
  srand((unsigned)time(NULL)); /* shuffle */
  for (size_t i = nf - 1; i; --i) {
    size_t j = rand() % (i + 1);
    char *t = files[i];
    files[i] = files[j];
    files[j] = t;
  }
  pcap_t *t = pcap_open_offline(files[0], NULL);
  if (!t) die("pcap_open");
  int ltype = pcap_datalink(t);
  pcap_close(t);
  pcap_t *dead = pcap_open_dead(ltype, 65535);
  if (!dead) die("dead");
  pcap_dumper_t *dmp = pcap_dump_open(dead, av[3]);
  if (!dmp) die("dump_open");

  session_t S[MAX_SESS] = {0};
  char **unused = files;
  size_t un = nf;
  item_t heap[MAX_SESS];
  int hsz = 0;

  /* ---- initial files ---- */
  for (int i = 0; i < N; ++i) {
    S[i].active = 1;
    S[i].start_off_us = rand() % 2000001L;
    open_next(&S[i], unused, &un, ltype);
    S[i].file_base_abs.tv_sec = S[i].start_off_us / 1000000L;
    S[i].file_base_abs.tv_usec = S[i].start_off_us % 1000000L;
    struct pcap_pkthdr h;
    const u_char *d = pcap_next(S[i].pc, &h);
    struct pcap_pkthdr adj = h;
    adj.ts = S[i].file_base_abs;
    S[i].last_abs = adj.ts;
    push(heap, &hsz, (item_t){.s = &S[i], .h = adj, .d = d});
  }

  /* ---- merge loop ---- */
  while (hsz) {
    item_t it = pop(heap, &hsz);
    session_t *s = it.s;
    pcap_dump((u_char *)dmp, &it.h, it.d);
    s->last_abs = it.h.ts;

    struct pcap_pkthdr h;
    const u_char *d = pcap_next(s->pc, &h);
    if (!d) { /* file finished */
      pcap_close(s->pc);
      open_next(s, unused, &un, ltype);
      if (!s->active) continue;
      s->file_base_abs = s->last_abs; /* CONTINUITY POINT */
      d = pcap_next(s->pc, &h);       /* guaranteed non-NULL */
    }
    long delta = usec_diff(&h.ts, &s->first_orig);
    struct pcap_pkthdr adj = h;
    adj.ts = s->file_base_abs;
    add_usec(&adj.ts, delta);
    push(heap, &hsz, (item_t){.s = s, .h = adj, .d = d});
  }

  /* ---- cleanup ---- */
  pcap_dump_close(dmp);
  pcap_close(dead);
  for (size_t i = 0; i < nf; ++i) free(files[i]);
  return 0;
}
