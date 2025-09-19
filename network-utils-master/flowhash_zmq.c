/*********************************************************************
 *  flowhash_zmq.c – track first 40 packets of every bi-directional flow
 *               (5-tuple key). When a flow finishes (TCP: FIN flags in both
 *               directions OR UDP: idle timer triggers), the flow record
 *               is dumped and sent as a JSON object via ZeroMQ.
 *
 *  Flow records are transmitted using a ZeroMQ PUSH socket bound to
 *  "ipc:///tmp/flowpipe". The JSON output includes client/server IPs
 *  and ports, protocol, packet count, and arrays for timestamps and
 *  signed packet lengths (client→server as positive values, server→client
 *  as negative values).
 *
 *  Key Details:
 *    • Hash key: FNV-1a 32-bit hash of the **canonical** tuple, where the
 *      canonical order = sort(srcIP,dstIP) | sort(srcPort,dstPort) | proto.
 *    • Hash table: open addressing using 1024 buckets (resizable as needed).
 *    • Flow entry payload: five-tuple plus up to 40 (timestamp, length) pairs.
 *
 *  Usage:
 *    gcc flowhash_zmq.c -std=c11 -Wall -O2 -lpcap $(pkg-config --cflags --libs jansson libzmq) -pthread -o flowhash_zmq
 *    ./flowhash_zmq <pcap_file>
 *********************************************************************/
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
//  #include <netinet/ether.h> replaced by  #include <netinet/if_ether.h> for macOS
#include <netinet/if_ether.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <zmq.h>
#include <jansson.h> 

#define TABLE_SIZE      65536*2
#define FLOW_CAP        40
#define UDP_IDLE_SEC    30          /* flush UDP flow after 5 s of silence */
#define BUF_MAX   10
#define BATCH_SIZE 1
#define SHOW_OUTPUT 0

/* ---------- tiny FNV-1a 32-bit ---------- */
static uint32_t fnv1a_32(const char *s)
{
    uint32_t h = 0x811c9dc5u;
    while (*s) {
        h ^= (uint8_t)(*s++);
        h *= 0x01000193u;
    }
    return h;
}

/* ---------- flow key & entry ---------- */
typedef struct {
    uint32_t ip1, ip2;             /* canonical order (lowest-to-highest) */
    uint16_t port1, port2;         /* canonical order */
    uint8_t  proto;                /* IPPROTO_TCP / _UDP */
} flow_key_t;

typedef struct {
    int      in_use;
    flow_key_t key;                /* for collision testing              */
    /* original orientation (saved from first SYN or first UDP packet)   */
    uint32_t cli_ip, srv_ip;
    uint16_t cli_port, srv_port;

    /* TCP end flags & protocol flag */
    int      is_udp;
    int      fin_cli_done, fin_srv_done;

    /* packet history */
    struct timeval ts[FLOW_CAP];
    int32_t        len[FLOW_CAP];  /* sign marks direction */
    int            count;

    /* last-seen for UDP idle detection */
    struct timeval last_seen;
} flow_entry_t;

static flow_entry_t table[TABLE_SIZE] = {0};

typedef struct {
    flow_entry_t slot;        /* deep‑copy of flow (ts & len arrays)   */
    int          used;
} buf_item_t;

static buf_item_t flow_buf[BUF_MAX];
static size_t     head = 0, tail = 0, fill = 0;
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  cond_full = PTHREAD_COND_INITIALIZER;

/* ---------- encode & push one flow_entry_t ----------------------- */
static void push_entry(void *sock, const flow_entry_t *f)
{
    /* --- header fields --- */
    char cli[INET_ADDRSTRLEN], srv[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &f->cli_ip, cli, sizeof cli);
    inet_ntop(AF_INET, &f->srv_ip, srv, sizeof srv);

    json_t *root = json_object();
    json_object_set_new(root, "cli_ip",   json_string(cli));
    json_object_set_new(root, "srv_ip",   json_string(srv));
    json_object_set_new(root, "cli_port", json_integer(f->cli_port));
    json_object_set_new(root, "srv_port", json_integer(f->srv_port));
    json_object_set_new(root, "count",    json_integer(f->count));
    json_object_set_new(root, "proto",    json_string(f->is_udp ? "UDP" : "TCP"));

    /* --- packet‑by‑packet vectors -------------------------------- */
    json_t *ts_arr  = json_array();
    json_t *len_arr = json_array();
    double ts_0 = f->ts[0].tv_sec + f->ts[0].tv_usec / 1e6;
    for (int i = 0; i < f->count; ++i) {
        double ts_i = f->ts[i].tv_sec + f->ts[i].tv_usec / 1e6;
        if (f->len[i] < 0) ts_i = -1 * ts_i;
        json_array_append_new(ts_arr,  json_real(ts_i - ts_0));
        json_array_append_new(len_arr, json_integer(f->len[i]));
    }
    json_object_set_new(root, "ts",  ts_arr);   /* timestamps  */
    json_object_set_new(root, "len", len_arr);  /* signed lens */

    /* --- dump & send --------------------------------------------- */
    char *txt = json_dumps(root, JSON_COMPACT);
    // printf("JSON: %s\n", txt);
    fflush(stdout);
    zmq_send(sock, txt, strlen(txt), 0);
    free(txt);
    json_decref(root);
}

static json_t* json_flow_entry(const flow_entry_t *f) {
    char cli[INET_ADDRSTRLEN], srv[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &f->cli_ip, cli, sizeof cli);
    inet_ntop(AF_INET, &f->srv_ip, srv, sizeof srv);

    json_t *root = json_object();
    json_object_set_new(root, "cli_ip",   json_string(cli));
    json_object_set_new(root, "srv_ip",   json_string(srv));
    json_object_set_new(root, "cli_port", json_integer(f->cli_port));
    json_object_set_new(root, "srv_port", json_integer(f->srv_port));
    json_object_set_new(root, "count",    json_integer(f->count));
    json_object_set_new(root, "proto",    json_string(f->is_udp ? "UDP" : "TCP"));

    json_t *ts_arr  = json_array();
    json_t *len_arr = json_array();
    double ts_0 = f->ts[0].tv_sec + f->ts[0].tv_usec / 1e6;
    for (int i = 0; i < f->count; ++i) {
        double ts_i = f->ts[i].tv_sec + f->ts[i].tv_usec / 1e6;
        json_array_append_new(ts_arr,  json_real(ts_i - ts_0));
        json_array_append_new(len_arr, json_integer(f->len[i]));
    }
    json_object_set_new(root, "ts",  ts_arr);
    json_object_set_new(root, "len", len_arr);

    return root;
}

static void *sender_thread(void *arg)
{
    void  *ctx  = zmq_ctx_new();
    void  *sock = zmq_socket(ctx, ZMQ_PUSH);
    zmq_bind(sock, "ipc:///tmp/flowpipe");

    while (1) {
        pthread_mutex_lock(&mtx);
        // Wait until there are at least BATCH_SIZE items in the buffer (or shutdown signaled)
        while (fill < BUF_MAX / 5 && fill < BATCH_SIZE && !(*(int *)arg))
            pthread_cond_wait(&cond_full, &mtx);

        // Create a JSON array to hold the batch.
        json_t *batch_arr = json_array();
        int count = 0;

        // Dequeue up to BATCH_SIZE items.
        while (fill && count < BATCH_SIZE) {
            buf_item_t item = flow_buf[tail];
            flow_buf[tail].used = 0;
            tail = (tail + 1) % BUF_MAX;
            fill--;
            count++;

            // Create JSON object for this flow entry and add to array.
            json_t *entry = json_flow_entry(&item.slot);
            json_array_append_new(batch_arr, entry);
        }
        pthread_mutex_unlock(&mtx);

        // Send the batch if array not empty.
        if (json_array_size(batch_arr) > 0) {
            char *txt = json_dumps(batch_arr, JSON_COMPACT);
            // Optionally print the batch: printf("BATCH: %s\n", txt);
            printf("---------SIZE: %d=============\n", count);
            printf("BATCH: %s\n\n\n", txt);
            zmq_send(sock, txt, strlen(txt), 0);
            free(txt);
        }
        json_decref(batch_arr);

        if (*(int *)arg) break;   /* exit if signaled */
    }
    zmq_close(sock);
    zmq_ctx_term(ctx);
    return NULL;
}

/* --------- ZeroMQ context/socket live in the sender thread -------- */
static void *sender_thread_single(void *arg)
{
    void  *ctx  = zmq_ctx_new();
    void  *sock = zmq_socket(ctx, ZMQ_PUSH);
    zmq_bind(sock, "ipc:///tmp/flowpipe");

    while (1) {
        pthread_mutex_lock(&mtx);
        while (fill < BUF_MAX / 5 && !(*(int *)arg))             /* arg==0 until exit */
            pthread_cond_wait(&cond_full, &mtx);

        /* consume everything currently in buffer */
        while (fill) {
            buf_item_t item = flow_buf[tail];
            flow_buf[tail].used = 0;
            tail = (tail + 1) % BUF_MAX;  fill--;

            pthread_mutex_unlock(&mtx);   /* ---- encode & send unlock ---- */
            push_entry(sock, &item.slot);
            pthread_mutex_lock(&mtx);     /* ---- relock for next element -- */
        }
        pthread_mutex_unlock(&mtx);
        if (*(int *)arg) break;           /* graceful shutdown               */
    }
    zmq_close(sock);  zmq_ctx_term(ctx);  return NULL;
}


/* ------------ producer side called from dump_and_clear() ----------- */
static inline void enqueue_flow(const flow_entry_t *src)
{
    pthread_mutex_lock(&mtx);
    if (fill == BUF_MAX) {                       /* should not happen ‑‑ but
                                                    drop oldest if producer
                                                    outruns consumer          */
        tail = (tail + 1) % BUF_MAX;  fill--;
    }
    flow_buf[head].slot = *src;   flow_buf[head].used = 1;
    head = (head + 1) % BUF_MAX;  fill++;

    if (fill == BUF_MAX)                         /* wake sender when full */
        pthread_cond_signal(&cond_full);
    pthread_mutex_unlock(&mtx);
}

/* ------------ init & graceful exit helpers ------------------------- */
static pthread_t th;
static int       exiting = 0;

static void buf_init(void)
{
    pthread_create(&th, NULL, sender_thread, &exiting);
}

static void program_exit(void)
{
    pthread_mutex_lock(&mtx);              /* tell sender to flush tail   */
    pthread_cond_signal(&cond_full);
    exiting = 1;
    pthread_mutex_unlock(&mtx);
    pthread_join(th, NULL);
}

/* ---------- helpers ---------- */
static int compare_key(const flow_key_t *a, const flow_key_t *b)
{
    return !(a->ip1 == b->ip1 && a->ip2 == b->ip2 &&
             a->port1 == b->port1 && a->port2 == b->port2 &&
             a->proto == b->proto);
}

/* canonicalise addresses/ports so A⇆B maps to same bucket as B⇆A */
static flow_key_t make_key(uint32_t s_ip, uint32_t d_ip,
                           uint16_t s_pt, uint16_t d_pt,
                           uint8_t proto)
{
    flow_key_t k;
    if (ntohl(s_ip) < ntohl(d_ip)) { 
        k.ip1 = s_ip; 
        k.ip2 = d_ip; 
        k.port1 = s_pt; 
        k.port2 = d_pt; 
    }
    else if (ntohl(s_ip) > ntohl(d_ip)) { 
        k.ip1 = d_ip; 
        k.ip2 = s_ip; 
        k.port1 = d_pt; 
        k.port2 = s_pt; 
    }
    else {  /* equal IPs – sort by port */
        k.ip1 = s_ip; 
        k.ip2 = d_ip;
        if (s_pt > d_pt) { uint16_t t = s_pt; s_pt = d_pt; d_pt = t; }
    }

    // if (s_pt < d_pt) { k.port1 = s_pt; k.port2 = d_pt; }
    // else              { k.port1 = d_pt; k.port2 = s_pt; }
    k.proto = proto;
    return k;
}

/* find bucket index (linear-probe if collision) */
static int find_bucket(const flow_key_t *key, uint32_t hash, int *found)
{
    uint32_t idx = hash % TABLE_SIZE; // check only for the current index and don't do linear probing to find next available spot
    for (int i = 0; i < TABLE_SIZE; ++i) {
        uint32_t p = (idx + i) & (TABLE_SIZE - 1);
        if (!table[p].in_use) { *found = 0; return p; }          /* empty slot   */
        if (!compare_key(&table[p].key, key)) { *found = 1; return p; } /* match */
    }
    return -1;  /* table full – shouldn’t happen for small captures */
}

/* flush entry to stdout and zero it */
static void dump_and_clear(flow_entry_t *e)
{
    if (SHOW_OUTPUT == 1) {
        char ip_cli[INET_ADDRSTRLEN], ip_srv[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &e->cli_ip, ip_cli, sizeof ip_cli);
        inet_ntop(AF_INET, &e->srv_ip, ip_srv, sizeof ip_srv);
    
        printf("\n=== Flow %s:%u ⇆ %s:%u (%s) packets:%d ===\n",
               ip_cli, e->cli_port, ip_srv, e->srv_port,
               e->is_udp ? "UDP" : "TCP", e->count);
        double ts_0 = e->ts[0].tv_sec + e->ts[0].tv_usec / 1e6;
        for (int i = 0; i < e->count; ++i) {
            double ts = e->ts[i].tv_sec + e->ts[i].tv_usec / 1e6;
            printf("%.6f  len=%d\n", ts - ts_0, e->len[i]);
        }
        fflush(stdout);
    }
    enqueue_flow(e); 
    memset(e, 0, sizeof *e);
}

/* called once per received packet */
static void track_packet(const struct timeval *tv,
                         uint32_t sip, uint32_t dip,
                         uint16_t sport, uint16_t dport,
                         uint8_t proto,
                         int tcp_syn, int tcp_fin,
                         u_short ip_len)
{
    /* --- build canonical key & bucket --- */
    flow_key_t key = make_key(sip, dip, sport, dport, proto);

    char keybuf[128];
    snprintf(keybuf, sizeof keybuf, "%08x%04x%08x%04x%02x",
        key.ip1, key.port1, key.ip2, key.port2, key.proto);
    uint32_t h = fnv1a_32(keybuf);

    int found;
    int idx = find_bucket(&key, h, &found);
    if (idx < 0) { fprintf(stderr,"Hash table full\n"); return; }

    flow_entry_t *e = &table[idx];

    /* --------------- CASE 1: empty bucket ---------------- */
    if (!found) {
        /* TCP → accept only SYN from client   */
        if (proto == IPPROTO_TCP && !tcp_syn) return;

        /* create new entry */
        e->in_use   = 1;
        e->key      = key;
        e->count    = 0;
        e->is_udp   = (proto == IPPROTO_UDP);
        e->fin_cli_done = e->fin_srv_done = 0;
        e->cli_ip   = sip;
        e->srv_ip   = dip;
        e->cli_port = sport;
        e->srv_port = dport;
    }

    /* --------------- verify tuple matches (collision) ---- */
    if (compare_key(&e->key, &key)) return;   /* not ours → ignore */

    /* --------------- add packet to history (≤40) --------- */
    if (e->count < FLOW_CAP) {
        /* determine direction */
        int from_client = (sip == e->cli_ip && sport == e->cli_port); // match only the sip
        int32_t sign = from_client ? +1 : -1;

        e->ts[e->count]  = *tv; // save the time stamps relative to the first packet timestamp (cur time - 1st packet time)
        e->len[e->count] = sign * (ip_len);  /* pkt length passed in len slot */
        e->count++;
    }

    /* --------------- update FIN / timer ------------------ */
    if (!e->is_udp) {        /* TCP */
        if (tcp_fin) {
            if (sip == e->cli_ip && sport == e->cli_port)  e->fin_cli_done = 1;
            else                                           e->fin_srv_done = 1;
            if (e->fin_cli_done && e->fin_srv_done && e->count == FLOW_CAP)
                dump_and_clear(e);
        }
    } else {                 /* UDP → idle timer */
        e->last_seen = *tv;
    }
}

/* scan entire table for idle UDP flows ≥5 s */
static void flush_idle_udp(const struct timeval *now)
{
    for (int i = 0; i < TABLE_SIZE; ++i) {
        flow_entry_t *e = &table[i];
        if (!e->in_use || !e->is_udp) continue;
        if ((now->tv_sec - e->last_seen.tv_sec) >= UDP_IDLE_SEC)
            dump_and_clear(e);
    }
}

/* -------------------------------------------------------- */
/* The original packet-parsing helper, trimmed to hand back the
 * numeric fields needed by the tracker.                                    */
static int parse_and_track(const struct pcap_pkthdr *h,
                           const u_char *pkt)
{
    const struct ether_header *eth = (const struct ether_header *)pkt;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return 0;

    const struct ip *iph = (const struct ip *)(pkt + sizeof *eth);
    uint8_t proto = iph->ip_p;

    uint32_t sip = iph->ip_src.s_addr;
    uint32_t dip = iph->ip_dst.s_addr;

    uint16_t sport=0, dport=0;
    int tcp_syn=0, tcp_fin=0;

    /* IP header length */
    int ip_hl = iph->ip_hl * 4;

    if (proto == IPPROTO_TCP) {
        const struct tcphdr *th = (const struct tcphdr *)
              (pkt + sizeof *eth + ip_hl);
        sport   = ntohs(th->th_sport);
        dport   = ntohs(th->th_dport);
        tcp_syn = (th->th_flags & TH_SYN) != 0;
        tcp_fin = (th->th_flags & TH_FIN) != 0;
    } else if (proto == IPPROTO_UDP) {
        const struct udphdr *uh = (const struct udphdr *)
              (pkt + sizeof *eth + ip_hl);
        sport = ntohs(uh->uh_sport);
        dport = ntohs(uh->uh_dport);
    } else return 0;   /* ignore non-TCP/UDP */

    u_short ip_length = ntohs(iph->ip_len);
    track_packet(&h->ts, sip, dip, sport, dport, proto,
                 tcp_syn, tcp_fin, ip_length);
    return 1;
}

/* --------------------- main ----------------------------- */
int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s file.pcap\n", argv[0]);
        return 1;
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pc = pcap_open_offline(argv[1], errbuf);
    if (!pc) { fprintf(stderr,"pcap_open: %s\n", errbuf); return 1; }
    buf_init();
    struct pcap_pkthdr *h; 
    const u_char *pkt;
    int rc;
    int pkt_count = 0;
    while ((rc = pcap_next_ex(pc, &h, &pkt)) >= 0) {
        if (rc == 0) continue;               /* timeout in live capture */
        parse_and_track(h, pkt);
        pkt_count += 1;
        flush_idle_udp(&h->ts);

    }
    if (rc == -1) fprintf(stderr,"pcap read error: %s\n", pcap_geterr(pc));

    /* flush anything still pending (e.g., long-lived TCP) */
    struct timeval final_tv = {0};
    gettimeofday(&final_tv, NULL);
    flush_idle_udp(&final_tv);      /* forces any dangling UDP out */
    for (int i = 0; i < TABLE_SIZE; ++i)
        if (table[i].in_use) dump_and_clear(&table[i]);

    pcap_close(pc);
    program_exit();
    return 0;
}
