/*********************************************************************
 *  flowhash.c – track first 40 packets of every bi-directional flow
 *               (5-tuple key) and dump them when the flow finishes
 *               (TCP → see FIN + FIN, UDP → idle‑timer 5 s).
 *
 *  • Hash key:  FNV‑1a 32 of the **canonical** tuple
 *               canonical order = sort(srcIP,dstIP) | sort(srcPort,dstPort) | proto
 *  • Hash table: open addressing, dynamically sized (power‑of‑2 required)
 *  • Per‑bucket payload (flow_entry): five‑tuple + 40 (timestamp,len) pairs
 *  • client→server traffic is stored as timestamp / +len
 *    server→client traffic is stored as timestamp / –len
 *
 *  Usage:
 *    gcc -O3 -std=c11 -Wall flowhash.c -o flowhash -lpcap
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

/* tunable parameters */
#define FLOW_CAP        40
#define UDP_IDLE_SEC    30          /* flush UDP flow after 5 s of silence */
#define WRITE_TO_CSV 0
#define SHOW_OUTPUT 0
#define TABLE_SIZE      65536*2


/* ---------- tiny FNV‑1a 32‑bit ---------- */
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
    uint32_t ip1, ip2;             /* canonical order (lowest‑to‑highest) */
    uint16_t port1, port2;         /* canonical order */
    uint8_t  proto;                /* IPPROTO_TCP / _UDP */
} flow_key_t;

typedef struct {
    int      in_use;
    flow_key_t key;                /* for collision testing              */
    /* original orientation (saved from first SYN or first UDP packet) */
    uint32_t cli_ip, srv_ip;
    uint16_t cli_port, srv_port;
    /* TCP end flags & protocol flag */
    int      is_udp;
    int      fin_cli_done, fin_srv_done;
    /* packet history */
    struct timeval ts[FLOW_CAP];
    int32_t        len[FLOW_CAP];  /* sign marks direction */
    int            count;
    /* last‑seen for UDP idle detection */
    struct timeval last_seen;
} flow_entry_t;

/* global variables for dynamic table */
static flow_entry_t *table = NULL;

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
    k.proto = proto;
    return k;
}

/* find bucket index (linear‑probe if collision) */
static int find_bucket(const flow_key_t *key, uint32_t hash, int *found)
{
    uint32_t idx = hash % TABLE_SIZE;
    for (size_t i = 0; i < TABLE_SIZE; ++i) {
        uint32_t p = (idx + i) & (TABLE_SIZE - 1);
        if (!table[p].in_use) { *found = 0; return p; }          /* empty slot */
        if (!compare_key(&table[p].key, key)) { *found = 1; return p; } /* match */
    }
    return -1;  /* table full – shouldn’t happen for small captures */
}

static void write_to_csv(flow_entry_t *e)
{
    if (e->count == FLOW_CAP) {
        char ip_small[INET_ADDRSTRLEN], ip_large[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &e->key.ip1, ip_small, sizeof(ip_small));
        inet_ntop(AF_INET, &e->key.ip2, ip_large, sizeof(ip_large));

        char input_field[256];
        snprintf(input_field, sizeof(input_field), "%s%d%s%d%s",
                ip_small, e->key.port1, ip_large, e->key.port2,
                e->is_udp ? "UDP" : "TCP");

        /* Build the feature vector string.
        Each tuple is (time_offset, signed length) calculated relative
        to the timestamp of the first packet. */
        char feature_vector[4096];
        feature_vector[0] = '\0';
        strcat(feature_vector, "[");
        double ts_0 = e->ts[0].tv_sec + e->ts[0].tv_usec / 1e6;
        char tuple[64];
        for (int i = 0; i < e->count; ++i) {
            double ts = e->ts[i].tv_sec + e->ts[i].tv_usec / 1e6;
            double offset = ts - ts_0;
            if (e->len[i] < 0) {
                offset *= -1;
            }
            snprintf(tuple, sizeof(tuple), "(%.6f, %.1f)", offset, (double)e->len[i]);
            strcat(feature_vector, tuple);
            if (i < e->count - 1)
                strcat(feature_vector, ", ");
        }
        strcat(feature_vector, "]");

        /* Write CSV fields (input, feature vector) to file */
        FILE *f = fopen("flow_output.csv", "a");
        if (!f) {
            perror("fopen");
            exit(1);
        }
        fprintf(f, "%s,\"%s\"\n", input_field, feature_vector);
        fclose(f);
    }
}

/* flush entry to stdout and zero it */
static void dump_and_clear(flow_entry_t *e)
{
    if (WRITE_TO_CSV == 1) {
        write_to_csv(e);
    }
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
    if (idx < 0) { 
        fprintf(stderr,"Hash table full\n"); 
        return; 
    }
    // printf("Keybuf: %s, Hash: %d, Found: %d, Protocol: %d\n", keybuf, h, found, proto);
    flow_entry_t *e = &table[idx];

    /* --------------- CASE 1: empty bucket ---------------- */
    if (!found) {
        /* TCP → accept only SYN from client */
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
    if (compare_key(&e->key, &key)) return;   /* not our flow → ignore */

    /* --------------- add packet to history (≤ FLOW_CAP) --------- */
    if (e->count < FLOW_CAP) {
        /* determine direction */
        int from_client = (sip == e->cli_ip && sport == e->cli_port);
        int32_t sign = from_client ? +1 : -1;
        e->ts[e->count]  = *tv;
        e->len[e->count] = sign * (ip_len);
        e->count++;
    }

    /* --------------- update FIN / timer ------------------ */
    if (proto != IPPROTO_UDP) {        /* TCP */
        if (tcp_fin) {
            if (sip == e->cli_ip && sport == e->cli_port)  e->fin_cli_done = 1;
            else                                           e->fin_srv_done = 1;
            if (e->fin_cli_done && e->fin_srv_done && e->count == FLOW_CAP)
                dump_and_clear(e);
        }
    } else {                 /* UDP → update idle timer */
        e->last_seen = *tv;
    }
}

/* scan entire table for idle UDP flows ≥ UDP_IDLE_SEC */
static void flush_idle_udp(const struct timeval *now)
{
    for (size_t i = 0; i < TABLE_SIZE; ++i) {
        flow_entry_t *e = &table[i];
        if (!e->in_use || !e->is_udp) continue;
        if ((now->tv_sec - e->last_seen.tv_sec) >= UDP_IDLE_SEC)
            dump_and_clear(e);
    }
}

/* -------------------------------------------------------- */
/* The packet‑parsing helper: extracts numeric fields and tracks packet */
static int parse_and_track(const struct pcap_pkthdr *h, const u_char *pkt)
{
    const struct ether_header *eth = (const struct ether_header *)pkt;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return 0;

    const struct ip *iph = (const struct ip *)(pkt + sizeof *eth);
    uint8_t proto = iph->ip_p;

    uint32_t sip = iph->ip_src.s_addr;
    uint32_t dip = iph->ip_dst.s_addr;

    uint16_t sport = 0, dport = 0;
    int tcp_syn = 0, tcp_fin = 0;

    /* IP header length */
    int ip_hl = iph->ip_hl * 4;

    if (proto == IPPROTO_TCP) {
        const struct tcphdr *th = (const struct tcphdr *)(pkt + sizeof *eth + ip_hl);
        sport   = ntohs(th->th_sport);
        dport   = ntohs(th->th_dport);
        tcp_syn = (th->th_flags & TH_SYN) != 0;
        tcp_fin = (th->th_flags & TH_FIN) != 0;
    } else if (proto == IPPROTO_UDP) {
        const struct udphdr *uh = (const struct udphdr *)(pkt + sizeof *eth + ip_hl);
        sport = ntohs(uh->uh_sport);
        dport = ntohs(uh->uh_dport);
    } else {
        return 0;   /* ignore non-TCP/UDP */
    }

    u_short ip_length = ntohs(iph->ip_len);
    track_packet(&h->ts, sip, dip, sport, dport, proto, tcp_syn, tcp_fin, ip_length);
    return 1;
}

/* --------------------- main ----------------------------- */
int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <file.pcap>\n", argv[0]);
        return 1;
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pc = pcap_open_offline(argv[1], errbuf);
    if (!pc) { 
        fprintf(stderr, "pcap_open: %s\n", errbuf); 
        return 1; 
    }
    
    /* Allocate the hash table dynamically and initialize to zero */
    table = calloc(TABLE_SIZE, sizeof(flow_entry_t));
    if (!table) { 
        perror("calloc"); 
        return 1; 
    }
    
    struct pcap_pkthdr *h; 
    const u_char *pkt;
    int rc;
        
    while ((rc = pcap_next_ex(pc, &h, &pkt)) >= 0) {
        if (rc == 0) continue;               /* timeout in live capture */
        parse_and_track(h, pkt);
        flush_idle_udp(&h->ts);
        
    }
    if (rc == -1) 
        fprintf(stderr, "pcap read error: %s\n", pcap_geterr(pc));
    
    /* flush any remaining flows (e.g., long‐lived TCP) */
    struct timeval final_tv = {0};
    gettimeofday(&final_tv, NULL);
    flush_idle_udp(&final_tv);
    for (size_t i = 0; i < TABLE_SIZE; ++i)
        if (table[i].in_use) 
            dump_and_clear(&table[i]);
    
    pcap_close(pc);
    free(table);
    return 0;
}