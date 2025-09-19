/*
 * pcap_parser.c
 *
 * Description:
 *   A simple pcap parser that reads packets from a pcap file,
 *   processes each packet to extract TCP and UDP details,
 *   and prints information about the packets such as timestamps,
 *   source and destination IPs, ports, protocol type, and packet length.
 *
 * Usage:
 *   gcc -Wall -Wextra -o pcap_parser pcap_parser.c -lpcap
 *   ./pcap_parser <pcap_file>
 */
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#define SHOW_OUTPUT 0

int process_packet(const struct pcap_pkthdr *header, const u_char *packet) {
    // Add check for minimum packet length
    if (header->caplen < sizeof(struct ether_header)) {
        return 0;
    }
    struct ether_header *eth_header = (struct ether_header *)packet;
    uint16_t ether_type = ntohs(eth_header->ether_type);

    // Handle both regular IP and 802.1Q VLAN tagged frames
    int ip_start = sizeof(struct ether_header);
    if (ether_type == ETHERTYPE_VLAN) {
        ip_start += 4;  // Skip VLAN tag
        if (header->caplen < ip_start + sizeof(struct ip)) {
            return 0;
        }
        // Get actual ethertype after VLAN tag
        ether_type = ntohs(*(uint16_t *)(packet + sizeof(struct ether_header) + 2));
    }

    // Check if it's an IP packet
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return 0;
    }

    // IP header comes right after Ethernet header (14 bytes)
    struct ip *ip_hdr = (struct ip *)(packet + ip_start);

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

    // Get protocol
    uint8_t protocol = ip_hdr->ip_p;

    // Transport header (after IP header, which can be variable length)
    int ip_header_len = ip_hdr->ip_hl * 4;
    const u_char *transport_hdr = packet + sizeof(struct ether_header) + ip_header_len;

    uint16_t src_port = 0, dst_port = 0;
    // Retrieve IP total length from IP header
    u_short ip_length = ntohs(ip_hdr->ip_len);
    
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp_hdr = (struct tcphdr *)transport_hdr;
        src_port = ntohs(tcp_hdr->th_sport);
        dst_port = ntohs(tcp_hdr->th_dport);
        // Retrieve TCP flags
        int th_fin = (tcp_hdr->th_flags & TH_FIN) ? 1 : 0;
        int th_syn = (tcp_hdr->th_flags & TH_SYN) ? 1 : 0;
        int th_rst = (tcp_hdr->th_flags & TH_RST) ? 1 : 0;
        int th_ack_flag = (tcp_hdr->th_flags & TH_ACK) ? 1 : 0;

        // Retrieve sequence and acknowledgement numbers
        tcp_seq th_seq = ntohl(tcp_hdr->th_seq);
        tcp_seq th_ack_num = ntohl(tcp_hdr->th_ack);
        // TCP details
        if (SHOW_OUTPUT == 1) {
            printf("TCP Packet Details: seq=%u, ack=%u, flags: FIN=%d, SYN=%d, RST=%d, ACK=%d\n",
            th_seq, th_ack_num, th_fin, th_syn, th_rst, th_ack_flag);
        }
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp_hdr = (struct udphdr *)transport_hdr;
        src_port = ntohs(udp_hdr->uh_sport);
        dst_port = ntohs(udp_hdr->uh_dport);
    }
    const char *proto_str = NULL;
    if (protocol == IPPROTO_TCP) {
        proto_str = "TCP";
    } else if (protocol == IPPROTO_UDP) {
        proto_str = "UDP";
    }
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        if (SHOW_OUTPUT == 1) {
            printf("Timestamp: %ld.%06ld | ", header->ts.tv_sec, header->ts.tv_usec);
            printf("5-tuple: %s -> %s | ", src_ip, dst_ip);
            printf("Ports: %u -> %u | Protocol: %s | ", src_port, dst_port, proto_str);
            printf("Packet Length: %u\n", ip_length);
        }
    }
    return ip_length;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pcap_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open file %s: %s\n", argv[1], errbuf);
        return EXIT_FAILURE;
    }

    struct pcap_pkthdr *header;
    const u_char *packet;
    int result;
    uint64_t packet_length = 0;
    uint64_t packet_count = 0;
    uint64_t total_packet_size = 0;
    while ((result = pcap_next_ex(handle, &header, &packet)) >= 0) {
        packet_length = process_packet(header, packet);
        packet_count += 1;
        total_packet_size += packet_length;
    }

    if (result == -1) {
        fprintf(stderr, "Error reading the packets: %s\n", pcap_geterr(handle));
    }

    printf("Total packets read: %llu\n", packet_count);
    printf("Total packets size: %llu\n", total_packet_size);

    pcap_close(handle);
    return EXIT_SUCCESS;
}
