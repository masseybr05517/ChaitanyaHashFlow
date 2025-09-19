#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <Python.h>

typedef struct {
    char *timestamp;
    char *src_ip;
    char *dst_ip;
    char *src_port;
    char *dst_port;
    char *protocol;
    char *packet_length;
    // TCP specific fields
    char *tcp_seq;
    char *tcp_ack;
    char *tcp_flags;  // e.g. "FIN:1, SYN:1, RST:0, ACK:1"
} packet_info_t;

packet_info_t *process_packet(const struct pcap_pkthdr *header, const u_char *packet) {
    // Allocate structure
    packet_info_t *info = malloc(sizeof(packet_info_t));
    if (!info) return NULL;
    memset(info, 0, sizeof(packet_info_t));

    // Check minimum packet length
    if (header->caplen < sizeof(struct ether_header)) {
        free(info);
        return NULL;
    }
    struct ether_header *eth_header = (struct ether_header *)packet;
    uint16_t ether_type = ntohs(eth_header->ether_type);

    // Handle VLAN tagged frames if needed
    int ip_start = sizeof(struct ether_header);
    if (ether_type == ETHERTYPE_VLAN) {
        ip_start += 4;
        if (header->caplen < ip_start + sizeof(struct ip)) {
            free(info);
            return NULL;
        }
        ether_type = ntohs(*(uint16_t *)(packet + sizeof(struct ether_header) + 2));
    }

    // Check if it's an IP packet
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        free(info);
        return NULL;
    }

    struct ip *ip_hdr = (struct ip *)(packet + ip_start);
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

    // Get protocol
    uint8_t protocol = ip_hdr->ip_p;
    
    // Calculate IP header length and total length
    int ip_header_len = ip_hdr->ip_hl * 4;
    u_short ip_length = ntohs(ip_hdr->ip_len);

    // Prepare common fields (convert numeric types to strings)
    asprintf(&info->timestamp, "%ld.%06ld", header->ts.tv_sec, header->ts.tv_usec);
    info->src_ip = strdup(src_ip);
    info->dst_ip = strdup(dst_ip);
    asprintf(&info->packet_length, "%u", ip_length);

    uint16_t src_port = 0, dst_port = 0;
    const char *proto_str = NULL;

    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header_len);
        src_port = ntohs(tcp_hdr->th_sport);
        dst_port = ntohs(tcp_hdr->th_dport);
        proto_str = "TCP";

        tcp_seq th_seq = ntohl(tcp_hdr->th_seq);
        tcp_seq th_ack_num = ntohl(tcp_hdr->th_ack);
        int th_fin = (tcp_hdr->th_flags & TH_FIN) ? 1 : 0;
        int th_syn = (tcp_hdr->th_flags & TH_SYN) ? 1 : 0;
        int th_rst = (tcp_hdr->th_flags & TH_RST) ? 1 : 0;
        int th_ack_flag = (tcp_hdr->th_flags & TH_ACK) ? 1 : 0;

        asprintf(&info->tcp_seq, "%u", th_seq);
        asprintf(&info->tcp_ack, "%u", th_ack_num);
        asprintf(&info->tcp_flags, "FIN:%d, SYN:%d, RST:%d, ACK:%d",
                 th_fin, th_syn, th_rst, th_ack_flag);
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp_hdr = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_header_len);
        src_port = ntohs(udp_hdr->uh_sport);
        dst_port = ntohs(udp_hdr->uh_dport);
        proto_str = "UDP";
        // No TCP fields for UDP; leave them NULL
    } else {
        free(info);
        return NULL;
    }
    
    asprintf(&info->src_port, "%u", src_port);
    asprintf(&info->dst_port, "%u", dst_port);
    info->protocol = strdup(proto_str);

    return info;
}

typedef struct {
    PyObject_HEAD
    pcap_t *handle;
} PcapReaderObject;

static void
PcapReader_dealloc(PcapReaderObject *self) {
    if (self->handle)
        pcap_close(self->handle);
    Py_TYPE(self)->tp_free((PyObject *)self);
}

static int
PcapReader_init(PcapReaderObject *self, PyObject *args, PyObject *kwds) {
    char *filename;
    if (!PyArg_ParseTuple(args, "s", &filename))
        return -1;
    char errbuf[PCAP_ERRBUF_SIZE];
    self->handle = pcap_open_offline(filename, errbuf);
    if (!self->handle) {
        PyErr_SetString(PyExc_RuntimeError, errbuf);
        return -1;
    }
    return 0;
}

static PyObject *
PcapReader_iter(PyObject *self) {
    Py_INCREF(self);
    return self;
}

static PyObject *
PcapReader_iternext(PcapReaderObject *self) {
    const struct pcap_pkthdr *header;
    const u_char *packet;
    int res;

    // Loop until we get a valid packet or reach end-of-file.
    while ((res = pcap_next_ex(self->handle, &header, &packet)) == 0) {
        // no packet ready, continue looping.
        continue;
    }

    if (res == -1) {
        PyErr_SetString(PyExc_RuntimeError, pcap_geterr(self->handle));
        return NULL;
    }
    if (res == 1) {
        packet_info_t *info = process_packet(header, packet);
        if (!info) {
            // Skip this packet and try next
            return PcapReader_iternext(self);
        }
        PyObject *dict = PyDict_New();
        if (info->timestamp)
            PyDict_SetItemString(dict, "timestamp", PyUnicode_FromString(info->timestamp));
        if (info->src_ip)
            PyDict_SetItemString(dict, "src_ip", PyUnicode_FromString(info->src_ip));
        if (info->dst_ip)
            PyDict_SetItemString(dict, "dst_ip", PyUnicode_FromString(info->dst_ip));
        if (info->src_port)
            PyDict_SetItemString(dict, "src_port", PyUnicode_FromString(info->src_port));
        if (info->dst_port)
            PyDict_SetItemString(dict, "dst_port", PyUnicode_FromString(info->dst_port));
        if (info->protocol)
            PyDict_SetItemString(dict, "protocol", PyUnicode_FromString(info->protocol));
        if (info->packet_length)
            PyDict_SetItemString(dict, "packet_length", PyUnicode_FromString(info->packet_length));
        if (info->tcp_seq)
            PyDict_SetItemString(dict, "tcp_seq", PyUnicode_FromString(info->tcp_seq));
        if (info->tcp_ack)
            PyDict_SetItemString(dict, "tcp_ack", PyUnicode_FromString(info->tcp_ack));
        if (info->tcp_flags)
            PyDict_SetItemString(dict, "tcp_flags", PyUnicode_FromString(info->tcp_flags));

        // Free allocated memory from process_packet
        free(info->timestamp);
        free(info->src_ip);
        free(info->dst_ip);
        free(info->src_port);
        free(info->dst_port);
        free(info->protocol);
        free(info->packet_length);
        free(info->tcp_seq);
        free(info->tcp_ack);
        free(info->tcp_flags);
        free(info);

        return dict;
    }
    PyErr_SetNone(PyExc_StopIteration);
    return NULL;
}

static PyTypeObject PcapReaderType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "pcap_parser_final.PcapReader",
    .tp_basicsize = sizeof(PcapReaderObject),
    .tp_itemsize = 0,
    .tp_dealloc = (destructor)PcapReader_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = "Pcap file reader iterator",
    .tp_iter = PcapReader_iter,
    .tp_iternext = (iternextfunc)PcapReader_iternext,
    .tp_init = (initproc)PcapReader_init,
    .tp_new = PyType_GenericNew,
};

static PyModuleDef pcapparsermodule = {
    PyModuleDef_HEAD_INIT,
    .m_name = "pcap_parser",
    .m_doc = "Module wrapping process_packet as iterator",
    .m_size = -1,
};

PyMODINIT_FUNC
PyInit_pcap_parser(void) {
    PyObject *m;
    if (PyType_Ready(&PcapReaderType) < 0)
        return NULL;

    m = PyModule_Create(&pcapparsermodule);
    if (m == NULL)
        return NULL;

    Py_INCREF(&PcapReaderType);
    PyModule_AddObject(m, "PcapReader", (PyObject *)&PcapReaderType);
    return m;
}

/* Example main to demonstrate usage */
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
    while ((result = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (result == 0) continue;
        packet_info_t *info = process_packet(header, packet);
        if (info != NULL) {
            printf("Timestamp: %s\n", info->timestamp);
            printf("5-tuple: %s -> %s\n", info->src_ip, info->dst_ip);
            printf("Ports: %s -> %s\n", info->src_port, info->dst_port);
            printf("Protocol: %s\n", info->protocol);
            printf("Packet Length: %s\n", info->packet_length);
            if (strcmp(info->protocol, "TCP") == 0) {
                printf("TCP Details: seq=%s, ack=%s, flags=%s\n",
                       info->tcp_seq, info->tcp_ack, info->tcp_flags);
            }
            // Free allocated fields
            free(info->timestamp);
            free(info->src_ip);
            free(info->dst_ip);
            free(info->src_port);
            free(info->dst_port);
            free(info->protocol);
            free(info->packet_length);
            free(info->tcp_seq);
            free(info->tcp_ack);
            free(info->tcp_flags);
            free(info);
        }
    }
    if (result == -1) {
        fprintf(stderr, "Error reading packets : %s\n", pcap_geterr(handle));
    }
    pcap_close(handle);
    return EXIT_SUCCESS;
}