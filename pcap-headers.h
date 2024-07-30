#include <stdint.h>
#include <netinet/in.h>

typedef uint32_t n_time;


struct libnet_ethernet_hdr {
    uint8_t ether_dhost[ETHER_ADDR_LEN]; /* destination eth addr */
    uint8_t ether_shost[ETHER_ADDR_LEN]; /* source ether addr */
    uint16_t ether_type;                 /* packet type ID field */
};

/* IPv4 header */
struct libnet_ipv4_hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t ip_hl:4,        /* header length */
            ip_v:4;         /* version */
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t ip_v:4,         /* version */
            ip_hl:4;        /* header length */
#else
# error "Please fix <bits/endian.h>"
#endif
    uint8_t ip_tos;         /* type of service */
    uint16_t ip_len;        /* total length */
    uint16_t ip_id;         /* identification */
    uint16_t ip_off;        /* fragment offset field */
#define IP_DF 0x4000        /* dont fragment flag */
#define IP_MF 0x2000        /* more fragments flag */
    uint8_t ip_ttl;         /* time to live */
    uint8_t ip_p;           /* protocol */
    uint16_t ip_sum;        /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

/* TCP header */
struct libnet_tcp_hdr {
    uint16_t th_sport;      /* source port */
    uint16_t th_dport;      /* destination port */
    uint32_t th_seq;        /* sequence number */
    uint32_t th_ack;        /* acknowledgement number */
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t th_x2:4,        /* (unused) */
            th_off:4;       /* data offset */
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t th_off:4,       /* data offset */
            th_x2:4;        /* (unused) */
#else
# error "Please fix <bits/endian.h>"
#endif
    uint8_t th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
    uint16_t th_win;        /* window */
    uint16_t th_sum;        /* checksum */
    uint16_t th_urp;        /* urgent pointer */
};