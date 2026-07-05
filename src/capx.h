#ifndef CAPX_H
#define CAPX_H
#include <pcap/pcap.h>
#include <stdint.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

typedef struct pkt_stats
{
    i32 pktcnt_total, pktcnt_ipproto_tcp, pktcnt_ipproto_udp,
        pktcnt_ipproto_icmp, pktcnt_arp, pktcnt_unknown;
} pkt_stats_t;

typedef struct app_ctx
{
    pcap_dumper_t *dumper;
    pcap_t *capdev;
    pkt_stats_t stats;
    u8 cached_tty;
} app_ctx_t;

typedef struct callback_data
{
    app_ctx_t *app_ctx;
    u32 link_hdr_len;
    pcap_dumper_t *dumpfile;
} callback_data_t;

typedef struct if_info
{
    i32 id;
    pcap_if_t *device;
} if_info_t;

typedef struct _dns_header
{
    u16 id;
    u16 flags;
    u16 q_cnt;
    u16 ans_cnt;
    u16 auth_cnt;
    u16 add_cnt;
} __attribute__((packed)) _dns_header_t;

typedef struct _dns_answer_tail
{
    u16 type;
    u16 Class;
    u32 ttl;
    u16 data_len;
} __attribute__((packed)) _dns_answer_tail_t;

#define MAX_INTERFACE_COUNT 32

void loop_callback(u_char *user, const struct pcap_pkthdr *header,
                   const u_char *packet_data);
void handle_interactive_selection(char *dev_out, size_t max_len);
void parse_ipv4(callback_data_t *cb_data, const struct pcap_pkthdr *header,
                const u_char *pktdptr, u32 l3_len);
void parse_ipv6(callback_data_t *cb_data, const struct pcap_pkthdr *header,
                const u_char *pktdptr, u32 l3_len);
void parse_arp(callback_data_t *cb_data, const struct pcap_pkthdr *header,
               const u_char *pktdptr, u32 l3_len);
void parse_dns(callback_data_t *cb_data, const u_char *dns_payload,
               u32 dns_len);
void decode_dns_name(const u_char *buffer, const u_char *reader, u32 max_len,
                     char *out_name, int *bytes_read);
u32 get_link_hdr_len(int datalink_type);
static inline void print_stats(void);
#endif
