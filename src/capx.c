#include "capx.h"
#include "utils.h"

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/dlt.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static app_ctx_t *g_app_ctx = NULL;

static inline void print_stats(void)
{
    printf("[i] %d packets transmitted. (tcp: %d, udp: %d, icmp: %d,"
           " arp: %d, unknown: %d)\n",
           g_app_ctx->stats.pktcnt_total, g_app_ctx->stats.pktcnt_ipproto_tcp,
           g_app_ctx->stats.pktcnt_ipproto_udp,
           g_app_ctx->stats.pktcnt_ipproto_icmp, g_app_ctx->stats.pktcnt_arp,
           g_app_ctx->stats.pktcnt_unknown);
}

void sigint_handler(int sig)
{
    (void)sig;
    if (g_app_ctx) {
        printf("\n[-] Ctrl+C detected, exiting gracefully\n");
        print_stats();
        if (g_app_ctx->dumper)
            pcap_dump_close(g_app_ctx->dumper);
        if (g_app_ctx->capdev)
            pcap_breakloop(g_app_ctx->capdev);

        exit(EXIT_SUCCESS);
    }
}

int main(i32 argc, char *argv[])
{
    struct bpf_program fp;
    char errbuf[PCAP_ERRBUF_SIZE];

    args_t args = parse_args(argc, argv);
    char *dev = args.ifname;
    char *filename = args.outfile;

    app_ctx_t ctx = {
        .dumper = NULL, .capdev = NULL, .stats = {0}, .cached_tty = isatty(1)};
    g_app_ctx = &ctx;
    signal(SIGINT, sigint_handler);

    if (dev[0] == '\0') {
        handle_interactive_selection(dev, IFNAMSIZ);
    }

    if ((ctx.capdev = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf)) == NULL) {
        fprintf(stderr, "[!] opening device %s\n", errbuf);
        return EXIT_FAILURE;
    }

    printf("[i] Listening on device: %s\n", dev);

    if (args.fltstr[0] == '\0') {
        // default fallback
        strcpy(args.fltstr, "ip or arp"); // todo: add ipv6
    }
    if ((pcap_compile(ctx.capdev, &fp, args.fltstr, 0, PCAP_NETMASK_UNKNOWN)) ==
        -1) {
        fprintf(stderr, "[!] pcap_compile(): %s\n", pcap_geterr(ctx.capdev));
        return EXIT_FAILURE;
    }
    if ((pcap_setfilter(ctx.capdev, &fp)) != 0) {
        fprintf(stderr, "[!] pcap_setfilter(): %s\n", pcap_geterr(ctx.capdev));
        return EXIT_FAILURE;
    }

    pcap_freecode(&fp);

    if ((ctx.dumper = pcap_dump_open(ctx.capdev, filename)) == NULL) {
        fprintf(stderr, "[!] opening dumpfile: %s\n", pcap_geterr(ctx.capdev));
        return EXIT_FAILURE;
    }
    printf("[i] dumping data to %s\n\n", filename);

    const int datalink_type = pcap_datalink(ctx.capdev);
    callback_data_t cb_data = {.app_ctx = &ctx,
                               .link_hdr_len = get_link_hdr_len(datalink_type),
                               .dumpfile = ctx.dumper};

    i32 ret =
        pcap_loop(ctx.capdev, args.count, loop_callback, (u_char *)&cb_data);
    if (ret == PCAP_ERROR) {
        fprintf(stderr, "[!] pcap_loop(): %s\n", pcap_geterr(ctx.capdev));
        return EXIT_FAILURE;
    } else if (ret == PCAP_ERROR_NOT_ACTIVATED) {
        fprintf(stderr, "[!] handle not activated\n");
        return EXIT_FAILURE;
    }

    pcap_dump_close(ctx.dumper);
    pcap_close(ctx.capdev);
    print_stats();
    return EXIT_SUCCESS;
}

void loop_callback(u_char *user, const struct pcap_pkthdr *header,
                   const u_char *pktdptr)
{
    callback_data_t *cb_data = (callback_data_t *)user;

    pcap_dumper_t *pd = cb_data->dumpfile;
    pcap_dump((u_char *)pd, header, pktdptr);

    if (header->caplen < cb_data->link_hdr_len) {
        /* packet is malformed */
        return;
    }

    struct ether_header *eth_hdr = (struct ether_header *)pktdptr;
    u16 ether_type = ntohs(eth_hdr->ether_type);

    const u_char *l3_payload = pktdptr + cb_data->link_hdr_len;
    u32 l3_len = header->caplen - cb_data->link_hdr_len;

    switch (ether_type) {
    case ETHERTYPE_IP: {
        parse_ipv4(cb_data, header, l3_payload, l3_len);
        break;
    }
    case ETHERTYPE_IPV6: {
        parse_ipv6(cb_data, header, l3_payload, l3_len);
        break;
    }
    case ETHERTYPE_ARP: {
        parse_arp(cb_data, header, l3_payload, l3_len);
        break;
    }
    default: {
        break;
    }
    }
}

void parse_ipv4(struct callback_data *cb_data, const struct pcap_pkthdr *header,
                const u_char *pktdptr, u32 l3_len)
{
    /* safety checks */
    if (l3_len < sizeof(struct ip))
        return;

    struct ip *iphdr = (struct ip *)pktdptr;
    if (iphdr->ip_v != 4)
        return;

    u32 pkt_hlen = iphdr->ip_hl * 4;
    if (pkt_hlen < sizeof(struct ip) || l3_len < pkt_hlen)
        return;

    char pkt_srcip[INET_ADDRSTRLEN], pkt_dstip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iphdr->ip_src), pkt_srcip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iphdr->ip_dst), pkt_dstip, INET_ADDRSTRLEN);

    i32 pkt_id = ntohs(iphdr->ip_id);
    i32 pkt_tos = iphdr->ip_tos;
    i32 wlen = header->len;
    i32 caplen = header->caplen;

    /* extract timestamp */
    char timestr[16];
    i64 microseconds;
    fmt_timestamp(header, timestr, sizeof(timestr), &microseconds);

    u8 tty = cb_data->app_ctx->cached_tty;

    i32 proto_type = iphdr->ip_p;
    const char *proto_name =
        (proto_type == IPPROTO_TCP)
            ? (tty ? PRINT_COLOR(COLOR_BLUE, "  TCP  ") : "  TCP  ")
        : (proto_type == IPPROTO_UDP)
            ? (tty ? PRINT_COLOR(COLOR_GREEN, "  UDP  ") : "  UDP  ")
        : (proto_type == IPPROTO_ICMP)
            ? (tty ? PRINT_COLOR(COLOR_YELLOW, " ICMP  ") : " ICMP  ")
            : (tty ? PRINT_COLOR(COLOR_RED, "  UNK  ") : "  UNK  ");

    cb_data->app_ctx->stats.pktcnt_total++;

    print_pkt_header(cb_data->app_ctx->stats.pktcnt_total, timestr,
                     microseconds, caplen, wlen, proto_name, pkt_srcip,
                     pkt_dstip);
    printf(" ID: %-5d %s TOS: 0x%02x %s", pkt_id,
           PRINT_COLOR(COLOR_BOLD_WHITE, "|"), pkt_tos,
           PRINT_COLOR(COLOR_BOLD_WHITE, "|"));
    const u_char *l4_payload = pktdptr + pkt_hlen;
    u32 l4_len = l3_len - pkt_hlen;

    switch (proto_type) {
    case IPPROTO_TCP: {
        cb_data->app_ctx->stats.pktcnt_ipproto_tcp++;

        if (l4_len >= sizeof(struct tcphdr)) {
            struct tcphdr *tcp = (struct tcphdr *)l4_payload;
            printf(" FLAGS: %c%c%c%c%c%c %s %5d -> %-5d",
                   (tcp->th_flags & TH_URG) ? 'U' : '.',
                   (tcp->th_flags & TH_ACK) ? 'A' : '.',
                   (tcp->th_flags & TH_PUSH) ? 'P' : '.',
                   (tcp->th_flags & TH_RST) ? 'R' : '.',
                   (tcp->th_flags & TH_SYN) ? 'S' : '.',
                   (tcp->th_flags & TH_FIN) ? 'F' : '.',
                   PRINT_COLOR(COLOR_BOLD_WHITE, "|"), ntohs(tcp->source),
                   ntohs(tcp->dest));
        } else {
            printf("TRUNCATED TCP");
        }
        break;
    }
    case IPPROTO_UDP: {
        cb_data->app_ctx->stats.pktcnt_ipproto_udp++;

        if (l4_len >= sizeof(struct udphdr)) {
            struct udphdr *udp = (struct udphdr *)l4_payload;
            i32 src_port = ntohs(udp->source);
            i32 dest_port = ntohs(udp->dest);

            printf(" LEN: %-8d %s %5d -> %-5d", ntohs(udp->len),
                   PRINT_COLOR(COLOR_BOLD_WHITE, "|"), ntohs(udp->source),
                   ntohs(udp->dest));

            if (src_port == 53 && dest_port == 53) {
                const u_char *dns_payload = l4_payload + sizeof(struct udphdr);
                u32 dns_len = l4_len - sizeof(struct udphdr);
                parse_dns(cb_data, dns_payload, dns_len);
            }
        } else {
            printf("TRUNCATED UDP");
        }
        break;
    }
    case IPPROTO_ICMP: {
        cb_data->app_ctx->stats.pktcnt_ipproto_icmp++;

        if (l4_len >= sizeof(struct icmp)) {
            struct icmp *icmp = (struct icmp *)l4_payload;
            const char *type_str = "UNKNOWN";
            const char *code_str = "UNKNOWN";

            switch (icmp->icmp_type) {
            case 0:
                type_str = "ECHO REPLY";
                if (icmp->icmp_code == 0)
                    code_str = "NO CODE";
                break;

            case 3:
                type_str = "DEST UNREACHABLE";
                switch (icmp->icmp_code) {
                case 0:
                    code_str = "NET UNREACHABLE";
                    break;
                case 1:
                    code_str = "HOST UNREACHABLE";
                    break;
                case 2:
                    code_str = "PROTO UNREACHABLE";
                    break;
                case 3:
                    code_str = "PORT UNREACHABLE";
                    break;
                case 4:
                    code_str = "FRAG NEEDED";
                    break;
                case 5:
                    code_str = "SRC ROUTE FAILED";
                    break;
                case 6:
                    code_str = "DEST NET UNKNOWN";
                    break;
                case 7:
                    code_str = "DEST HOST UNKNOWN";
                    break;
                case 8:
                    code_str = "SRC HOST ISOLATED";
                    break;
                case 9:
                    code_str = "NET PROHIBITED";
                    break;
                case 10:
                    code_str = "HOST PROHIBITED";
                    break;
                case 11:
                    code_str = "NET UNREACH TOS";
                    break;
                case 12:
                    code_str = "HOST UNREACH TOS";
                    break;
                case 13:
                    code_str = "COMM PROHIBITED";
                    break;
                default:
                    code_str = "UNKNOWN CODE";
                    break;
                }
                break;

            case 4:
                type_str = "SOURCE QUENCH";
                if (icmp->icmp_code == 0)
                    code_str = "NO CODE";
                break;

            case 5:
                type_str = "REDIRECT";
                switch (icmp->icmp_code) {
                case 0:
                    code_str = "REDIRECT NET";
                    break;
                case 1:
                    code_str = "REDIRECT HOST";
                    break;
                case 2:
                    code_str = "REDIRECT TOS & NET";
                    break;
                case 3:
                    code_str = "REDIRECT TOS & HOST";
                    break;
                default:
                    code_str = "UNKNOWN CODE";
                    break;
                }
                break;

            case 8:
                type_str = "ECHO REQUEST";
                if (icmp->icmp_code == 0)
                    code_str = "NO CODE";
                break;

            case 11:
                type_str = "TIME EXCEEDED";
                switch (icmp->icmp_code) {
                case 0:
                    code_str = "TTL EXCEEDED IN TRANSIT";
                    break;
                case 1:
                    code_str = "FRAG REASSEMBLY TIME EXCEEDED";
                    break;
                default:
                    code_str = "UNKNOWN CODE";
                    break;
                }
                break;

            case 12:
                type_str = "PARAMETER PROBLEM";
                switch (icmp->icmp_code) {
                case 0:
                    code_str = "POINTER INDICATES ERROR";
                    break;
                case 1:
                    code_str = "MISSING REQUIRED OPTION";
                    break;
                case 2:
                    code_str = "BAD LENGTH";
                    break;
                default:
                    code_str = "UNKNOWN CODE";
                    break;
                }
                break;

            case 13:
                type_str = "TIMESTAMP REQUEST";
                if (icmp->icmp_code == 0)
                    code_str = "NO CODE";
                break;

            case 14:
                type_str = "TIMESTAMP REPLY";
                if (icmp->icmp_code == 0)
                    code_str = "NO CODE";
                break;

            default:
                type_str = "UNKNOWN TYPE";
                code_str = "UNKNOWN CODE";
                break;
            }

            printf(" %-15s %s %-15s", type_str,
                   PRINT_COLOR(COLOR_BOLD_WHITE, "|"), code_str);

        } else {
            printf("TRUNCATED ICMP");
        }
        break;
    }
    default:
        cb_data->app_ctx->stats.pktcnt_unknown++;
        printf("PROTOCOL UNKNOWN");
    }

    printf("\n");
}

void parse_arp(callback_data_t *cb_data, const struct pcap_pkthdr *header,
               const u_char *pktdptr, u32 l3_len)
{
    /* packet is malformed */
    if (l3_len < sizeof(struct ether_arp)) {
        return;
    }

    struct ether_arp *arp = (struct ether_arp *)pktdptr;

    u16 hw_type = ntohs(arp->ea_hdr.ar_hrd);
    u16 proto_type = ntohs(arp->ea_hdr.ar_pro);

    if (hw_type != ARPHRD_ETHER || proto_type != ETHERTYPE_IP) {
        fprintf(stderr, "ARP: unexpected hw_type=0x%04x proto_type=0x%04x\n",
                hw_type, proto_type);
        return;
    }

    u16 op = ntohs(arp->ea_hdr.ar_op);

    char sender_ip[INET_ADDRSTRLEN], target_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, arp->arp_spa, sender_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, arp->arp_tpa, target_ip, INET_ADDRSTRLEN);

    /* extract timestamp */
    char timestr[16];
    i64 microseconds;
    fmt_timestamp(header, timestr, sizeof(timestr), &microseconds);

    u8 tty = cb_data->app_ctx->cached_tty;
    const char *op_name =
        (op == ARPOP_REQUEST)
            ? (tty ? PRINT_COLOR(COLOR_YELLOW, "ARP REQ") : "ARP_REQ")
        : (op == ARPOP_REPLY)
            ? (tty ? PRINT_COLOR(COLOR_GREEN, "ARP REP") : "ARP REP")
            : (tty ? PRINT_COLOR(COLOR_RED, "ARP UNK") : "ARP UNK");

    cb_data->app_ctx->stats.pktcnt_total++;
    cb_data->app_ctx->stats.pktcnt_arp++;

    print_pkt_header(cb_data->app_ctx->stats.pktcnt_total, timestr,
                     microseconds, (int)header->caplen, (int)header->len,
                     op_name, sender_ip, target_ip);

    printf(" %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
           arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2], arp->arp_sha[3],
           arp->arp_sha[4], arp->arp_sha[5], arp->arp_tha[0], arp->arp_tha[1],
           arp->arp_tha[2], arp->arp_tha[3], arp->arp_tha[4], arp->arp_tha[5]);
}

void parse_ipv6(callback_data_t *cb_data, const struct pcap_pkthdr *header,
                const u_char *pktdptr, u32 l3_len)
{
    // todo
    printf("[not implemented] an IPV6 packet received!\n");
    return;
}

void parse_dns(callback_data_t *cb_data, const u_char *dns_payload, u32 dns_len)
{
    /* security checks */
    if (dns_len < sizeof(struct _dns_header)) {
        printf(" [TRUNCATED DNS HEADER]\n");
        return;
    }

    struct _dns_header *dns = (struct _dns_header *)dns_payload;
    u16 q_cnt = ntohs(dns->q_cnt);
    u16 ans_cnt = ntohs(dns->ans_cnt);

    i32 is_response = ntohs(dns->flags) & 0x8000;
    u8 tty = cb_data->app_ctx->cached_tty;

    printf("\n    %s [ID: 0x%04x Q: %d Ans: %d]",
           is_response
               ? (tty ? PRINT_COLOR(COLOR_GREEN, "DNS RESP") : "DNS RESP")
               : (tty ? PRINT_COLOR(COLOR_YELLOW, "DNS QRY ") : "DNS QRY "),
           ntohs(dns->id), q_cnt, ans_cnt);

    const u_char *cursor = dns_payload + sizeof(struct _dns_header);
    int bytes_read = 0;
    char name_buf[256];

    for (i32 i = 0; i < q_cnt; i++) {
        decode_dns_name(dns_payload, cursor, dns_len, name_buf, &bytes_read);
        cursor += bytes_read;

        if (cursor + 4 > dns_payload + dns_len)
            return;
        cursor += 4;

        if (i == 0)
            printf(" Name: %s\n", name_buf);
    }

    for (i32 i = 0; i < ans_cnt; i++) {
        decode_dns_name(dns_payload, cursor, dns_len, name_buf, &bytes_read);
        cursor += bytes_read;

        if (cursor + sizeof(struct _dns_header) > dns_payload + dns_len)
            return;

        struct _dns_answer_tail *tail = (struct _dns_answer_tail *)cursor;
        cursor += sizeof(struct _dns_answer_tail);

        u16 type = ntohs(tail->type);
        u16 data_len = ntohs(tail->data_len);

        if (cursor + data_len > dns_payload + data_len)
            return;

        if (type == 1 && data_len == 4) {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, cursor, ip_str, sizeof(ip_str));
            printf("\n      -> %s", ip_str);
        } else if (type == 5) {
            char cname_buf[256];
            i32 cname_bytes;
            decode_dns_name(dns_payload, cursor, dns_len, cname_buf,
                            &cname_bytes);
            printf("\n      -> CNAME: %s", cname_buf);
        }

        cursor += data_len;
    }
}

void decode_dns_name(const u_char *buffer, const u_char *reader, u32 max_len,
                     char *out_name, int *bytes_read)
{
    int pos = 0, jumped = 0, offset;
    *bytes_read = 0;

    const u_char *cur_reader = reader;
    while (cur_reader < (buffer + max_len) && *cur_reader != 0) {
        if (*cur_reader >= 192) {
            /* branch compression pointer */
            if (cur_reader + 1 >= (buffer + max_len))
                break;

            offset = ((*cur_reader & 63) << 8) + *(cur_reader + 1);
            cur_reader = buffer + offset;

            if (!jumped)
                *bytes_read += 2;
            jumped = 1;
        } else {
            /* standard label */
            i32 len = *cur_reader;
            cur_reader++; // skip lenght byte

            if (!jumped)
                *bytes_read += 1;

            if (cur_reader + len > (buffer + max_len))
                break;

            for (i32 i = 0; i < len; i++) {
                out_name[pos++] = *cur_reader;
                cur_reader++;
                if (!jumped)
                    *bytes_read += 1;
            }
            /* to seperate labels, cleaned up later */
            out_name[pos++] = '.';
        }
    }

    if (pos > 0)
        out_name[pos - 1] = '\0';
    else
        strcpy(out_name, "<root>");

    if (!jumped)
        *bytes_read += 1;
}

u32 get_link_hdr_len(int datalink_type)
{
    switch (datalink_type) {
    case DLT_EN10MB: // ethernet
        return 14;
    case DLT_NULL: // loopback (bsd & macos)
        return 4;
    case DLT_RAW: // raw ip
        return 0;
    case DLT_LINUX_SLL: // linux cooked capture
        return 16;
    case DLT_LINUX_SLL2: // linux cooked v2
        return 20;
    default:
        return 0; // unknown
    }
}

void handle_interactive_selection(char *dev_out, size_t max_len)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevsp, *device;

    if (pcap_findalldevs(&alldevsp, errbuf) == -1) {
        fprintf(stderr, "[!] unable to find interfaces: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    printf("[-] interface not provided, provide it via -i <ifname> or chose "
           "from below\n");
    printf("[i] all available devices:\n");

    i32 i = 1;
    for (device = alldevsp; device != NULL; device = device->next) {
        printf("\t[%02d] %s - %s\n", i++, device->name,
               device->description ? device->description
                                   : "no description available");
    }

    if (i == 1) {
        fprintf(stderr, "[i] no devices found.\n");
        pcap_freealldevs(alldevsp);
        exit(EXIT_FAILURE);
    }

    i32 ifno;
    printf("\n[>] enter interface number: ");
    if (scanf("%d", &ifno) != 1) {
        fprintf(stderr, "[!] invalid input\n");
        pcap_freealldevs(alldevsp);
        exit(EXIT_FAILURE);
    }

    i32 current_idx = 1;
    u8 found = 0;
    for (device = alldevsp; device != NULL; device = device->next) {
        if (current_idx == ifno) {
            strncpy(dev_out, device->name, max_len - 1);
            dev_out[max_len - 1] = '\0';
            found = 1;
            break;
        }
        current_idx++;
    }

    pcap_freealldevs(alldevsp);

    if (!found) {
        // fprintf(stderr, "[!] invalid interface choice index.\n");
        fprintf(stderr, "[-] unable to find interface, perhaps check index "
                        "number again?\n");
        exit(EXIT_FAILURE);
    }
}
