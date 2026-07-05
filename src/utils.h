#ifndef UTILS_H
#define UTILS_H

#include <pcap.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <stddef.h>
#define ANSI_RESET "\033[0m"
#define ANSI_BOLD "\033[1m"

#define COLOR_BLACK "\033[0;30m"
#define COLOR_RED "\033[0;31m"
#define COLOR_GREEN "\033[0;32m"
#define COLOR_YELLOW "\033[0;33m"
#define COLOR_BLUE "\033[0;34m"
#define COLOR_MAGENTA "\033[0;35m"
#define COLOR_CYAN "\033[0;36m"
#define COLOR_WHITE "\033[0;37m"

#define COLOR_BOLD_BLACK "\033[1;30m"
#define COLOR_BOLD_RED "\033[1;31m"
#define COLOR_BOLD_GREEN "\033[1;32m"
#define COLOR_BOLD_YELLOW "\033[1;33m"
#define COLOR_BOLD_BLUE "\033[1;34m"
#define COLOR_BOLD_MAGENTA "\033[1;35m"
#define COLOR_BOLD_CYAN "\033[1;36m"
#define COLOR_BOLD_WHITE "\033[1;37m"

#define COLOR_BG_BLACK "\033[40m"
#define COLOR_BG_RED "\033[41m"
#define COLOR_BG_GREEN "\033[42m"
#define COLOR_BG_YELLOW "\033[43m"
#define COLOR_BG_BLUE "\033[44m"
#define COLOR_BG_MAGENTA "\033[45m"
#define COLOR_BG_CYAN "\033[46m"
#define COLOR_BG_WHITE "\033[47m"

// helper macro
#define PRINT_COLOR(color, text) color text ANSI_RESET

#define FLSTRSZ 256
#define OFSZ 256
#define IFSZ 64
#define PCAP_SAVEFILE "./capture.pcap"

typedef struct args
{
    char fltstr[FLSTRSZ];
    char outfile[OFSZ];
    char ifname[IFSZ];
    int count;
} args_t;

void usage(char *progname);
args_t parse_args(int argc, char **argv);

static inline void fmt_timestamp(const struct pcap_pkthdr *header,
                                 char *timestr, size_t tslen,
                                 long int *out_usec)
{
    time_t sec = header->ts.tv_sec;
    *out_usec = header->ts.tv_usec;
    struct tm *lt = localtime(&sec);
    if (lt)
        strftime(timestr, tslen, "%H:%M:%S", lt);
    else
        snprintf(timestr, tslen, "00:00:00");
}

static inline void print_pkt_header(uint32_t pktcnt, const char *timestr,
                                    long int usec, int caplen, int wirelen,
                                    const char *proto_name, const char *srcip,
                                    const char *dstip)
{
    printf("%s%05d%s at %s.%06ld %s CAPLEN: %04d/%04d %s %-8s %s %-15s -> "
           "%-15s %s",
           PRINT_COLOR(COLOR_BOLD_WHITE, "["), pktcnt,
           PRINT_COLOR(COLOR_BOLD_WHITE, "]"), timestr, usec,
           PRINT_COLOR(COLOR_BOLD_WHITE, "|"), caplen, wirelen,
           PRINT_COLOR(COLOR_BOLD_WHITE, "|"), proto_name,
           PRINT_COLOR(COLOR_BOLD_WHITE, "|"), srcip, dstip,
           PRINT_COLOR(COLOR_BOLD_WHITE, "|"));
}
#endif
