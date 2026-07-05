#include "utils.h"
void usage(char *progname)
{
    fprintf(
        stderr,
        "[-] usage: %s -i interface_name -n count -f bpf_filter -o outfile\n",
        progname);
    exit(EXIT_FAILURE);
}

args_t parse_args(int argc, char **argv)
{
    int opt;
    args_t args = {0};
    opterr = 0;

    // init defaults
    strcpy(args.ifname, "");
    strcpy(args.outfile, PCAP_SAVEFILE);
    args.count = 0;

    while ((opt = getopt(argc, argv, "i:o:f:n:")) != -1) {
        switch (opt) {
        case 'o':
            if (optarg) {
                strncpy(args.outfile, optarg, OFSZ - 1);
                args.outfile[OFSZ - 1] = '\0';
            }
            break;
        case 'i':
            if (optarg) {
                strncpy(args.ifname, optarg, IFSZ - 1);
                args.ifname[IFSZ - 1] = '\0';
            }
            break;
        case 'f':
            if (optarg) {
                strncpy(args.fltstr, optarg, FLSTRSZ - 1);
                args.fltstr[FLSTRSZ - 1] = '\0';
            }
            break;
        case 'n': {
            if (optarg) {
                args.count = atoi(optarg);
            }
            break;
        }
        case '?':
            fprintf(stderr, "[-] invalid option: -%c\n", optopt);
            exit(EXIT_FAILURE);
        case ':':
            fprintf(stderr, "[-] option -%c requires an argument\n", optopt);
            exit(EXIT_FAILURE);
        }
    }

    return args;
}
