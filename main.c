#define VERSION "v1.0"

#include <err.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include "rrr.h"

static void
usage(char *arg0)
{
	printf("usage: %s [-h] [-v] [-s] host port <req\n"
	       "\n"
	       "	host	Target server hostname.\n"
	       "	port	Target server port.\n"
	       "	req	Request message from stdin.\n"
	       "	-h	Print this help message.\n"
	       "	-v	Print program version.\n"
	       "	-s	Use SSL secure connection.\n"
	       , arg0);
}

int
main(int argc, char **argv)
{
	int i, ssl=0;
	while ((i = getopt(argc, argv, "hvs")) != -1) {
		switch (i) {
		case 'h':
			usage(argv[0]);
			return 0;
		case 'v':
			puts(VERSION);
			return 0;
		case 's':
			ssl = 1;
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}
	if (argc - optind < 2) {
		fprintf(stderr, "ERROR: Missing required arguments");
		usage(argv[0]);
		return 1;
	}
	i = rrr_req(stdin, argv[optind], atoi(argv[optind+1]), ssl);
	if (i >= RRR_ERRNO) {
		err(1, "%s", rrr_err(i));
	}
	if (i) {
		errx(1, "%s", rrr_err(i));
	}
	return 0;
}
