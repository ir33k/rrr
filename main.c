#define VERSION "v1.1"

#include <assert.h>
#include <err.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include "rrr.h"

// Print usage help message to stdout for ARG0 program name.
static void
usage(char *arg0)
{
	printf("usage: %s [-s] [-v] [-h] host port <req\n"
	       "\n"
	       "	host	Target server hostname.\n"
	       "	port	Target server port.\n"
	       "	req	Request message from stdin.\n"
	       "	-s	Use SSL secure connection.\n"
	       "	-v	Print program version.\n"
	       "	-h	Print this help message.\n"
	       , arg0);
}

// If error CODE is non 0 then print error message and exit with 1.
static void
maybe(int code)
{
	if (!code) {
		return;
	}
	if (code >= RRR_NO) {
		err(1, "%s", rrr_err(code));
	}
	if (code >= RRR_SSL) {
		errx(1, "OpenSSL: %s", rrr_err(code));
	}
	errx(1, "%s", rrr_err(code));
}

// Open connection to HOST with PORT, secure if SSL, read request
// message from stdin and write server response to stdout.
static void
run(char *host, int port, int ssl)
{
	struct rrr ctx;
	char buf[4096];
	size_t sz;
	assert(host);
	assert(port > 0);
	maybe(rrr_open(&ctx, host, port, ssl));
	while ((sz = fread(buf, 1, sizeof(buf), stdin))) {
		maybe(rrr_req(&ctx, buf, sz));
	}
	maybe(rrr_req(&ctx, "\r\n", 2));
	while ((sz = rrr_res(&ctx, buf, sizeof(buf)))) {
		if (fwrite(buf, 1, sz, stdout) != sz) {
			err(1, "Failed to print response");
		}
	}
	maybe(rrr_close(&ctx));
}

int
main(int argc, char **argv)
{
	int i, ssl=0;
	while ((i = getopt(argc, argv, "shv")) != -1) {
		switch (i) {
		case 's':
			ssl = 1;
			break;
		case 'v':
			puts(VERSION);
			return 0;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 1;
		}
	}
	if (argc - optind < 2) {
		warnx("Missing required arguments");
		usage(argv[0]);
		return 1;
	}
	run(argv[optind], atoi(argv[optind+1]), ssl);
	return 0;
}
