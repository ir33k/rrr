#define VERSION "v2.1"

#include <assert.h>
#include <err.h>
#include <getopt.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CRLF "\r\n"

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

/* Establish internet TCP socket stream connection to HOST on PORT.
 * Return Socker File Descriptor on success, exit with 1 on error. */
static int
tcp(char *host, int port)
{
	int i, sfd;
	struct hostent *he;
	struct sockaddr_in addr;
	assert(host);
	assert(port > 0);
	if ((sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		err(1, "Failed to open socker");
	}
	if ((he = gethostbyname(host)) == 0) {
		errx(1, "Failed to get hostname");
	}
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	for (i=0; he->h_addr_list[i]; i++) {
		memcpy(&addr.sin_addr.s_addr, he->h_addr_list[i], sizeof(in_addr_t));
		if (connect(sfd, (struct sockaddr*)&addr, sizeof(addr))) {
			continue;
		}
		return sfd;	/* Success */
	}
	errx(1, "Failed to connect (invalid port?)");
}

/* Non secure plain request for open SFD. */
static void
plain(int sfd)
{
	char buf[4096];
	size_t sz;
	assert(sfd);
	while ((sz = fread(buf, 1, sizeof(buf), stdin))) {
		if (send(sfd, buf, sz, 0) == -1) {
			err(1, "Failed to send request to server");
		}
	}
	if (send(sfd, CRLF, sizeof(CRLF), 0) == -1) {
		err(1, "Failed to send CRLF to server");
	}
	while ((sz = recv(sfd, buf, sizeof(buf), 0))) {
		if (fwrite(buf, 1, sz, stdout) != sz) {
			err(1, "Failed to print response");
		}
	}
}

/* Secure SSL request for open SFD and HOST. */
static void
secure(int sfd, char *host)
{
	char buf[4096];
	size_t sz;
	SSL_CTX *ctx;
	SSL *ssl;
	assert(sfd);
	assert(host);
	if (!(ctx = SSL_CTX_new(TLS_client_method()))) {
		errx(1, "Failed to create SSL context");
	}
	if (!(ssl = SSL_new(ctx))) {
		errx(1, "Failed to create SSL instance");
	}
	if (!SSL_set_tlsext_host_name(ssl, host)) {
		errx(1, "Failed to TLS set hostname");
	}
	if (!SSL_set_fd(ssl, sfd)) {
		errx(1, "Failed to set SSL sfd");
	}
	if (SSL_connect(ssl) < 1) {
		errx(1, "Failed to stablish SSL connection");
	}
	while ((sz = fread(buf, 1, sizeof(buf), stdin))) {
		if (SSL_write(ssl, buf, sz) < 1) {
			errx(1, "Failed to send secure request to server");
		}
	}
	if (SSL_write(ssl, CRLF, sizeof(CRLF)) < 1) {
		errx(1, "Failed to send secure CRLF to server");
	}
	while ((sz = SSL_read(ssl, buf, sizeof(buf)))) {
		if (fwrite(buf, 1, sz, stdout) != sz) {
			err(1, "Failed to print secure response");
		}
	}
	SSL_CTX_free(ctx);
	SSL_free(ssl);
}

static void
run(char *host, int port, int ssl)
{
	int sfd;
	assert(host);
	assert(port > 0);
	sfd = tcp(host, port);
	if (ssl) {
		secure(sfd, host);
	} else {
		plain(sfd);
	}
	if (close(sfd)) {
		err(1, "Failed to close socker file descriptor");
	}
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
