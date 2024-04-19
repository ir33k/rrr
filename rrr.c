#include <assert.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "rrr.h"

// Carriage Return and Line Feed characters are send at the end of
// each request message to indicated end of transmission to server.
#define CRLF "\r\n"

// Establish internet TCP socket stream connection to HOST on PORT.
// Return socket file descriptor.
static enum rrr
tcp(char *host, int port, int *sfd)
{
	int i;
	struct hostent *he;
	struct sockaddr_in addr;
	assert(host);
	assert(port > 0);
	if ((*sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		return RRR_OPEN;
	}
	if ((he = gethostbyname(host)) == 0) {
		return RRR_HOST;
	}
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	for (i=0; he->h_addr_list[i]; i++) {
		memcpy(&addr.sin_addr.s_addr, he->h_addr_list[i], sizeof(in_addr_t));
		if (connect(*sfd, (struct sockaddr*)&addr, sizeof(addr))) {
			continue;
		}
		return 0;
	}
	return RRR_CONNECT;
}

// Write RES response bytes of SZ size to standard output.
static enum rrr
onres(char *res, size_t sz)
{
	assert(res);
	if (fwrite(res, 1, sz, stdout) != sz) {
		return RRR_PRINT;
	}
	return 0;
}

// Request content of FP to open SFD socket.
// Call onres() on each server response message.
static enum rrr
req_plain(int sfd, FILE *fp)
{
	enum rrr err;
	char buf[4096];
	size_t sz;
	assert(sfd);
	assert(fp);
	while ((sz = fread(buf, 1, sizeof(buf), fp))) {
		if (send(sfd, buf, sz, 0) == -1) {
			return RRR_REQ_SEND;
		}
	}
	if (send(sfd, CRLF, sizeof(CRLF) -1, 0) == -1) {
		return RRR_REQ_CRLF;
	}
	while ((sz = recv(sfd, buf, sizeof(buf), 0)) > 0) {
		if ((err = onres(buf, sz))) {
			return err;
		}
	}
	return 0;
}

// Request secure content of FP to open SFD socket to HOST.
// Call onres() on each server response message.
static enum rrr
req_secure(int sfd, FILE *fp, char *host)
{
	enum rrr err;
	char buf[4096];
	size_t sz;
	SSL *ssl;
	SSL_CTX *ctx;
	assert(sfd);
	assert(fp);
	assert(host);
	if (!(ctx = SSL_CTX_new(TLS_client_method()))) {
		return RRR_SSL_CTX;
	}
	if (!(ssl = SSL_new(ctx))) {
		return RRR_SSL_NEW;
	}
	if (!SSL_set_tlsext_host_name(ssl, host)) {
		return RRR_SSL_HOST;
	}
	if (!SSL_set_fd(ssl, sfd)) {
		return RRR_SSL_FD;
	}
	if (SSL_connect(ssl) < 1) {
		return RRR_SSL_CONNECT;
	}
	while ((sz = fread(buf, 1, sizeof(buf), fp))) {
		if (SSL_write(ssl, buf, sz) < 1) {
			return RRR_SSL_WRITE;
		}
	}
	if (SSL_write(ssl, CRLF, sizeof(CRLF) - 1) < 1) {
		return RRR_SSL_CRLF;
	}
	while ((sz = SSL_read(ssl, buf, sizeof(buf))) > 0) {
		if ((err = onres(buf, sz))) {
			return err;
		}
	}
	SSL_CTX_free(ctx);
	SSL_free(ssl);
	return 0;
}

enum rrr
rrr_req(FILE *fp, char *host, int port, int secure)
{
	enum rrr err;
	int sfd;
	if (!port) {
		return RRR_PORT;
	}
	if ((err = tcp(host, port, &sfd))) {
		return err;
	}
	if (secure) {
		if ((err = req_secure(sfd, fp, host))) {
			return err;
		}
	} else {
		if ((err = req_plain(sfd, fp))) {
			return err;
		}
	}
	if (close(sfd)) {
		return RRR_CLOSE;
	}
	return 0;
}

char *
rrr_err(enum rrr err)
{
	switch (err) {
	case RRR_OK:          return "Ok";
	case RRR_PORT:        return "Missing port";
	case RRR_HOST:        return "Failed to get hostname";
	case RRR_CONNECT:     return "Failed to connect (invalid port?)";
	case RRR_PRINT:       return "Failed to print response";
	case RRR_OPEN:        return "Failed to open socket";
	case RRR_CLOSE:       return "Failed to close sfd";
	case RRR_REQ_SEND:    return "Failed to send request to server";
	case RRR_REQ_CRLF:    return "Failed to send CRLF to server";
	case RRR_SSL_CTX:     return "Failed to create SSL context";
	case RRR_SSL_NEW:     return "Failed to create SSL instance";
	case RRR_SSL_HOST:    return "Failed to TLS set hostname";
	case RRR_SSL_FD:      return "Failed to set SSL sfd";
	case RRR_SSL_CONNECT: return "Failed to stablish SSL connection";
	case RRR_SSL_WRITE:   return "Failed to send secure request to server";
	case RRR_SSL_CRLF:    return "Failed to send secure CRLF to server";
	}
	return "Unknown error";
}
