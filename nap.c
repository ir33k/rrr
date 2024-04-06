#include "nap.h"
#include <assert.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// Carriage Return and Line Feed characters are send at the end of
// each request message to indicated end of transmission to server.
#define CRLF "\r\n"

// Establish internet TCP socket stream connection to HOST on PORT.
// Return socket file descriptor.
static enum nap
tcp(char *host, int port, int *sfd)
{
	int i;
	struct hostent *he;
	struct sockaddr_in addr;
	assert(host);
	assert(port > 0);
	if ((*sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		return NAP_OPEN;
	}
	if ((he = gethostbyname(host)) == 0) {
		return NAP_HOST;
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
	return NAP_CONNECT;
}

// Write RES response bytes of SZ size to standard output.
static enum nap
onres(char *res, size_t sz)
{
	assert(res);
	if (fwrite(res, 1, sz, stdout) != sz) {
		return NAP_PRINT;
	}
	return 0;
}

// Request MSG of SZ size to open SFD socket.
// Call onres() on each server response message.
static enum nap
req_plain(int sfd, char *msg, int sz)
{
	enum nap err;
	char buf[4096];
	assert(sfd);
	assert(msg);
	if (send(sfd, msg, sz, 0) == -1) {
		return NAP_REQ_SEND;
	}
	if (send(sfd, CRLF, sizeof(CRLF) -1, 0) == -1) {
		return NAP_REQ_CRLF;
	}
	while ((sz = recv(sfd, buf, sizeof(buf), 0)) > 0) {
		if ((err = onres(buf, sz))) {
			return err;
		}
	}
	return 0;
}

// Request secure MSG of SZ size to open SFD socket to HOST.
// Call onres() on each server response message.
static enum nap
req_secure(int sfd, char *msg, int sz, char *host)
{
	enum nap err;
	char buf[4096];
	SSL *ssl;
	SSL_CTX *ctx;
	assert(sfd);
	assert(msg);
	assert(host);
	if (!(ctx = SSL_CTX_new(TLS_client_method()))) {
		return NAP_SSL_CTX;
	}
	if (!(ssl = SSL_new(ctx))) {
		return NAP_SSL_NEW;
	}
	if (!SSL_set_tlsext_host_name(ssl, host)) {
		return NAP_SSL_HOST;
	}
	if (!SSL_set_fd(ssl, sfd)) {
		return NAP_SSL_FD;
	}
	if (SSL_connect(ssl) < 1) {
		return NAP_SSL_CONNECT;
	}
	if (SSL_write(ssl, msg, sz) < 1) {
		return NAP_SSL_WRITE;
	}
	if (SSL_write(ssl, CRLF, sizeof(CRLF) - 1) < 1) {
		return NAP_SSL_CRLF;
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

enum nap
nap_req(char *msg, int sz, char *host, int port, int secure)
{
	enum nap err;
	int sfd;
	if (!port) {
		return NAP_PORT;
	}
	if ((err = tcp(host, port, &sfd))) {
		return err;
	}
	if (secure) {
		if ((err = req_secure(sfd, msg, sz, host))) {
			return err;
		}
	} else {
		if ((err = req_plain(sfd, msg, sz))) {
			return err;
		}
	}
	if (close(sfd)) {
		return NAP_CLOSE;
	}
	return 0;
}

char *
nap_err(enum nap err)
{
	switch (err) {
	case NAP_OK:          return "Ok";
	case NAP_PORT:        return "Missing port";
	case NAP_HOST:        return "Failed to get hostname";
	case NAP_CONNECT:     return "Failed to connect";
	case NAP_PRINT:       return "Failed to print response";
	case NAP_OPEN:        return "Failed to open socket";
	case NAP_CLOSE:       return "Failed to close sfd";
	case NAP_REQ_SEND:    return "Failed to send request to server";
	case NAP_REQ_CRLF:    return "Failed to send CRLF to server";
	case NAP_SSL_CTX:     return "Failed to create SSL context";
	case NAP_SSL_NEW:     return "Failed to create SSL instance";
	case NAP_SSL_HOST:    return "Failed to TLS set hostname";
	case NAP_SSL_FD:      return "Failed to set SSL sfd";
	case NAP_SSL_CONNECT: return "Failed to stablish SSL connection";
	case NAP_SSL_WRITE:   return "Failed to send secure request to server";
	case NAP_SSL_CRLF:    return "Failed to send secure CRLF to server";
	}
	return "Unknown error";
}
