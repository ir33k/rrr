#include <assert.h>
#include <netdb.h>              // For sockaddr stuff
#include <openssl/ssl.h>
#include <string.h>             // For memcpy()
#include <unistd.h>             // For close()
#include "rrr.h"

// Establish internet TCP socket stream connection to HOST on PORT.
// When 0 is returned then SFD was set and connected successfully.
static enum rrr_err
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
		return 0;	// Success
	}
	return RRR_CONNECT;
}

enum rrr_err
rrr_open(struct rrr *req, char *host, int port, int ssl)
{
	enum rrr_err code;
	SSL_CTX *ctx;
	assert(req);
	assert(host);
	assert(port > 0);
	req->host = host;
	if ((code = tcp(host, port, &req->sfd))) {
		return code;
	}
	if (!ssl) {
		req->ssl = 0;
		return 0;
	}
	if (!(ctx = SSL_CTX_new(TLS_client_method()))) {
		return RRR_SSL_CTX;
	}
	if (!(req->ssl = SSL_new(ctx))) {
		return RRR_SSL_NEW;
	}
	if (!SSL_set_tlsext_host_name(req->ssl, host)) {
		return RRR_SSL_HOST;
	}
	if (!SSL_set_fd(req->ssl, req->sfd)) {
		return RRR_SSL_FD;
	}
	if (SSL_connect(req->ssl) < 1) {
		return RRR_SSL_CONNECT;
	}
	SSL_CTX_free(ctx);
	return 0;
}

enum rrr_err
rrr_req(struct rrr *req, char *buf, size_t sz)
{
	assert(req);
	assert(buf);
	assert(sz > 0);
	if (req->ssl) {
		if (SSL_write(req->ssl, buf, sz) < 1) {
			return RRR_SSL_WRITE;
		}
	} else {
		if (send(req->sfd, buf, sz, 0) == -1) {
			return RRR_SEND;
		}
	}
	return 0;
}

size_t
rrr_res(struct rrr *req, char *buf, size_t sz)
{
	assert(req);
	assert(buf);
	assert(sz > 0);
	if (req->ssl) {
		return SSL_read(req->ssl, buf, sizeof(buf));
	}
	return recv(req->sfd, buf, sizeof(buf), 0);
}

enum rrr_err
rrr_close(struct rrr *req)
{
	if (req->ssl) {
		SSL_free(req->ssl);
	}
	if (close(req->sfd)) {
		return RRR_CLOSE;
	}
	return 0;
}

char *
rrr_err(enum rrr_err code)
{
	switch (code) {
	case RRR_OK:          return "Ok";
	case RRR_HOST:        return "Failed to get hostname";
	case RRR_CONNECT:     return "Failed to connect (invalid port?)";
	case RRR_OPEN:        return "Failed to open socket";
	case RRR_CLOSE:       return "Failed to close sfd";
	case RRR_SEND:        return "Failed to send request to server";
	case RRR_SSL_CTX:     return "Failed to create SSL context";
	case RRR_SSL_NEW:     return "Failed to create SSL instance";
	case RRR_SSL_HOST:    return "Failed to TLS set hostname";
	case RRR_SSL_FD:      return "Failed to set SSL sfd";
	case RRR_SSL_CONNECT: return "Failed to stablish SSL connection";
	case RRR_SSL_WRITE:   return "Failed to send secure request to server";
	}
	return "Unknown error";
}
