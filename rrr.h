#ifndef _RRR_H
#define _RRR_H

#include <stdio.h>

enum {
	RRR_ERROR	= 100,	// Generic errors
	RRR_OPENSSL	= 200,	// OpenSSL errors
	RRR_ERRNO	= 300,	// LibC errno errors
};

enum rrr {
	RRR_OK		= 0,
	RRR_PORT        = RRR_ERROR,
	RRR_HOST,
	RRR_CONNECT,
	RRR_PRINT,
	RRR_SSL_CTX	= RRR_OPENSSL,
	RRR_SSL_NEW,
	RRR_SSL_HOST,
	RRR_SSL_FD,
	RRR_SSL_CONNECT,
	RRR_SSL_WRITE,
	RRR_SSL_CRLF,
	RRR_OPEN	= RRR_ERRNO,
	RRR_CLOSE,
	RRR_REQ_SEND,
	RRR_REQ_CRLF,
};

// Send FP content as request to HOST on PORT, use SSL if SECURE.
// Return 0 on success.
enum rrr rrr_req(FILE *fp, char *host, int port, int secure);

// Retrive string message for given ERR error code.
char *rrr_err(enum rrr err);

#endif // _RRR_H
