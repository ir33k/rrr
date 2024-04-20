// RRR Raw Request Response.  Provides same abstraction for secure and
// non secure requests wrapping OpenSSL lib.

#ifndef _RRR_H
#define _RRR_H

#include <stddef.h>             // For size_t type
#include <openssl/ssl.h>        // For SSL type

enum {
	RRR_ERR = 100,          // Generic error
	RRR_SSL = 200,          // OpenSSL error
	RRR_NO  = 300,          // Errno error
};

enum rrr_err {                  // Possible error codes
	RRR_OK          = 0,    // Everything is fine
	RRR_HOST        = RRR_ERR,
	RRR_CONNECT,
	RRR_SSL_CONNECT = RRR_SSL,
	RRR_SSL_CTX,
	RRR_SSL_FD,
	RRR_SSL_HOST,
	RRR_SSL_NEW,
	RRR_SSL_WRITE,
	RRR_OPEN        = RRR_NO,
	RRR_CLOSE,
	RRR_SEND,
};

struct rrr {                    // Request context
	char   *host;           // Host name that we connecting to
	int     sfd;            // Socket file descriptor
	SSL    *ssl;            // SSL instance for secure connection
};

// Open connection with REQ context to HOST with PORT, open secure
// connection if SSL.
enum rrr_err rrr_open(struct rrr *req, char *host, int port, int ssl);

// For open REQ connection send request bytes from BUF of SZ size.
enum rrr_err rrr_req(struct rrr *req, char *buf, size_t sz);

// For open REQ connection get server response to BUF of SZ size.
size_t rrr_res(struct rrr *req, char *buf, size_t sz);

// Close open REQ connection.
enum rrr_err rrr_close(struct rrr *req);

// Retrive string message for given error CODE.
char *rrr_err(enum rrr_err code);

#endif // _RRR_H
