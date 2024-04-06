#ifndef _NAP_H
#define _NAP_H

enum {
	NAP_ERRNO	= 100,	// LibC errno errors
	NAP_OPENSSL	= 200,	// OpenSSL errors
};

enum nap {
	NAP_OK		= 0,
	NAP_PORT,
	NAP_HOST,
	NAP_CONNECT,
	NAP_PRINT,
	NAP_OPEN	= NAP_ERRNO,
	NAP_CLOSE,
	NAP_REQ_SEND,
	NAP_REQ_CRLF,
	NAP_SSL_CTX	= NAP_OPENSSL,
	NAP_SSL_NEW,
	NAP_SSL_HOST,
	NAP_SSL_FD,
	NAP_SSL_CONNECT,
	NAP_SSL_WRITE,
	NAP_SSL_CRLF,
};

// Send MSG or SZ size request to HOST on PORT, use SSL if SECURE.
// Return 0 on success.
enum nap nap_req(char *msg, int sz, char *host, int port, int secure);

// Retrive string message for given ERR error code.
char *nap_err(enum nap err);

#endif // _NAP_H
