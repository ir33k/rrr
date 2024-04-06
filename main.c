#include "nap.h"
#include "uri.h"
#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <string.h>

// Allocate FP file stream as string to OUT, return string length.
static size_t
falloc(FILE *fp, char **out)
{
	const size_t chunk = 4096;
	size_t sz, len = 0;
	assert(fp);
	assert(out);
	if (!(*out = malloc(chunk))) {
		err(1, "Failed to allocate %lu", chunk);
	}
	while ((sz = fread(*out + len, 1, chunk - 1, fp))) {
		len += sz;
		if (sz == chunk - 1 && !(*out = realloc(*out, len + chunk))) {
			err(1, "Failed to reallocate %lu", len + chunk);
		}
	}
	memcpy(*out + len, "\0", 1);	// Null terminate
	return len;
}

int
main(void)
{
	int error, protocol, port, secure=0;
	size_t len;
	char *str, *host;
	len = falloc(stdin, &str);
	protocol = uri_protocol(str);
	if (!(host = uri_host(str))) errx(1, "Missing host");
	if (!(port = uri_port(str))) port = protocol;
	switch (protocol) {
	case GOPHER:
		if (!(str = uri_path(str))) str = "";
		len = strlen(str);
		break;
	case HTTPS:
	case GEMINI:
		secure = 1;
	}
	error = nap_req(str, len, host, port, secure);
	if (error >= NAP_OPENSSL) {
		errx(1, "ERROR SSL: %s", nap_err(error));
	}
	if (error >= NAP_ERRNO) {
		err(1, "ERROR: %s", nap_err(error));
	}
	if (error) {
		errx(1, "ERROR: %s", nap_err(error));
	}
	return 0;
}
