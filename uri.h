#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

// Protocol types and to corresponding default ports.
enum {
	GOPHER = 70,
	HTTP   = 80,
	HTTPS  = 443,
	GEMINI = 1965,
};

// Return pointer to first character after protocol in URI or if no
// protocol present then return initial URI pointer.
static inline char *
_uri_skip_protocol(char *uri)
{
	char *beg;
	assert(uri);
	return (beg = strstr(uri, "://")) ? beg + 3 : uri;
}

// Get protocol default port from URI string.
static int
uri_protocol(char *uri)
{
	char *beg;
	int sz;
	assert(uri);
	if (!(beg = strstr(uri, "://"))) {
		return 0;
	}
	for (sz = 0; beg > uri && *(beg -1) > ' '; sz++) {
		beg--;
	}
	if (sz == 0) {
		return 0;
	}
#define _URI_PROTOCOL_IS(x) sz == strlen(x) && !strncasecmp(beg, x, sz)
	if (_URI_PROTOCOL_IS("gopher")) return GOPHER;
	if (_URI_PROTOCOL_IS("gemini")) return GEMINI;
	if (_URI_PROTOCOL_IS("https"))  return HTTPS;
	if (_URI_PROTOCOL_IS("http"))   return HTTP;
	return 0;
}

// Get host from URI string.  Return NULL if not found.  Return
// pointer to static string on success.
static char *
uri_host(char *uri)
{
	static char buf[4096];
	char *end;
	size_t len;
	assert(uri);
	assert(strlen(uri) < sizeof(buf));
	uri = _uri_skip_protocol(uri);
	len = strlen(uri);
	if (len == 0) {
		return 0;
	}
	if (!(end = strpbrk(uri, ":/"))) {
		end = uri + len;
	}
	len = end - uri;
	while (len > 0 && uri[len-1] <= ' ') {
		len--;
	}
	if (len == 0) {
		return 0;
	}
	buf[len] = 0;
	return memcpy(buf, uri, len);
}

// Get port from URI string.  Return 0 by default.
static int
uri_port(char *uri)
{
	assert(uri);
	uri = _uri_skip_protocol(uri);
	return (uri = strchr(uri, ':')) ? atoi(uri + 1) : 0;
}

// Return pointer to first URI string path character.  Return NULL if
// not found.
static char *
uri_path(char *uri)
{
	assert(uri);
	return strchr(_uri_skip_protocol(uri), '/');
}
