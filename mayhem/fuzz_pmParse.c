#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <pcp/pmapi.h>
#include <pcp/libpcp.h>

/* libpcp reads its config lazily (pmgetconfig) and exit(1)s without a pcp.conf; point it at the built one. */
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    setenv("PCP_CONF", "/mayhem/src/include/pcp.conf", 0);
    return 0;
}

/* First input byte selects the libpcp string parser, the rest is its argument. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *s, *err = NULL, *p;
    int sel;

    if (size < 1)
	return -1;
    sel = data[0] & 7;
    s = malloc(size);
    if (s == NULL)
	return -1;
    memcpy(s, data + 1, size - 1);
    s[size - 1] = '\0';

    switch (sel) {
    case 0: {
	struct timeval tv;
	if (pmParseInterval(s, &tv, &err) < 0)
	    free(err);
	break;
    }
    case 1: {
	/* start, end, align and offset specs are newline-separated */
	char *f[4] = { NULL, NULL, NULL, NULL };
	struct timeval logstart = { 1000000000, 0 }, logend = { 1000003600, 0 };
	struct timeval start, end, offset;
	int i;
	p = s;
	for (i = 0; i < 4 && p != NULL; i++) {
	    char *nl = strchr(p, '\n');
	    if (nl != NULL)
		*nl = '\0';
	    if (*p != '\0')
		f[i] = p;
	    p = (nl != NULL) ? nl + 1 : NULL;
	}
	if (pmParseTimeWindow(f[0], f[1], f[2], f[3], &logstart, &logend,
			      &start, &end, &offset, &err) < 0)
	    free(err);
	break;
    }
    case 2: {
	pmUnits units;
	double mult;
	if (pmParseUnitsStr(s, &units, &mult, &err) < 0)
	    free(err);
	break;
    }
    case 3: {
	pmMetricSpec *spec = NULL;
	if (pmParseMetricSpec(s, (data[0] >> 3) & 1, "localhost", &spec, &err) < 0)
	    free(err);
	else
	    pmFreeMetricSpec(spec);
	break;
    }
    case 4: {
	__pmHostSpec *hosts = NULL;
	int nhosts = 0;
	p = NULL;
	if (__pmParseHostSpec(s, &hosts, &nhosts, &p) >= 0)
	    __pmFreeHostSpec(hosts, nhosts);
	else
	    free(p);
	break;
    }
    case 5: {
	__pmHostSpec *hosts = NULL;
	int nhosts = 0;
	__pmHashCtl attrs;
	__pmHashInit(&attrs);
	if (__pmParseHostAttrsSpec(s, &hosts, &nhosts, &attrs, &err) >= 0) {
	    __pmFreeHostAttrsSpec(hosts, nhosts, &attrs);
	    __pmHashClear(&attrs);
	} else {
	    free(err);
	}
	break;
    }
    case 6: {
	char *out = NULL;
	size_t len = size - 1;
	if (__pmUrlDecode(s, len, &out) >= 0)
	    free(out);
	out = NULL;
	if (__pmUrlEncode(s, len, &out) >= 0)
	    free(out);
	break;
    }
    default: {
	struct tm tm;
	memset(&tm, 0, sizeof(tm));
	if (__pmParseCtime(s, &tm, &err) < 0)
	    free(err);
	break;
    }
    }
    free(s);
    return 0;
}
