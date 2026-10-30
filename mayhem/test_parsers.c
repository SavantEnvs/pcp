/* Known-answer tests for the libpcp parsers/formatters the fuzz harnesses exercise. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <pcp/pmapi.h>
#include <pcp/libpcp.h>

static int ntests, nfail;

static void check(int ok, const char *what)
{
    ntests++;
    if (!ok)
	nfail++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", ntests, what);
}

int main(void)
{
    char *err = NULL;

    {
	char buf[3][32];
	strncpy(buf[0], pmNumberStr(0.0), 31);
	strncpy(buf[1], pmNumberStr(1234.0), 31);
	strncpy(buf[2], pmNumberStr(5.5e6), 31);
	buf[0][31] = buf[1][31] = buf[2][31] = '\0';
	printf("# pmNumberStr: [%s] [%s] [%s]\n", buf[0], buf[1], buf[2]);
	check(strcmp(buf[0], "  0.00 ") == 0, "pmNumberStr(0)");
	check(strcmp(buf[1], "  1.23K") == 0, "pmNumberStr(1234)");
	check(strcmp(buf[2], "  5.50M") == 0, "pmNumberStr(5.5e6)");
    }

    {
	struct timespec tv;
	check(pmParseInterval("1 hour 30 seconds", &tv, &err) == 0 && tv.tv_sec == 3630 && tv.tv_nsec == 0,
	      "pmParseInterval(1 hour 30 seconds)");
	check(pmParseInterval("2.5s", &tv, &err) == 0 && tv.tv_sec == 2 && tv.tv_nsec == 500000000,
	      "pmParseInterval(2.5s)");
	check(pmParseInterval("bogus", &tv, &err) < 0 && err != NULL, "pmParseInterval rejects garbage");
	free(err);
	err = NULL;
    }
    {
	pmUnits u;
	double mult = 0;
	check(pmParseUnitsStr("Kbyte/sec", &u, &mult, &err) == 0 && u.dimSpace == 1 && u.dimTime == -1 &&
	      u.scaleSpace == PM_SPACE_KBYTE && u.scaleTime == PM_TIME_SEC && mult == 1.0,
	      "pmParseUnitsStr(Kbyte/sec)");
	check(pmParseUnitsStr("count", &u, &mult, &err) == 0 && u.dimCount == 1 && u.dimSpace == 0,
	      "pmParseUnitsStr(count)");
    }
    {
	pmMetricSpec *ms = NULL;
	check(pmParseMetricSpec("kernel.all.load[1,5]", 0, "localhost", &ms, &err) == 0 &&
	      ms != NULL && strcmp(ms->metric, "kernel.all.load") == 0 && ms->ninst == 2 &&
	      strcmp(ms->inst[0], "1") == 0 && strcmp(ms->inst[1], "5") == 0 &&
	      ms->isarch == 0 && strcmp(ms->source, "localhost") == 0,
	      "pmParseMetricSpec(kernel.all.load[...])");
	if (ms != NULL)
	    pmFreeMetricSpec(ms);
	check(pmParseMetricSpec("host1:foo.bar", 0, "localhost", &ms, &err) == 0 && ms != NULL &&
	      strcmp(ms->source, "host1") == 0 && strcmp(ms->metric, "foo.bar") == 0 && ms->ninst == 0,
	      "pmParseMetricSpec(host1:foo.bar)");
	if (ms != NULL)
	    pmFreeMetricSpec(ms);
    }
    {
	__pmHostSpec *hosts = NULL;
	int nhosts = 0;
	char *end = NULL;
	check(__pmParseHostSpec("pcphost@proxy:44322", &hosts, &nhosts, &end) == 0 && nhosts == 2 &&
	      strcmp(hosts[0].name, "pcphost") == 0 && hosts[0].nports == 0 &&
	      strcmp(hosts[1].name, "proxy") == 0 && hosts[1].nports == 1 && hosts[1].ports[0] == 44322,
	      "__pmParseHostSpec(pcphost@proxy:44322)");
	if (hosts != NULL)
	    __pmFreeHostSpec(hosts, nhosts);
    }
    {
	char path[] = "/tmp/pcp-test-pmns-XXXXXX";
	int fd = mkstemp(path);
	const char *text = "root {\n\tsample\n}\nsample {\n\tload\t1:2:3\n\tcolour\t1:3:4\n}\n";
	const char *names[] = { "sample.load", "sample.colour", "sample.nope" };
	pmID ids[3];
	int n;
	if (fd >= 0) {
	    if (write(fd, text, strlen(text)) < 0)
		perror("write");
	    close(fd);
	}
	check(fd >= 0 && pmLoadNameSpace(path) == 0, "pmLoadNameSpace");
	n = pmLookupName(3, names, ids);
	check(n == PM_ERR_NAME || n == 2, "pmLookupName partial result code");
	check(ids[0] == pmID_build(1, 2, 3) && ids[1] == pmID_build(1, 3, 4) && ids[2] == PM_ID_NULL,
	      "pmLookupName ids");
	pmUnloadNameSpace();
	unlink(path);
    }

    printf("tests=%d failed=%d\n", ntests, nfail);
    return nfail != 0;
}
