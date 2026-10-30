#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcp/pmapi.h>

#define ARCHIVE "/mayhem/qa/archives/20041125"
#define NAME "fuzz.derived"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    setenv("PCP_CONF", "/mayhem/src/include/pcp.conf", 0);
    int ctx = pmNewContext(PM_CONTEXT_ARCHIVE, ARCHIVE);
    if (ctx < 0) {
	fprintf(stderr, "cannot open archive %s: %s\n", ARCHIVE, pmErrStr(ctx));
	exit(1);
    }
    pmDestroyContext(ctx);
    return 0;
}

/* The input is a derived-metric expression, registered against an archive context and then evaluated. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *expr, *err = NULL;
    int ctx;

    expr = malloc(size + 1);
    if (expr == NULL)
	return -1;
    memcpy(expr, data, size);
    expr[size] = '\0';

    ctx = pmNewContext(PM_CONTEXT_ARCHIVE, ARCHIVE);
    if (ctx < 0) {
	free(expr);
	return -1;
    }
    if (pmAddDerivedMetric(NAME, expr, &err) < 0) {
	free(err);
    } else {
	const char *name = NAME;
	pmID pmid;
	pmDesc desc;
	pmResult *rp;
	int i;
	if (pmLookupName(1, &name, &pmid) == 1 && pmLookupDesc(pmid, &desc) >= 0) {
	    for (i = 0; i < 3; i++) {
		if (pmFetch(1, &pmid, &rp) < 0)
		    break;
		pmFreeResult(rp);
	    }
	}
    }
    pmDestroyContext(ctx);
    free(expr);
    return 0;
}
