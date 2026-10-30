#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcp/pmapi.h>

/* libpcp reads its config lazily (pmgetconfig) and exit(1)s without a pcp.conf; point it at the built one. */
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    setenv("PCP_CONF", "/mayhem/src/include/pcp.conf", 0);
    return 0;
}

/* The input is a PMNS (metric name space) file, loaded without cpp preprocessing. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const char *tmpdir = getenv("TMPDIR");
    char path[4096];
    FILE *f;
    int fd;

    snprintf(path, sizeof(path), "%s/pmns-XXXXXX", tmpdir != NULL ? tmpdir : "/tmp");
    fd = mkstemp(path);
    if (fd < 0)
	return -1;
    f = fdopen(fd, "w");
    if (f == NULL) {
	close(fd);
	unlink(path);
	return -1;
    }
    fwrite(data, 1, size, f);
    fclose(f);

    if (pmLoadNameSpace(path) >= 0) {
	char **names = NULL;
	if (pmGetChildren("", &names) >= 0)
	    free(names);
	pmUnloadNameSpace();
    }
    unlink(path);
    return 0;
}
