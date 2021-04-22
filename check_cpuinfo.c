#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>

int main() {
        FILE *fp = fopen("/proc/cpuinfo", "r");
        assert(fp != NULL);
        size_t n = 0;
        char *line = NULL;
        while (getline(&line, &n, fp) > 0) {
                if (strstr(line, "model name") || strstr(line, "cpu cores")) {
                        printf("%s", line);
                }
        }
        free(line);
        fclose(fp);
        return errno;
}


/*
#include <stdio.h>
#include <sys/sysinfo.h>

int main(int argc, char *argv[])
{
    printf("This system has %d processors configured and "
        "%d processors available.\n",
        get_nprocs_conf(), get_nprocs());
    return 0;
}
*/