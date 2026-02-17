#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "nft_helper.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

int nft_cmd(struct nft_ctx *nft, const char *fmt, ...)
{
    char *buf;
    va_list ap;
    va_start(ap, fmt);
    int n = vasprintf(&buf, fmt, ap);
    va_end(ap);

    if (n < 0) return -1;

    int rc = nft_run_cmd_from_buffer(nft, buf);
    if (rc < 0)
        fprintf(stderr, "nft_cmd: command failed: %s\n", buf);
    free(buf);
    return rc < 0 ? -1 : 0;
}
