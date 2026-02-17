#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define CHECK(expr, message) \
    do { \
        if (!(expr)) { \
            fprintf(stderr, "CHECK failed[%s:%d]: %s\n", __FILE__, __LINE__, message); \
            exit(EXIT_FAILURE); \
        } \
    } while (0)

/**
 * Compute the test data directory path from the test binary path (argv[0]).
 * The binary is expected to be at test/build/test_xxx, so the data directory
 * is at test/data (i.e., dirname(argv0)/../data).
 *
 * Creates the directory if it does not already exist.
 */
static inline void test_get_data_dir(char *buf, size_t bufsize, const char *argv0)
{
    char exe_dir[240];
    snprintf(exe_dir, sizeof(exe_dir), "%s", argv0);
    char *slash = strrchr(exe_dir, '/');
    if (slash)
        *slash = '\0';
    else
        snprintf(exe_dir, sizeof(exe_dir), ".");
    snprintf(buf, bufsize, "%s/../data", exe_dir);
    mkdir(buf, 0755);
}
