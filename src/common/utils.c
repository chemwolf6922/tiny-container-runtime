#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "common/utils.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

char *path_join(const char *a, const char *b)
{
    size_t la = strlen(a);
    size_t lb = strlen(b);
    /* strip trailing slash from a */
    while (la > 0 && a[la - 1] == '/') la--;
    /* strip leading slash from b */
    while (*b == '/') { b++; lb--; }

    char *out = malloc(la + 1 + lb + 1);
    if (!out) return NULL;
    memcpy(out, a, la);
    out[la] = '/';
    memcpy(out + la + 1, b, lb);
    out[la + 1 + lb] = '\0';
    return out;
}

cJSON *load_json_file(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0)
    {
        close(fd);
        return NULL;
    }

    void *data = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (data == MAP_FAILED) return NULL;

    cJSON *root = cJSON_ParseWithLength(data, (size_t)st.st_size);
    munmap(data, (size_t)st.st_size);
    return root;
}
