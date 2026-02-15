#pragma once

#include <stdio.h>
#include <stdlib.h>

#define CHECK(expr, message) \
    do { \
        if (!(expr)) { \
            fprintf(stderr, "CHECK failed[%s:%d]: %s\n", __FILE__, __LINE__, message); \
            exit(EXIT_FAILURE); \
        } \
    } while (0)
