#ifndef SECCOMP_JSON_H
#define SECCOMP_JSON_H

#include <stddef.h>

/*
 * Symbols produced by: ld -r -b binary -o seccomp.o seccomp.json
 *
 * _binary_seccomp_json_start  – first byte of the embedded JSON
 * _binary_seccomp_json_end    – one past the last byte
 *
 * Usage:
 *   const char *json = SECCOMP_JSON_DATA;
 *   size_t      len  = SECCOMP_JSON_LEN;
 */

extern const unsigned char _binary_seccomp_json_start[];
extern const unsigned char _binary_seccomp_json_end[];

/* Convenience macros */
#define SECCOMP_JSON_DATA ((const char *)_binary_seccomp_json_start)
#define SECCOMP_JSON_LEN  ((size_t)(_binary_seccomp_json_end - _binary_seccomp_json_start))

#endif /* SECCOMP_JSON_H */
