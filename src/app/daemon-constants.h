#pragma once

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Default paths                                                             */
/* ═══════════════════════════════════════════════════════════════════════════ */

#ifndef TCR_DEFAULT_ROOT
#define TCR_DEFAULT_ROOT "/var/lib/tcr"
#endif

#ifndef TCR_LOCK_FILE
#define TCR_LOCK_FILE "/var/run/tcrd.lock"
#endif

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Error codes (matches docs/tcr_commands.md)                                */
/* ═══════════════════════════════════════════════════════════════════════════ */

#define ERR_UNKNOWN_CMD         1
#define ERR_CONTAINER_NOT_FOUND 2
#define ERR_IMAGE_NOT_FOUND     3
#define ERR_NETWORK_NOT_FOUND   4
#define ERR_RESOURCE_IN_USE     5
#define ERR_INVALID_ARG         6
#define ERR_INTERNAL            7
