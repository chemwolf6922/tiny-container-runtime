#pragma once

#include <nftables/libnftables.h>

/**
 * @brief Run an nft command string via libnftables (no subprocess).
 *
 * @param nft  An initialized nft_ctx (with buffered output/error).
 * @param fmt  printf-style format string for the nft command.
 * @return 0 on success, -1 on failure.
 */
int nft_cmd(struct nft_ctx *nft, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
