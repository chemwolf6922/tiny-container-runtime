#pragma once

#include <stdint.h>

/**
 * @file bitmap.h
 * @brief Variable-length bitmap using uint64_t words with fast first-free lookup.
 *
 * Designed for IP address pool allocation but usable as a general-purpose
 * bitmap.  Trailing bits beyond total_bits are pre-marked so
 * bitmap_find_first_free never returns an out-of-range index.
 */

typedef struct bitmap_s *bitmap_t;

/**
 * @brief Create a new bitmap.
 *
 * Bits [0, total_bits) are initially clear.
 * Bits beyond total_bits in the last word are pre-set so they are never
 * returned by bitmap_find_first_free.
 *
 * @param total_bits Total number of addressable bits. Must be >= 1.
 * @return bitmap_t  Newly allocated bitmap, or NULL on failure.
 *                   Caller must free with bitmap_free().
 */
bitmap_t bitmap_create(int total_bits);

/**
 * @brief Free a bitmap.
 *
 * @param bm The bitmap to free. NULL is safe.
 */
void bitmap_free(bitmap_t bm);

/**
 * @brief Set (mark) a bit.
 *
 * @param bm  The bitmap.
 * @param bit Bit index (0-based). Must be in [0, total_bits).
 */
void bitmap_set(bitmap_t bm, int bit);

/**
 * @brief Clear (unmark) a bit.
 *
 * @param bm  The bitmap.
 * @param bit Bit index (0-based). Must be in [0, total_bits).
 */
void bitmap_clear(bitmap_t bm, int bit);

/**
 * @brief Test whether a bit is set.
 *
 * @param bm  The bitmap.
 * @param bit Bit index (0-based). Must be in [0, total_bits).
 * @return int Non-zero if set, 0 if clear.
 */
int bitmap_test(const bitmap_t bm, int bit);

/**
 * @brief Find the lowest clear bit in the bitmap.
 *
 * Uses __builtin_ctzll to skip fully-occupied words in O(1) each.
 *
 * @param bm The bitmap.
 * @return int Bit index of the first clear bit, or -1 if all bits are set.
 */
int bitmap_find_first_free(const bitmap_t bm);

/**
 * @brief Get the total number of bits in the bitmap.
 *
 * @param bm The bitmap.
 * @return int Total bits.
 */
int bitmap_total_bits(const bitmap_t bm);
