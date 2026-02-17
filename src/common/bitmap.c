#include "common/bitmap.h"

#include <stdlib.h>
#include <string.h>

struct bitmap_s
{
    int total_bits;
    int num_words;    /* ceil(total_bits / 64) */
    uint64_t words[]; /* flexible array        */
};

bitmap_t bitmap_create(int total_bits)
{
    if (total_bits < 1) return NULL;

    int num_words = (total_bits + 63) / 64;

    struct bitmap_s *bm =
        calloc(1, sizeof(*bm) + (size_t)num_words * sizeof(uint64_t));
    if (!bm) return NULL;

    bm->total_bits = total_bits;
    bm->num_words  = num_words;

    /* Mark trailing bits beyond total_bits so they are never returned
       by bitmap_find_first_free. */
    int tail = total_bits & 63;
    if (tail != 0)
        bm->words[num_words - 1] |= ~((1ull << tail) - 1);

    return bm;
}

void bitmap_free(bitmap_t bm) { free(bm); }

void bitmap_set(bitmap_t bm, int bit)
{
    bm->words[bit / 64] |= 1ull << (bit % 64);
}

void bitmap_clear(bitmap_t bm, int bit)
{
    bm->words[bit / 64] &= ~(1ull << (bit % 64));
}

int bitmap_test(const bitmap_t bm, int bit)
{
    return (int)((bm->words[bit / 64] >> (bit % 64)) & 1);
}

int bitmap_find_first_free(const bitmap_t bm)
{
    for (int i = 0; i < bm->num_words; i++) {
        uint64_t free_bits = ~bm->words[i];
        if (free_bits == 0) continue;
        int bit = i * 64 + __builtin_ctzll(free_bits);
        if (bit < bm->total_bits)
            return bit;
        return -1;
    }
    return -1;
}

int bitmap_total_bits(const bitmap_t bm)
{
    return bm->total_bits;
}
