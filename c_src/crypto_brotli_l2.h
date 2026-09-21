#ifndef CRYPTO_BROTLI_L2_H
#define CRYPTO_BROTLI_L2_H

#include <stddef.h>
#include <stdint.h>

#define BROTLI_L2_OK 0
#define BROTLI_L2_ERR_ARG -1
#define BROTLI_L2_ERR_CAPACITY -2
#define BROTLI_L2_ERR_TRUNC -3
#define BROTLI_L2_ERR_FORMAT -4
#define BROTLI_L2_ERR_WINDOW -5
#define BROTLI_L2_ERR_DICT -6

int brotli_l2_decompress(const uint8_t *in, size_t in_len, uint8_t *out,
    size_t out_capacity, size_t *out_len);

#endif
