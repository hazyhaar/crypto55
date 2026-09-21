#ifndef MPT_HASH_H
#define MPT_HASH_H

#include "crypto_keccak.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

size_t mpt_compact_encode(const uint8_t *nibbles, size_t num_nibbles,
    int is_leaf, uint8_t *out);
size_t rlp_encode_bytes(const uint8_t *data, size_t data_len, uint8_t *out);
size_t rlp_encode_list_header(size_t payload_len, uint8_t *out);
void mpt_hash_node(const uint8_t *rlp_data, size_t rlp_len, uint8_t out[32]);

size_t mpt_encode_leaf(const uint8_t *key_nibbles, size_t num_nibbles,
    const uint8_t *value, size_t val_len, uint8_t *out);
size_t mpt_encode_extension(const uint8_t *key_nibbles, size_t num_nibbles,
    const uint8_t child_hash[32], uint8_t *out);
size_t mpt_encode_branch(const uint8_t children[16][32],
    const int has_child[16], const uint8_t *value, size_t val_len,
    uint8_t *out);

#endif
