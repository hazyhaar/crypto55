// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. Licensed under the Business Source License 1.1;
// see ../LICENSE and ../NOTICE.

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

/*
 * Empreinte keccak256 d'un nœud déjà encodé en RLP. Un nœud parent ne
 * référence un enfant par cette empreinte que si son encodage atteint 32
 * octets ; les encodages plus courts sont insérés bruts (mpt_encode_child_ref).
 */
void mpt_hash_node(const uint8_t *rlp_data, size_t rlp_len, uint8_t out[32]);

/* Taille RLP de la référence parente portée pour un enfant encodé en RLP. */
size_t mpt_child_ref_size(const uint8_t *child_rlp, size_t child_len);

/* Écrit la référence parente d'un enfant encodé en RLP (brut ou empreinte). */
size_t mpt_encode_child_ref(const uint8_t *child_rlp, size_t child_len,
    uint8_t *out);

size_t mpt_encode_leaf(const uint8_t *key_nibbles, size_t num_nibbles,
    const uint8_t *value, size_t val_len, uint8_t *out);
size_t mpt_encode_extension(const uint8_t *key_nibbles, size_t num_nibbles,
    const uint8_t *child_rlp, size_t child_len, uint8_t *out);
size_t mpt_encode_branch(const uint8_t *children_rlp[16],
    const size_t child_lens[16], const int has_child[16], const uint8_t *value,
    size_t val_len, uint8_t *out);

#endif
