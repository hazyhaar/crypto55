// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. Licensed under the Business Source License 1.1;
// see ../LICENSE and ../NOTICE.

#include "mpt_hash.h"

#include "crypto_keccak.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static size_t rlp_int_len(size_t n)
{
	size_t len;

	len = 0;
	while (n != 0) {
		len++;
		n >>= 8;
	}
	return len;
}

static void rlp_write_int(size_t n, uint8_t *out, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		out[len - 1U - i] = (uint8_t)(n & 0xffU);
		n >>= 8;
	}
}

static size_t rlp_bytes_size(const uint8_t *data, size_t data_len)
{
	if (data_len == 1U && data[0] < 0x80U) {
		return 1U;
	}
	if (data_len < 56U) {
		return 1U + data_len;
	}
	return 1U + rlp_int_len(data_len) + data_len;
}

size_t mpt_compact_encode(const uint8_t *nibbles, size_t num_nibbles,
    int is_leaf, uint8_t *out)
{
	uint8_t flag;
	size_t i;
	size_t n;

	flag = is_leaf ? 2U : 0U;
	if (num_nibbles & 1U) {
		flag |= 1U;
		out[0] = (uint8_t)((flag << 4) | (nibbles[0] & 0x0fU));
		i = 1U;
		n = 1U;
	} else {
		out[0] = (uint8_t)(flag << 4);
		i = 0U;
		n = 1U;
	}
	while (i < num_nibbles) {
		out[n] = (uint8_t)(((nibbles[i] & 0x0fU) << 4) |
		    (nibbles[i + 1U] & 0x0fU));
		n++;
		i += 2U;
	}
	return n;
}

size_t rlp_encode_bytes(const uint8_t *data, size_t data_len, uint8_t *out)
{
	size_t llen;

	if (data_len == 1U && data[0] < 0x80U) {
		out[0] = data[0];
		return 1U;
	}
	if (data_len < 56U) {
		out[0] = (uint8_t)(0x80U + data_len);
		if (data_len != 0U) {
			memcpy(out + 1, data, data_len);
		}
		return 1U + data_len;
	}
	llen = rlp_int_len(data_len);
	out[0] = (uint8_t)(0xb7U + llen);
	rlp_write_int(data_len, out + 1, llen);
	memcpy(out + 1U + llen, data, data_len);
	return 1U + llen + data_len;
}

size_t rlp_encode_list_header(size_t payload_len, uint8_t *out)
{
	size_t llen;

	if (payload_len < 56U) {
		out[0] = (uint8_t)(0xc0U + payload_len);
		return 1U;
	}
	llen = rlp_int_len(payload_len);
	out[0] = (uint8_t)(0xf7U + llen);
	rlp_write_int(payload_len, out + 1, llen);
	return 1U + llen;
}

void mpt_hash_node(const uint8_t *rlp_data, size_t rlp_len, uint8_t out[32])
{
	keccak256(rlp_data, rlp_len, out);
}

size_t mpt_child_ref_size(const uint8_t *child_rlp, size_t child_len)
{
	if (child_len < 32U) {
		return child_len;
	}
	return 1U + 32U;
}

size_t mpt_encode_child_ref(const uint8_t *child_rlp, size_t child_len,
    uint8_t *out)
{
	uint8_t hash[32];

	if (child_len < 32U) {
		memcpy(out, child_rlp, child_len);
		return child_len;
	}
	keccak256(child_rlp, child_len, hash);
	return rlp_encode_bytes(hash, 32U, out);
}

size_t mpt_encode_leaf(const uint8_t *key_nibbles, size_t num_nibbles,
    const uint8_t *value, size_t val_len, uint8_t *out)
{
	uint8_t compact[256];
	size_t compact_len;
	size_t payload;
	size_t n;

	compact_len = mpt_compact_encode(key_nibbles, num_nibbles, 1, compact);
	payload = rlp_bytes_size(compact, compact_len) +
	    rlp_bytes_size(value, val_len);
	n = rlp_encode_list_header(payload, out);
	n += rlp_encode_bytes(compact, compact_len, out + n);
	n += rlp_encode_bytes(value, val_len, out + n);
	return n;
}

size_t mpt_encode_extension(const uint8_t *key_nibbles, size_t num_nibbles,
    const uint8_t *child_rlp, size_t child_len, uint8_t *out)
{
	uint8_t compact[256];
	size_t compact_len;
	size_t payload;
	size_t n;

	compact_len = mpt_compact_encode(key_nibbles, num_nibbles, 0, compact);
	payload = rlp_bytes_size(compact, compact_len) +
	    mpt_child_ref_size(child_rlp, child_len);
	n = rlp_encode_list_header(payload, out);
	n += rlp_encode_bytes(compact, compact_len, out + n);
	n += mpt_encode_child_ref(child_rlp, child_len, out + n);
	return n;
}

size_t mpt_encode_branch(const uint8_t *children_rlp[16],
    const size_t child_lens[16], const int has_child[16], const uint8_t *value,
    size_t val_len, uint8_t *out)
{
	size_t payload;
	size_t n;
	int i;

	payload = 0;
	for (i = 0; i < 16; i++) {
		if (has_child[i] != 0) {
			payload += mpt_child_ref_size(children_rlp[i], child_lens[i]);
		} else {
			payload += 1U;
		}
	}
	if (val_len == 0U) {
		payload += 1U;
	} else {
		payload += rlp_bytes_size(value, val_len);
	}

	n = rlp_encode_list_header(payload, out);
	for (i = 0; i < 16; i++) {
		if (has_child[i] != 0) {
			n += mpt_encode_child_ref(children_rlp[i], child_lens[i], out + n);
		} else {
			out[n] = 0x80U;
			n += 1U;
		}
	}
	if (val_len == 0U) {
		out[n] = 0x80U;
		n += 1U;
	} else {
		n += rlp_encode_bytes(value, val_len, out + n);
	}
	return n;
}
