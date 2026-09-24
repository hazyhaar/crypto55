// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. Licensed under the Business Source License 1.1;
// see ../LICENSE and ../NOTICE.

#ifndef CRYPTO_KECCAK_H
#define CRYPTO_KECCAK_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
	uint64_t a[25];
} keccak_state_t;

void keccak_f1600(keccak_state_t *st);
void keccak256(const uint8_t *in, size_t in_len, uint8_t out[32]);
void keccak512(const uint8_t *in, size_t in_len, uint8_t out[64]);

#endif
