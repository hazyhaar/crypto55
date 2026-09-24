// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. Licensed under the Business Source License 1.1;
// see ../LICENSE and ../NOTICE.

#ifndef EVM_ARITH256_H
#define EVM_ARITH256_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
	uint64_t w[4];
} uint256_t;

void evm_add256(const uint256_t *a, const uint256_t *b, uint256_t *out);
void evm_sub256(const uint256_t *a, const uint256_t *b, uint256_t *out);
void evm_mul256(const uint256_t *a, const uint256_t *b, uint256_t *out);
void evm_div256(const uint256_t *a, const uint256_t *b, uint256_t *out);
void evm_sdiv256(const uint256_t *a, const uint256_t *b, uint256_t *out);
void evm_mod256(const uint256_t *a, const uint256_t *b, uint256_t *out);
void evm_smod256(const uint256_t *a, const uint256_t *b, uint256_t *out);
void evm_addmod256(const uint256_t *a, const uint256_t *b, const uint256_t *m, uint256_t *out);
void evm_mulmod256(const uint256_t *a, const uint256_t *b, const uint256_t *m, uint256_t *out);
void evm_exp256(const uint256_t *base, const uint256_t *exp, uint256_t *out);
void evm_signextend256(uint64_t b, const uint256_t *x, uint256_t *out);

#endif
