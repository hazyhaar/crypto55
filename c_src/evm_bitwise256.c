// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. Licensed under the Business Source License 1.1;
// see ../LICENSE and ../NOTICE.

#include "evm_arith256.h"

static int u256_is_neg(const uint256_t *x)
{
	return (int)(x->w[3] >> 63);
}

static int u256_cmp(const uint256_t *a, const uint256_t *b)
{
	int i;
	for (i = 3; i >= 0; i--) {
		if (a->w[i] < b->w[i]) {
			return -1;
		}
		if (a->w[i] > b->w[i]) {
			return 1;
		}
	}
	return 0;
}

static int u256_shift_ge_256(const uint256_t *shift)
{
	return (shift->w[1] | shift->w[2] | shift->w[3]) != 0 || shift->w[0] >= 256ULL;
}

int evm_lt256(const uint256_t *a, const uint256_t *b)
{
	return u256_cmp(a, b) < 0;
}

int evm_gt256(const uint256_t *a, const uint256_t *b)
{
	return u256_cmp(a, b) > 0;
}

int evm_slt256(const uint256_t *a, const uint256_t *b)
{
	int na = u256_is_neg(a);
	int nb = u256_is_neg(b);
	if (na != nb) {
		return na;
	}
	return u256_cmp(a, b) < 0;
}

int evm_sgt256(const uint256_t *a, const uint256_t *b)
{
	int na = u256_is_neg(a);
	int nb = u256_is_neg(b);
	if (na != nb) {
		return nb;
	}
	return u256_cmp(a, b) > 0;
}

int evm_eq256(const uint256_t *a, const uint256_t *b)
{
	return (a->w[0] == b->w[0]) && (a->w[1] == b->w[1]) && (a->w[2] == b->w[2]) && (a->w[3] == b->w[3]);
}

int evm_iszero256(const uint256_t *a)
{
	return (a->w[0] | a->w[1] | a->w[2] | a->w[3]) == 0;
}

void evm_and256(const uint256_t *a, const uint256_t *b, uint256_t *out)
{
	out->w[0] = a->w[0] & b->w[0];
	out->w[1] = a->w[1] & b->w[1];
	out->w[2] = a->w[2] & b->w[2];
	out->w[3] = a->w[3] & b->w[3];
}

void evm_or256(const uint256_t *a, const uint256_t *b, uint256_t *out)
{
	out->w[0] = a->w[0] | b->w[0];
	out->w[1] = a->w[1] | b->w[1];
	out->w[2] = a->w[2] | b->w[2];
	out->w[3] = a->w[3] | b->w[3];
}

void evm_xor256(const uint256_t *a, const uint256_t *b, uint256_t *out)
{
	out->w[0] = a->w[0] ^ b->w[0];
	out->w[1] = a->w[1] ^ b->w[1];
	out->w[2] = a->w[2] ^ b->w[2];
	out->w[3] = a->w[3] ^ b->w[3];
}

void evm_not256(const uint256_t *a, uint256_t *out)
{
	out->w[0] = ~a->w[0];
	out->w[1] = ~a->w[1];
	out->w[2] = ~a->w[2];
	out->w[3] = ~a->w[3];
}

void evm_byte256(uint64_t i, const uint256_t *x, uint256_t *out)
{
	uint256_t xx = *x;
	out->w[0] = 0;
	out->w[1] = 0;
	out->w[2] = 0;
	out->w[3] = 0;
	if (i < 32ULL) {
		unsigned idx = 31U - (unsigned)i;
		unsigned wi = idx >> 3;
		unsigned sh = (idx & 7U) * 8U;
		out->w[0] = (xx.w[wi] >> sh) & 0xffULL;
	}
}

void evm_shl256(const uint256_t *shift, const uint256_t *val, uint256_t *out)
{
	uint256_t s = *shift;
	uint256_t v = *val;
	unsigned wsh;
	unsigned bsh;
	int i;

	if (u256_shift_ge_256(&s)) {
		out->w[0] = 0;
		out->w[1] = 0;
		out->w[2] = 0;
		out->w[3] = 0;
		return;
	}
	wsh = (unsigned)(s.w[0] / 64ULL);
	bsh = (unsigned)(s.w[0] % 64ULL);
	for (i = 0; i < 4; i++) {
		int src = i - (int)wsh;
		uint64_t lo = 0;
		uint64_t hi = 0;
		if (src >= 0 && src < 4) {
			lo = v.w[src];
		}
		src = i - (int)wsh - 1;
		if (src >= 0 && src < 4) {
			hi = v.w[src];
		}
		if (bsh == 0U) {
			out->w[i] = lo;
		} else {
			out->w[i] = (lo << bsh) | (hi >> (64U - bsh));
		}
	}
}

void evm_shr256(const uint256_t *shift, const uint256_t *val, uint256_t *out)
{
	uint256_t s = *shift;
	uint256_t v = *val;
	unsigned wsh;
	unsigned bsh;
	int i;

	if (u256_shift_ge_256(&s)) {
		out->w[0] = 0;
		out->w[1] = 0;
		out->w[2] = 0;
		out->w[3] = 0;
		return;
	}
	wsh = (unsigned)(s.w[0] / 64ULL);
	bsh = (unsigned)(s.w[0] % 64ULL);
	for (i = 0; i < 4; i++) {
		int src = i + (int)wsh;
		uint64_t lo = 0;
		uint64_t hi = 0;
		if (src >= 0 && src < 4) {
			lo = v.w[src];
		}
		src = i + (int)wsh + 1;
		if (src >= 0 && src < 4) {
			hi = v.w[src];
		}
		if (bsh == 0U) {
			out->w[i] = lo;
		} else {
			out->w[i] = (lo >> bsh) | (hi << (64U - bsh));
		}
	}
}

void evm_sar256(const uint256_t *shift, const uint256_t *val, uint256_t *out)
{
	uint256_t s = *shift;
	uint256_t v = *val;
	uint64_t fill;
	unsigned wsh;
	unsigned bsh;
	int i;

	fill = u256_is_neg(&v) ? UINT64_MAX : 0ULL;
	if (u256_shift_ge_256(&s)) {
		out->w[0] = fill;
		out->w[1] = fill;
		out->w[2] = fill;
		out->w[3] = fill;
		return;
	}
	wsh = (unsigned)(s.w[0] / 64ULL);
	bsh = (unsigned)(s.w[0] % 64ULL);
	for (i = 0; i < 4; i++) {
		int src = i + (int)wsh;
		uint64_t lo = fill;
		uint64_t hi = fill;
		if (src >= 0 && src < 4) {
			lo = v.w[src];
		}
		src = i + (int)wsh + 1;
		if (src >= 0 && src < 4) {
			hi = v.w[src];
		}
		if (bsh == 0U) {
			out->w[i] = lo;
		} else {
			out->w[i] = (lo >> bsh) | (hi << (64U - bsh));
		}
	}
}
