// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. Licensed under the Business Source License 1.1;
// see ../LICENSE and ../NOTICE.

#include "crypto_brotli_l2.h"

#include <string.h>

#define L2_WIN 65536u
#define L2_MAX_ALPH 704u

static const uint8_t k_cl_order[18] = {
	1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15
};
static const uint8_t k_cl_pfx_len[16] = {
	2, 2, 2, 3, 2, 2, 2, 4, 2, 2, 2, 3, 2, 2, 2, 4
};
static const uint8_t k_cl_pfx_val[16] = {
	0, 4, 3, 2, 0, 4, 3, 1, 0, 4, 3, 2, 0, 4, 3, 5
};
static const uint8_t k_ins_nbits[24] = {
	0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 12, 14, 24
};
static const uint32_t k_ins_base[24] = {
	0, 1, 2, 3, 4, 5, 6, 8, 10, 14, 18, 26, 34, 50, 66, 98, 130, 194, 322, 578,
	1090, 2114, 6210, 22594
};
static const uint8_t k_cpy_nbits[24] = {
	0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 24
};
static const uint32_t k_cpy_base[24] = {
	2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 18, 22, 30, 38, 54, 70, 102, 134, 198,
	326, 582, 1094, 2118
};
static const uint8_t k_blk_nbits[26] = {
	2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 7, 8, 9, 10, 11, 12,
	13, 24
};
static const uint32_t k_blk_base[26] = {
	1, 5, 9, 13, 17, 25, 33, 41, 49, 65, 81, 97, 113, 145, 177, 209, 241, 305,
	369, 497, 753, 1265, 2289, 4337, 8433, 16625
};
static const int8_t k_short_delta[16] = {
	0, 0, 0, 0, -1, 1, -2, 2, -3, 3, -1, 1, -2, 2, -3, 3
};
static const uint8_t k_short_which[16] = {
	0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1
};
static const uint8_t k_utf8_signed[1024] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 0, 0, 4, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	8, 12, 16, 12, 12, 20, 12, 16, 24, 28, 12, 12, 32, 12, 36, 12,
	44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 32, 32, 24, 40, 28, 12,
	12, 48, 52, 52, 52, 48, 52, 52, 52, 48, 52, 52, 52, 52, 52, 48,
	52, 52, 52, 52, 52, 48, 52, 52, 52, 52, 52, 24, 12, 28, 12, 12,
	12, 56, 60, 60, 60, 56, 60, 60, 60, 56, 60, 60, 60, 60, 60, 56,
	60, 60, 60, 60, 60, 56, 60, 60, 60, 60, 60, 24, 12, 28, 12, 0,
	0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
	0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
	0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
	0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
	2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
	2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
	2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
	2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1,
	1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1,
	1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 1, 1, 1, 1, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	0, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
	16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
	16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
	24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
	24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
	24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
	24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
	32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
	32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
	32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
	32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
	40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40,
	40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40,
	40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40,
	48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 56,
	0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
	4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
	4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
	4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
	5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
	5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
	5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
	6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7
};

static uint8_t g_ctx[2048];
static uint8_t g_lit_cl[256][256];
static uint8_t g_cmd_cl[256][704];
static uint8_t g_dist_cl[256][520];
static uint8_t g_lit_map[256 * 64];
static uint8_t g_dist_map[256 * 4];
static uint8_t g_ctx_mode[256];
static int g_ctx_ready;

typedef struct {
	const uint8_t *p;
	const uint8_t *end;
	uint64_t acc;
	int bits;
} br_t;

typedef struct {
	uint16_t count[16];
	uint16_t first[16];
	uint16_t pos[16];
	uint16_t symbols[704];
	uint16_t table[256];
	int single;
	uint16_t single_sym;
} huff_t;

typedef struct {
	br_t br;
	uint8_t *out;
	size_t cap;
	size_t pos;
	uint32_t wsize;
	uint32_t dist_rb[4];
	uint32_t npostfix;
	uint32_t ndirect;
	uint32_t nbl[3];
	uint32_t ntrees_l;
	uint32_t ntrees_d;
	uint32_t dist_alph;
	uint32_t btype[3];
	uint32_t btype_prev[3];
	uint32_t blen[3];
	huff_t h_bt[3];
	huff_t h_bl[3];
	huff_t h_lit;
	huff_t h_cmd;
	huff_t h_dist;
	int lit_id;
	int cmd_id;
	int dist_id;
	uint8_t p1;
	uint8_t p2;
} dec_t;

static void ctx_init(void)
{
	uint32_t i;
	if (g_ctx_ready) {
		return;
	}
	for (i = 0; i < 256; i++) {
		g_ctx[i] = (uint8_t)(i & 63u);
		g_ctx[256 + i] = 0;
		g_ctx[512 + i] = (uint8_t)(i >> 2);
		g_ctx[768 + i] = 0;
	}
	memcpy(g_ctx + 1024, k_utf8_signed, 1024);
	g_ctx_ready = 1;
}

static unsigned alph_bits(uint32_t alph)
{
	unsigned n = 0;
	uint32_t x;
	if (alph <= 1u) {
		return 0;
	}
	x = alph - 1u;
	while (x > 0u) {
		x >>= 1;
		n++;
	}
	return n;
}

static int br_need(br_t *b, unsigned n)
{
	size_t left;
	if ((unsigned)b->bits >= n) {
		return BROTLI_L2_OK;
	}
	left = (size_t)(b->end - b->p);
	if (b->bits == 0 && left >= 8u) {
		uint64_t v = (uint64_t)b->p[0]
		    | ((uint64_t)b->p[1] << 8)
		    | ((uint64_t)b->p[2] << 16)
		    | ((uint64_t)b->p[3] << 24)
		    | ((uint64_t)b->p[4] << 32)
		    | ((uint64_t)b->p[5] << 40)
		    | ((uint64_t)b->p[6] << 48)
		    | ((uint64_t)b->p[7] << 56);
		b->acc = v;
		b->p += 8;
		left -= 8u;
		b->bits = 64;
		if ((unsigned)b->bits >= n) {
			return BROTLI_L2_OK;
		}
	}
	while ((unsigned)b->bits < n) {
		if (left >= 4u && b->bits <= 32) {
			uint32_t v = (uint32_t)b->p[0]
			    | ((uint32_t)b->p[1] << 8)
			    | ((uint32_t)b->p[2] << 16)
			    | ((uint32_t)b->p[3] << 24);
			b->acc |= ((uint64_t)v) << b->bits;
			b->p += 4;
			left -= 4u;
			b->bits += 32;
			continue;
		}
		if (left == 0) {
			return BROTLI_L2_ERR_TRUNC;
		}
		if (b->bits > 56) {
			return BROTLI_L2_ERR_FORMAT;
		}
		b->acc |= ((uint64_t)(*b->p++)) << b->bits;
		left--;
		b->bits += 8;
	}
	return BROTLI_L2_OK;
}

static int br_read(br_t *b, unsigned n, uint32_t *v)
{
	uint32_t mask;
	if (n == 0) {
		*v = 0;
		return BROTLI_L2_OK;
	}
	if (n > 24u) {
		return BROTLI_L2_ERR_FORMAT;
	}
	if ((unsigned)b->bits < n) {
		int r = br_need(b, n);
		if (r < 0) {
			return r;
		}
	}
	mask = (1u << n) - 1u;
	*v = (uint32_t)b->acc & mask;
	b->acc >>= n;
	b->bits -= (int)n;
	return BROTLI_L2_OK;
}

static int br_peek(br_t *b, unsigned n, uint32_t *v)
{
	if (n == 0) {
		*v = 0;
		return BROTLI_L2_OK;
	}
	if ((unsigned)b->bits < n) {
		int r = br_need(b, n);
		if (r < 0) {
			return r;
		}
	}
	*v = (uint32_t)b->acc & ((1u << n) - 1u);
	return BROTLI_L2_OK;
}

static void br_drop(br_t *b, unsigned n)
{
	b->acc >>= n;
	b->bits -= (int)n;
}

static void br_align(br_t *b)
{
	unsigned r = (unsigned)b->bits & 7u;
	if (r != 0) {
		b->acc >>= r;
		b->bits -= (int)r;
	}
}

static uint16_t bit_rev8(uint16_t code, unsigned n);

static int huff_build(huff_t *h, const uint8_t *len, uint32_t n)
{
	uint32_t i;
	uint32_t nz = 0;
	uint32_t last = 0;
	uint16_t code;
	unsigned bits;
	uint16_t seen[16];
	uint32_t space;
	uint16_t acc;
	memset(h, 0, sizeof(*h));
	if (n == 0 || n > L2_MAX_ALPH) {
		return BROTLI_L2_ERR_FORMAT;
	}
	for (i = 0; i < n; i++) {
		uint8_t L = len[i];
		if (L == 0xFFu) {
			h->single = 1;
			h->single_sym = (uint16_t)i;
			return BROTLI_L2_OK;
		}
		if (L > 15u) {
			return BROTLI_L2_ERR_FORMAT;
		}
		if (L != 0) {
			h->count[L]++;
			nz++;
			last = i;
		}
	}
	if (nz == 0) {
		h->single = 1;
		h->single_sym = (uint16_t)last;
		return BROTLI_L2_OK;
	}
	if (nz == 1) {
		h->single = 1;
		h->single_sym = (uint16_t)last;
		return BROTLI_L2_OK;
	}
	code = 0;
	h->count[0] = 0;
	for (bits = 1; bits <= 15; bits++) {
		code = (uint16_t)((code + h->count[bits - 1]) << 1);
		h->first[bits] = code;
	}
	acc = 0;
	space = 0;
	for (bits = 1; bits <= 15; bits++) {
		h->pos[bits] = acc;
		acc = (uint16_t)(acc + h->count[bits]);
		if (h->count[bits] != 0) {
			space += (uint32_t)h->count[bits] << (15u - bits);
		}
	}
	if (space != 32768u) {
		return BROTLI_L2_ERR_FORMAT;
	}
	memset(seen, 0, sizeof(seen));
	for (i = 0; i < n; i++) {
		uint8_t L = len[i];
		if (L != 0) {
			uint16_t slot = (uint16_t)(h->pos[L] + seen[L]);
			uint16_t code = (uint16_t)(h->first[L] + seen[L]);
			h->symbols[slot] = (uint16_t)i;
			if (L <= 8u) {
				unsigned rev = bit_rev8(code, L);
				unsigned step = 1u << L;
				uint16_t pack = (uint16_t)((uint16_t)i |
				    ((uint16_t)L << 12));
				unsigned idx;
				for (idx = rev; idx < 256u; idx += step) {
					h->table[idx] = pack;
				}
			}
			seen[L]++;
		}
	}
	return BROTLI_L2_OK;
}

static uint16_t bit_rev8(uint16_t code, unsigned n)
{
	uint16_t r = 0;
	unsigned i;
	for (i = 0; i < n; i++) {
		r = (uint16_t)((r << 1) | (code & 1u));
		code >>= 1;
	}
	return r;
}

static int huff_decode_slow(br_t *b, const huff_t *h, uint32_t *sym,
    uint32_t code, unsigned start)
{
	unsigned len;
	for (len = start + 1; len <= 15; len++) {
		uint32_t bit;
		uint32_t cnt;
		uint32_t first;
		int r = br_read(b, 1, &bit);
		if (r < 0) {
			return r;
		}
		code = (code << 1) | bit;
		cnt = h->count[len];
		if (cnt == 0) {
			continue;
		}
		first = h->first[len];
		if (code >= first && (code - first) < cnt) {
			*sym = h->symbols[h->pos[len] + (uint16_t)(code - first)];
			return BROTLI_L2_OK;
		}
	}
	return BROTLI_L2_ERR_FORMAT;
}

static int huff_decode(br_t *b, const huff_t *h, uint32_t *sym)
{
	uint16_t e;
	unsigned L;
	uint32_t prefix;
	uint32_t code;
	unsigned i;
	if (h->single) {
		*sym = h->single_sym;
		return BROTLI_L2_OK;
	}
	if ((unsigned)b->bits < 8u) {
		int r = br_need(b, 8u);
		if (r < 0) {
			return huff_decode_slow(b, h, sym, 0, 0);
		}
	}
	e = h->table[(uint8_t)b->acc];
	L = (unsigned)(e >> 12);
	if (L != 0) {
		*sym = (uint32_t)(e & 0x0fffu);
		b->acc >>= L;
		b->bits -= (int)L;
		return BROTLI_L2_OK;
	}
	prefix = (uint32_t)(b->acc & 0xffu);
	code = 0;
	for (i = 0; i < 8; i++) {
		code = (code << 1) | (prefix & 1u);
		prefix >>= 1;
	}
	b->acc >>= 8;
	b->bits -= 8;
	return huff_decode_slow(b, h, sym, code, 8);
}

static int read_huffman_lengths(br_t *b, uint32_t alph, uint8_t *len)
{
	uint32_t kind;
	int r;
	unsigned i;
	if (alph == 0 || alph > L2_MAX_ALPH) {
		return BROTLI_L2_ERR_FORMAT;
	}
	memset(len, 0, alph);
	r = br_read(b, 2, &kind);
	if (r < 0) {
		return r;
	}
	if (kind == 1u) {
		uint32_t nsm1;
		uint32_t nsym;
		uint32_t syms[4];
		uint32_t tree_sel = 0;
		unsigned ab = alph_bits(alph);
		uint8_t ls[4];
		r = br_read(b, 2, &nsm1);
		if (r < 0) {
			return r;
		}
		nsym = nsm1 + 1u;
		for (i = 0; i < nsym; i++) {
			r = br_read(b, ab, &syms[i]);
			if (r < 0) {
				return r;
			}
			if (syms[i] >= alph) {
				return BROTLI_L2_ERR_FORMAT;
			}
		}
		for (i = 0; i < nsym; i++) {
			unsigned j;
			for (j = 0; j < i; j++) {
				if (syms[i] == syms[j]) {
					return BROTLI_L2_ERR_FORMAT;
				}
			}
		}
		if (nsym == 4u) {
			r = br_read(b, 1, &tree_sel);
			if (r < 0) {
				return r;
			}
		}
		if (nsym == 1u) {
			len[syms[0]] = 0xFFu;
			return BROTLI_L2_OK;
		}
		if (nsym == 2u) {
			ls[0] = 1;
			ls[1] = 1;
		} else if (nsym == 3u) {
			ls[0] = 1;
			ls[1] = 2;
			ls[2] = 2;
		} else if (tree_sel == 0u) {
			ls[0] = 2;
			ls[1] = 2;
			ls[2] = 2;
			ls[3] = 2;
		} else {
			ls[0] = 1;
			ls[1] = 2;
			ls[2] = 3;
			ls[3] = 3;
		}
		for (i = 0; i < nsym; i++) {
			len[syms[i]] = ls[i];
		}
		return BROTLI_L2_OK;
	}
	{
		uint8_t cl_len[18];
		huff_t hcl;
		uint32_t space = 32;
		uint32_t num_codes = 0;
		uint32_t prev = 8;
		uint32_t repeat = 0;
		uint32_t repeat_len = 0xFFFFFFFFu;
		uint32_t si;
		memset(cl_len, 0, sizeof(cl_len));
		memset(&hcl, 0, sizeof(hcl));
		for (i = (unsigned)kind; i < 18u; i++) {
			uint32_t ix;
			uint32_t v;
			unsigned drop;
			r = br_peek(b, 4, &ix);
			if (r < 0) {
				return r;
			}
			drop = k_cl_pfx_len[ix];
			if ((unsigned)b->bits < drop) {
				return BROTLI_L2_ERR_TRUNC;
			}
			v = k_cl_pfx_val[ix];
			br_drop(b, drop);
			cl_len[k_cl_order[i]] = (uint8_t)v;
			if (v != 0) {
				space -= 32u >> v;
				num_codes++;
				if (space == 0u || space > 32u) {
					break;
				}
			}
		}
		if (!(num_codes == 1u || space == 0u)) {
			return BROTLI_L2_ERR_FORMAT;
		}
		if (num_codes == 1u) {
			uint32_t only = 0;
			for (i = 0; i < 18u; i++) {
				if (cl_len[i] != 0) {
					only = i;
					break;
				}
			}
			hcl.single = 1;
			hcl.single_sym = (uint16_t)only;
		} else {
			r = huff_build(&hcl, cl_len, 18);
			if (r < 0) {
				return r;
			}
		}
		space = 32768;
		si = 0;
		while (si < alph && space > 0u) {
			uint32_t code;
			r = huff_decode(b, &hcl, &code);
			if (r < 0) {
				return r;
			}
			if (code < 16u) {
				len[si] = (uint8_t)code;
				repeat = 0;
				if (code != 0) {
					prev = code;
					space -= 32768u >> code;
				}
				si++;
			} else {
				uint32_t extra_n;
				uint32_t extra;
				uint32_t new_len;
				uint32_t reps;
				uint32_t old_rep;
				if (code == 16u) {
					extra_n = 2;
					new_len = prev;
				} else if (code == 17u) {
					extra_n = 3;
					new_len = 0;
				} else {
					return BROTLI_L2_ERR_FORMAT;
				}
				r = br_read(b, extra_n, &extra);
				if (r < 0) {
					return r;
				}
				if (repeat_len != new_len) {
					repeat = 0;
					repeat_len = new_len;
				}
				old_rep = repeat;
				if (repeat > 0u) {
					repeat -= 2u;
					repeat <<= extra_n;
				}
				repeat += extra + 3u;
				reps = repeat - old_rep;
				if (si + reps > alph) {
					return BROTLI_L2_ERR_FORMAT;
				}
				if (new_len != 0) {
					uint32_t k;
					for (k = 0; k < reps; k++) {
						len[si++] = (uint8_t)new_len;
					}
					space -= reps << (15u - new_len);
				} else {
					si += reps;
				}
			}
		}
		if (space != 0u) {
			return BROTLI_L2_ERR_FORMAT;
		}
	}
	return BROTLI_L2_OK;
}

static int lengths_to_huff(const uint8_t *len, uint32_t alph, huff_t *h)
{
	return huff_build(h, len, alph);
}

static int read_huff(br_t *b, uint32_t alph, huff_t *h)
{
	uint8_t len[L2_MAX_ALPH];
	int r = read_huffman_lengths(b, alph, len);
	if (r < 0) {
		return r;
	}
	return lengths_to_huff(len, alph, h);
}

static int decode_varlen_u8(br_t *b, uint32_t *v)
{
	uint32_t bit;
	uint32_t n;
	int r = br_read(b, 1, &bit);
	if (r < 0) {
		return r;
	}
	if (bit == 0) {
		*v = 0;
		return BROTLI_L2_OK;
	}
	r = br_read(b, 3, &n);
	if (r < 0) {
		return r;
	}
	if (n == 0) {
		*v = 1;
		return BROTLI_L2_OK;
	}
	r = br_read(b, n, v);
	if (r < 0) {
		return r;
	}
	*v += (1u << n);
	return BROTLI_L2_OK;
}

static int decode_window_bits(br_t *b, uint32_t *wbits)
{
	uint32_t n;
	int r = br_read(b, 1, &n);
	if (r < 0) {
		return r;
	}
	if (n == 0) {
		*wbits = 16;
		return BROTLI_L2_OK;
	}
	r = br_read(b, 3, &n);
	if (r < 0) {
		return r;
	}
	if (n != 0) {
		*wbits = 17u + n;
		return BROTLI_L2_OK;
	}
	r = br_read(b, 3, &n);
	if (r < 0) {
		return r;
	}
	if (n == 1u) {
		return BROTLI_L2_ERR_WINDOW;
	}
	if (n != 0) {
		*wbits = 8u + n;
		return BROTLI_L2_OK;
	}
	*wbits = 17;
	return BROTLI_L2_OK;
}

static int read_block_count(br_t *b, const huff_t *h, uint32_t *count)
{
	uint32_t code;
	uint32_t extra;
	int r = huff_decode(b, h, &code);
	if (r < 0) {
		return r;
	}
	if (code > 25u) {
		return BROTLI_L2_ERR_FORMAT;
	}
	r = br_read(b, k_blk_nbits[code], &extra);
	if (r < 0) {
		return r;
	}
	*count = k_blk_base[code] + extra;
	return BROTLI_L2_OK;
}

static void imtf(uint8_t *v, uint32_t n)
{
	uint8_t mtf[256];
	uint32_t i;
	uint32_t j;
	for (i = 0; i < 256; i++) {
		mtf[i] = (uint8_t)i;
	}
	for (i = 0; i < n; i++) {
		uint8_t idx = v[i];
		uint8_t val = mtf[idx];
		v[i] = val;
		for (j = idx; j > 0; j--) {
			mtf[j] = mtf[j - 1];
		}
		mtf[0] = val;
	}
}

static int decode_context_map(br_t *b, uint32_t map_size, uint32_t *ntrees,
    uint8_t *map)
{
	uint32_t n;
	uint32_t rlemax = 0;
	uint32_t bit;
	huff_t h;
	uint32_t idx;
	int r;
	r = decode_varlen_u8(b, &n);
	if (r < 0) {
		return r;
	}
	*ntrees = n + 1u;
	if (*ntrees > 256u) {
		return BROTLI_L2_ERR_FORMAT;
	}
	memset(map, 0, map_size);
	if (*ntrees <= 1u) {
		return BROTLI_L2_OK;
	}
	r = br_read(b, 1, &bit);
	if (r < 0) {
		return r;
	}
	if (bit != 0) {
		r = br_read(b, 4, &rlemax);
		if (r < 0) {
			return r;
		}
		rlemax += 1u;
	}
	r = read_huff(b, *ntrees + rlemax, &h);
	if (r < 0) {
		return r;
	}
	idx = 0;
	while (idx < map_size) {
		uint32_t code;
		r = huff_decode(b, &h, &code);
		if (r < 0) {
			return r;
		}
		if (code == 0) {
			map[idx++] = 0;
			continue;
		}
		if (code > rlemax) {
			map[idx++] = (uint8_t)(code - rlemax);
			continue;
		}
		{
			uint32_t extra;
			uint32_t reps;
			r = br_read(b, code, &extra);
			if (r < 0) {
				return r;
			}
			reps = (1u << code) + extra;
			if (idx + reps > map_size) {
				return BROTLI_L2_ERR_FORMAT;
			}
			while (reps > 0u) {
				map[idx++] = 0;
				reps--;
			}
		}
	}
	r = br_read(b, 1, &bit);
	if (r < 0) {
		return r;
	}
	if (bit != 0) {
		imtf(map, map_size);
	}
	return BROTLI_L2_OK;
}

static int emit_byte(dec_t *d, uint8_t v)
{
	if (d->pos >= d->cap) {
		return BROTLI_L2_ERR_CAPACITY;
	}
	d->out[d->pos++] = v;
	d->p2 = d->p1;
	d->p1 = v;
	return BROTLI_L2_OK;
}

static int emit_copy(dec_t *d, uint32_t dist, uint32_t len)
{
	uint32_t i;
	size_t max_back;
	if (len == 0) {
		return BROTLI_L2_OK;
	}
	if (d->pos > d->cap || (size_t)len > d->cap - d->pos) {
		return BROTLI_L2_ERR_CAPACITY;
	}
	if (dist == 0) {
		return BROTLI_L2_ERR_FORMAT;
	}
	max_back = d->pos;
	if (max_back > d->wsize) {
		max_back = d->wsize;
	}
	if ((size_t)dist > d->pos || (size_t)dist > d->wsize) {
		return BROTLI_L2_ERR_DICT;
	}
	if (dist > L2_WIN) {
		return BROTLI_L2_ERR_WINDOW;
	}
	(void)max_back;
	for (i = 0; i < len; i++) {
		uint8_t v = d->out[d->pos - dist];
		int r = emit_byte(d, v);
		if (r < 0) {
			return r;
		}
	}
	return BROTLI_L2_OK;
}

static int copy_raw(dec_t *d, uint32_t mlen)
{
	br_t *b = &d->br;
	br_align(b);
	while (mlen > 0u && b->bits >= 8) {
		int r = emit_byte(d, (uint8_t)(b->acc & 0xffu));
		if (r < 0) {
			return r;
		}
		b->acc >>= 8;
		b->bits -= 8;
		mlen--;
	}
	if ((size_t)mlen > (size_t)(b->end - b->p)) {
		return BROTLI_L2_ERR_TRUNC;
	}
	if (d->pos > d->cap || (size_t)mlen > d->cap - d->pos) {
		return BROTLI_L2_ERR_CAPACITY;
	}
	while (mlen > 0u) {
		int r = emit_byte(d, *b->p++);
		if (r < 0) {
			return r;
		}
		mlen--;
	}
	return BROTLI_L2_OK;
}

static int skip_meta(dec_t *d, uint32_t mlen)
{
	br_t *b = &d->br;
	br_align(b);
	while (mlen > 0u && b->bits >= 8) {
		b->acc >>= 8;
		b->bits -= 8;
		mlen--;
	}
	if ((size_t)mlen > (size_t)(b->end - b->p)) {
		return BROTLI_L2_ERR_TRUNC;
	}
	b->p += mlen;
	return BROTLI_L2_OK;
}

static void iac_split(uint32_t code, uint32_t *ins_c, uint32_t *cpy_c, int *imp)
{
	uint32_t ins_off;
	uint32_t cpy_off;
	*imp = 0;
	if (code < 128u) {
		*imp = 1;
		ins_off = 0;
		cpy_off = (code < 64u) ? 0u : 8u;
	} else if (code < 192u) {
		ins_off = 0;
		cpy_off = 0;
	} else if (code < 256u) {
		ins_off = 0;
		cpy_off = 8;
	} else if (code < 320u) {
		ins_off = 8;
		cpy_off = 0;
	} else if (code < 384u) {
		ins_off = 8;
		cpy_off = 8;
	} else if (code < 448u) {
		ins_off = 0;
		cpy_off = 16;
	} else if (code < 512u) {
		ins_off = 16;
		cpy_off = 0;
	} else if (code < 576u) {
		ins_off = 8;
		cpy_off = 16;
	} else if (code < 640u) {
		ins_off = 16;
		cpy_off = 8;
	} else {
		ins_off = 16;
		cpy_off = 16;
	}
	*cpy_c = cpy_off + (code & 7u);
	*ins_c = ins_off + ((code >> 3) & 7u);
}

static int resolve_distance(dec_t *d, uint32_t dcode, uint32_t extra,
    uint32_t *dist, int *push)
{
	int64_t nd;
	*push = 1;
	if (dcode < 16u) {
		uint32_t which = k_short_which[dcode];
		int8_t delta = k_short_delta[dcode];
		nd = (int64_t)d->dist_rb[which] + (int64_t)delta;
		if (nd <= 0) {
			return BROTLI_L2_ERR_FORMAT;
		}
		*dist = (uint32_t)nd;
		if (dcode == 0u) {
			*push = 0;
		}
		return BROTLI_L2_OK;
	}
	if (dcode < 16u + d->ndirect) {
		*dist = dcode - 15u;
		return BROTLI_L2_OK;
	}
	{
		uint32_t npost = d->npostfix;
		uint32_t mask = (1u << npost) - 1u;
		uint32_t ndirect = d->ndirect;
		uint32_t hcode;
		uint32_t lcode;
		uint32_t ndistbits;
		uint32_t offset;
		dcode -= ndirect + 16u;
		ndistbits = 1u + (dcode >> (npost + 1u));
		if (ndistbits > 24u) {
			return BROTLI_L2_ERR_FORMAT;
		}
		hcode = dcode >> npost;
		lcode = dcode & mask;
		offset = ((2u + (hcode & 1u)) << ndistbits) - 4u;
		*dist = ((offset + extra) << npost) + lcode + ndirect + 1u;
		return BROTLI_L2_OK;
	}
}

static int load_lit(dec_t *d, uint32_t tree)
{
	if (d->lit_id == (int)tree) {
		return BROTLI_L2_OK;
	}
	if (tree >= d->ntrees_l) {
		return BROTLI_L2_ERR_FORMAT;
	}
	{
		int r = lengths_to_huff(g_lit_cl[tree], 256, &d->h_lit);
		if (r < 0) {
			return r;
		}
	}
	d->lit_id = (int)tree;
	return BROTLI_L2_OK;
}

static int load_cmd(dec_t *d, uint32_t tree)
{
	if (d->cmd_id == (int)tree) {
		return BROTLI_L2_OK;
	}
	if (tree >= d->nbl[1]) {
		return BROTLI_L2_ERR_FORMAT;
	}
	{
		int r = lengths_to_huff(g_cmd_cl[tree], 704, &d->h_cmd);
		if (r < 0) {
			return r;
		}
	}
	d->cmd_id = (int)tree;
	return BROTLI_L2_OK;
}

static int load_dist(dec_t *d, uint32_t tree)
{
	if (d->dist_id == (int)tree) {
		return BROTLI_L2_OK;
	}
	if (tree >= d->ntrees_d) {
		return BROTLI_L2_ERR_FORMAT;
	}
	{
		int r = lengths_to_huff(g_dist_cl[tree], d->dist_alph, &d->h_dist);
		if (r < 0) {
			return r;
		}
	}
	d->dist_id = (int)tree;
	return BROTLI_L2_OK;
}

static int switch_block(dec_t *d, int cat)
{
	uint32_t code;
	uint32_t btype;
	int r;
	r = huff_decode(&d->br, &d->h_bt[cat], &code);
	if (r < 0) {
		return r;
	}
	r = read_block_count(&d->br, &d->h_bl[cat], &d->blen[cat]);
	if (r < 0) {
		return r;
	}
	if (code == 1u) {
		btype = d->btype[cat] + 1u;
	} else if (code == 0u) {
		btype = d->btype_prev[cat];
	} else {
		btype = code - 2u;
	}
	if (btype >= d->nbl[cat]) {
		btype -= d->nbl[cat];
	}
	d->btype_prev[cat] = d->btype[cat];
	d->btype[cat] = btype;
	return BROTLI_L2_OK;
}

static int prepare_cat(dec_t *d, int cat)
{
	if (d->nbl[cat] > 1u && d->blen[cat] == 0u) {
		int r = switch_block(d, cat);
		if (r < 0) {
			return r;
		}
	}
	return BROTLI_L2_OK;
}

static void consume_cat(dec_t *d, int cat)
{
	if (d->nbl[cat] > 1u && d->blen[cat] > 0u) {
		d->blen[cat]--;
	}
}

static uint32_t lit_context(dec_t *d)
{
	uint32_t mode = g_ctx_mode[d->btype[0]] & 3u;
	const uint8_t *lut = g_ctx + (mode << 9);
	return (uint32_t)(lut[d->p1] | lut[256 + d->p2]);
}

static uint32_t dist_context(uint32_t copy_len)
{
	if (copy_len == 2u) {
		return 0;
	}
	if (copy_len == 3u) {
		return 1;
	}
	if (copy_len == 4u) {
		return 2;
	}
	return 3;
}

static int process_compressed(dec_t *d, uint32_t mlen)
{
	uint32_t remain = mlen;
	int r;
	r = load_cmd(d, d->btype[1]);
	if (r < 0) {
		return r;
	}
	while (remain > 0u) {
		uint32_t icode;
		uint32_t ins_c;
		uint32_t cpy_c;
		int imp;
		uint32_t ins;
		uint32_t cpy;
		uint32_t extra;
		uint32_t i;
		r = prepare_cat(d, 1);
		if (r < 0) {
			return r;
		}
		r = load_cmd(d, d->btype[1]);
		if (r < 0) {
			return r;
		}
		r = huff_decode(&d->br, &d->h_cmd, &icode);
		if (r < 0) {
			return r;
		}
		consume_cat(d, 1);
		if (icode > 703u) {
			return BROTLI_L2_ERR_FORMAT;
		}
		iac_split(icode, &ins_c, &cpy_c, &imp);
		if (ins_c > 23u || cpy_c > 23u) {
			return BROTLI_L2_ERR_FORMAT;
		}
		r = br_read(&d->br, k_ins_nbits[ins_c], &extra);
		if (r < 0) {
			return r;
		}
		ins = k_ins_base[ins_c] + extra;
		r = br_read(&d->br, k_cpy_nbits[cpy_c], &extra);
		if (r < 0) {
			return r;
		}
		cpy = k_cpy_base[cpy_c] + extra;
		if (ins > remain) {
			return BROTLI_L2_ERR_FORMAT;
		}
		for (i = 0; i < ins; i++) {
			uint32_t ctx;
			uint32_t tree;
			uint32_t lit;
			r = prepare_cat(d, 0);
			if (r < 0) {
				return r;
			}
			ctx = lit_context(d);
			tree = g_lit_map[(d->btype[0] << 6) + ctx];
			r = load_lit(d, tree);
			if (r < 0) {
				return r;
			}
			r = huff_decode(&d->br, &d->h_lit, &lit);
			if (r < 0) {
				return r;
			}
			if (lit > 255u) {
				return BROTLI_L2_ERR_FORMAT;
			}
			r = emit_byte(d, (uint8_t)lit);
			if (r < 0) {
				return r;
			}
			consume_cat(d, 0);
			remain--;
		}
		if (remain == 0u) {
			break;
		}
		if (cpy > remain) {
			return BROTLI_L2_ERR_FORMAT;
		}
		{
			uint32_t dist;
			int push = 1;
			if (!imp) {
				uint32_t dcode;
				uint32_t dextra = 0;
				uint32_t dctx;
				uint32_t tree;
				r = prepare_cat(d, 2);
				if (r < 0) {
					return r;
				}
				dctx = dist_context(cpy);
				tree = g_dist_map[(d->btype[2] << 2) + dctx];
				r = load_dist(d, tree);
				if (r < 0) {
					return r;
				}
				r = huff_decode(&d->br, &d->h_dist, &dcode);
				if (r < 0) {
					return r;
				}
				if (dcode >= d->dist_alph) {
					return BROTLI_L2_ERR_FORMAT;
				}
				if (dcode >= 16u + d->ndirect) {
					uint32_t ndistbits = 1u +
					    ((dcode - d->ndirect - 16u) >>
					    (d->npostfix + 1u));
					if (ndistbits > 24u) {
						return BROTLI_L2_ERR_FORMAT;
					}
					r = br_read(&d->br, ndistbits, &dextra);
					if (r < 0) {
						return r;
					}
				}
				r = resolve_distance(d, dcode, dextra, &dist, &push);
				if (r < 0) {
					return r;
				}
				consume_cat(d, 2);
			} else {
				dist = d->dist_rb[0];
				push = 0;
			}
			r = emit_copy(d, dist, cpy);
			if (r < 0) {
				return r;
			}
			if (push) {
				d->dist_rb[3] = d->dist_rb[2];
				d->dist_rb[2] = d->dist_rb[1];
				d->dist_rb[1] = d->dist_rb[0];
				d->dist_rb[0] = dist;
			}
			remain -= cpy;
		}
	}
	return BROTLI_L2_OK;
}

static int read_block_types(dec_t *d, int cat)
{
	int r;
	uint32_t n;
	r = decode_varlen_u8(&d->br, &n);
	if (r < 0) {
		return r;
	}
	d->nbl[cat] = n + 1u;
	if (d->nbl[cat] > 256u) {
		return BROTLI_L2_ERR_FORMAT;
	}
	d->btype[cat] = 0;
	d->btype_prev[cat] = 1;
	d->blen[cat] = 1u << 24;
	if (d->nbl[cat] >= 2u) {
		r = read_huff(&d->br, d->nbl[cat] + 2u, &d->h_bt[cat]);
		if (r < 0) {
			return r;
		}
		r = read_huff(&d->br, 26, &d->h_bl[cat]);
		if (r < 0) {
			return r;
		}
		r = read_block_count(&d->br, &d->h_bl[cat], &d->blen[cat]);
		if (r < 0) {
			return r;
		}
	}
	return BROTLI_L2_OK;
}

static int decode_metablock_header(dec_t *d, uint32_t *mlen, int *is_last,
    int *is_uncomp, int *is_meta)
{
	uint32_t bit;
	uint32_t nib;
	uint32_t i;
	int r;
	*is_uncomp = 0;
	*is_meta = 0;
	*mlen = 0;
	r = br_read(&d->br, 1, &bit);
	if (r < 0) {
		return r;
	}
	*is_last = bit ? 1 : 0;
	if (*is_last) {
		r = br_read(&d->br, 1, &bit);
		if (r < 0) {
			return r;
		}
		if (bit) {
			*mlen = 0;
			return BROTLI_L2_OK;
		}
	}
	r = br_read(&d->br, 2, &nib);
	if (r < 0) {
		return r;
	}
	if (nib == 3u) {
		uint32_t skipb;
		uint32_t skip = 0;
		*is_meta = 1;
		r = br_read(&d->br, 1, &bit);
		if (r < 0) {
			return r;
		}
		if (bit != 0) {
			return BROTLI_L2_ERR_FORMAT;
		}
		r = br_read(&d->br, 2, &skipb);
		if (r < 0) {
			return r;
		}
		for (i = 0; i < skipb; i++) {
			uint32_t b;
			r = br_read(&d->br, 8, &b);
			if (r < 0) {
				return r;
			}
			if (i + 1u == skipb && skipb > 1u && b == 0) {
				return BROTLI_L2_ERR_FORMAT;
			}
			skip |= b << (8u * i);
		}
		if (skipb != 0) {
			skip += 1u;
		}
		*mlen = skip;
		return BROTLI_L2_OK;
	}
	{
		uint32_t nn = nib + 4u;
		uint32_t m = 0;
		for (i = 0; i < nn; i++) {
			uint32_t n4;
			r = br_read(&d->br, 4, &n4);
			if (r < 0) {
				return r;
			}
			if (i + 1u == nn && nn > 4u && n4 == 0) {
				return BROTLI_L2_ERR_FORMAT;
			}
			m |= n4 << (4u * i);
		}
		*mlen = m + 1u;
	}
	if (!*is_last) {
		r = br_read(&d->br, 1, &bit);
		if (r < 0) {
			return r;
		}
		*is_uncomp = bit ? 1 : 0;
	}
	return BROTLI_L2_OK;
}

static int decode_compressed_header(dec_t *d)
{
	uint32_t i;
	uint32_t npost;
	uint32_t ndir;
	int r;
	uint8_t len[L2_MAX_ALPH];
	r = read_block_types(d, 0);
	if (r < 0) {
		return r;
	}
	r = read_block_types(d, 1);
	if (r < 0) {
		return r;
	}
	r = read_block_types(d, 2);
	if (r < 0) {
		return r;
	}
	r = br_read(&d->br, 2, &npost);
	if (r < 0) {
		return r;
	}
	d->npostfix = npost;
	r = br_read(&d->br, 4, &ndir);
	if (r < 0) {
		return r;
	}
	d->ndirect = ndir << npost;
	if (d->ndirect > 120u) {
		return BROTLI_L2_ERR_FORMAT;
	}
	d->dist_alph = 16u + d->ndirect + (48u << d->npostfix);
	if (d->dist_alph > 520u) {
		return BROTLI_L2_ERR_FORMAT;
	}
	for (i = 0; i < d->nbl[0]; i++) {
		uint32_t mode;
		r = br_read(&d->br, 2, &mode);
		if (r < 0) {
			return r;
		}
		g_ctx_mode[i] = (uint8_t)mode;
	}
	r = decode_context_map(&d->br, d->nbl[0] * 64u, &d->ntrees_l, g_lit_map);
	if (r < 0) {
		return r;
	}
	r = decode_context_map(&d->br, d->nbl[2] * 4u, &d->ntrees_d, g_dist_map);
	if (r < 0) {
		return r;
	}
	for (i = 0; i < d->ntrees_l; i++) {
		r = read_huffman_lengths(&d->br, 256, len);
		if (r < 0) {
			return r;
		}
		memcpy(g_lit_cl[i], len, 256);
	}
	for (i = 0; i < d->nbl[1]; i++) {
		r = read_huffman_lengths(&d->br, 704, len);
		if (r < 0) {
			return r;
		}
		memcpy(g_cmd_cl[i], len, 704);
	}
	for (i = 0; i < d->ntrees_d; i++) {
		r = read_huffman_lengths(&d->br, d->dist_alph, len);
		if (r < 0) {
			return r;
		}
		memcpy(g_dist_cl[i], len, d->dist_alph);
	}
	d->lit_id = -1;
	d->cmd_id = -1;
	d->dist_id = -1;
	return BROTLI_L2_OK;
}

int brotli_l2_decompress(const uint8_t *in, size_t in_len, uint8_t *out,
    size_t out_capacity, size_t *out_len)
{
	dec_t d;
	uint32_t wbits;
	int r;
	ctx_init();
	if (out_len == NULL) {
		return BROTLI_L2_ERR_ARG;
	}
	*out_len = 0;
	if (in_len > 0 && in == NULL) {
		return BROTLI_L2_ERR_ARG;
	}
	if (out_capacity > 0 && out == NULL) {
		return BROTLI_L2_ERR_ARG;
	}
	memset(&d, 0, sizeof(d));
	d.br.p = in;
	d.br.end = in + in_len;
	d.out = out;
	d.cap = out_capacity;
	d.dist_rb[0] = 4;
	d.dist_rb[1] = 11;
	d.dist_rb[2] = 15;
	d.dist_rb[3] = 16;
	d.p1 = 0;
	d.p2 = 0;
	d.lit_id = -1;
	d.cmd_id = -1;
	d.dist_id = -1;
	r = decode_window_bits(&d.br, &wbits);
	if (r < 0) {
		return r;
	}
	if (wbits < 10u || wbits > 24u) {
		return BROTLI_L2_ERR_WINDOW;
	}
	d.wsize = (1u << wbits) - 16u;
	for (;;) {
		uint32_t mlen;
		int is_last;
		int is_uncomp;
		int is_meta;
		r = decode_metablock_header(&d, &mlen, &is_last, &is_uncomp, &is_meta);
		if (r < 0) {
			return r;
		}
		if (is_last && mlen == 0 && !is_meta && !is_uncomp) {
			break;
		}
		if (is_meta) {
			r = skip_meta(&d, mlen);
			if (r < 0) {
				return r;
			}
			if (is_last) {
				break;
			}
			continue;
		}
		if (mlen > 0u) {
			if (d.pos > d.cap || (size_t)mlen > d.cap - d.pos) {
				return BROTLI_L2_ERR_CAPACITY;
			}
		}
		if (is_uncomp) {
			if (is_last) {
				return BROTLI_L2_ERR_FORMAT;
			}
			r = copy_raw(&d, mlen);
			if (r < 0) {
				return r;
			}
			if (is_last) {
				break;
			}
			continue;
		}
		if (mlen == 0) {
			if (is_last) {
				break;
			}
			continue;
		}
		r = decode_compressed_header(&d);
		if (r < 0) {
			return r;
		}
		r = process_compressed(&d, mlen);
		if (r < 0) {
			return r;
		}
		if (is_last) {
			break;
		}
	}
	*out_len = d.pos;
	return BROTLI_L2_OK;
}
