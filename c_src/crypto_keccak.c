// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. Licensed under the Business Source License 1.1;
// see ../LICENSE and ../NOTICE.

#include "crypto_keccak.h"

#include <string.h>

static const uint64_t keccak_rc[24] = {
	0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL,
	0x8000000080008000ULL, 0x000000000000808BULL, 0x0000000080000001ULL,
	0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008AULL,
	0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
	0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL,
	0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
	0x000000000000800AULL, 0x800000008000000AULL, 0x8000000080008081ULL,
	0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

#define ROL64(x, n) (((x) << (n)) | ((x) >> (64U - (n))))

#define KECCAK_ROUND(Aba, Abe, Abi, Abo, Abu, \
	Aga, Age, Agi, Ago, Agu, \
	Aka, Ake, Aki, Ako, Aku, \
	Ama, Ame, Ami, Amo, Amu, \
	Asa, Ase, Asi, Aso, Asu, \
	Eba, Ebe, Ebi, Ebo, Ebu, \
	Ega, Ege, Egi, Ego, Egu, \
	Eka, Eke, Eki, Eko, Eku, \
	Ema, Eme, Emi, Emo, Emu, \
	Esa, Ese, Esi, Eso, Esu, \
	rcval) \
do { \
	uint64_t bca = (Aba) ^ (Aga) ^ (Aka) ^ (Ama) ^ (Asa); \
	uint64_t bce = (Abe) ^ (Age) ^ (Ake) ^ (Ame) ^ (Ase); \
	uint64_t bci = (Abi) ^ (Agi) ^ (Aki) ^ (Ami) ^ (Asi); \
	uint64_t bco = (Abo) ^ (Ago) ^ (Ako) ^ (Amo) ^ (Aso); \
	uint64_t bcu = (Abu) ^ (Agu) ^ (Aku) ^ (Amu) ^ (Asu); \
	uint64_t da = bcu ^ ROL64(bce, 1U); \
	uint64_t de = bca ^ ROL64(bci, 1U); \
	uint64_t di = bce ^ ROL64(bco, 1U); \
	uint64_t do_ = bci ^ ROL64(bcu, 1U); \
	uint64_t du = bco ^ ROL64(bca, 1U); \
	(Aba) ^= da; \
	bca = (Aba); \
	(Age) ^= de; \
	bce = ROL64((Age), 44U); \
	(Aki) ^= di; \
	bci = ROL64((Aki), 43U); \
	(Amo) ^= do_; \
	bco = ROL64((Amo), 21U); \
	(Asu) ^= du; \
	bcu = ROL64((Asu), 14U); \
	(Eba) = bca ^ ((~bce) & bci) ^ (rcval); \
	(Ebe) = bce ^ ((~bci) & bco); \
	(Ebi) = bci ^ ((~bco) & bcu); \
	(Ebo) = bco ^ ((~bcu) & bca); \
	(Ebu) = bcu ^ ((~bca) & bce); \
	(Abo) ^= do_; \
	bca = ROL64((Abo), 28U); \
	(Agu) ^= du; \
	bce = ROL64((Agu), 20U); \
	(Aka) ^= da; \
	bci = ROL64((Aka), 3U); \
	(Ame) ^= de; \
	bco = ROL64((Ame), 45U); \
	(Asi) ^= di; \
	bcu = ROL64((Asi), 61U); \
	(Ega) = bca ^ ((~bce) & bci); \
	(Ege) = bce ^ ((~bci) & bco); \
	(Egi) = bci ^ ((~bco) & bcu); \
	(Ego) = bco ^ ((~bcu) & bca); \
	(Egu) = bcu ^ ((~bca) & bce); \
	(Abe) ^= de; \
	bca = ROL64((Abe), 1U); \
	(Agi) ^= di; \
	bce = ROL64((Agi), 6U); \
	(Ako) ^= do_; \
	bci = ROL64((Ako), 25U); \
	(Amu) ^= du; \
	bco = ROL64((Amu), 8U); \
	(Asa) ^= da; \
	bcu = ROL64((Asa), 18U); \
	(Eka) = bca ^ ((~bce) & bci); \
	(Eke) = bce ^ ((~bci) & bco); \
	(Eki) = bci ^ ((~bco) & bcu); \
	(Eko) = bco ^ ((~bcu) & bca); \
	(Eku) = bcu ^ ((~bca) & bce); \
	(Abu) ^= du; \
	bca = ROL64((Abu), 27U); \
	(Aga) ^= da; \
	bce = ROL64((Aga), 36U); \
	(Ake) ^= de; \
	bci = ROL64((Ake), 10U); \
	(Ami) ^= di; \
	bco = ROL64((Ami), 15U); \
	(Aso) ^= do_; \
	bcu = ROL64((Aso), 56U); \
	(Ema) = bca ^ ((~bce) & bci); \
	(Eme) = bce ^ ((~bci) & bco); \
	(Emi) = bci ^ ((~bco) & bcu); \
	(Emo) = bco ^ ((~bcu) & bca); \
	(Emu) = bcu ^ ((~bca) & bce); \
	(Abi) ^= di; \
	bca = ROL64((Abi), 62U); \
	(Ago) ^= do_; \
	bce = ROL64((Ago), 55U); \
	(Aku) ^= du; \
	bci = ROL64((Aku), 39U); \
	(Ama) ^= da; \
	bco = ROL64((Ama), 41U); \
	(Ase) ^= de; \
	bcu = ROL64((Ase), 2U); \
	(Esa) = bca ^ ((~bce) & bci); \
	(Ese) = bce ^ ((~bci) & bco); \
	(Esi) = bci ^ ((~bco) & bcu); \
	(Eso) = bco ^ ((~bcu) & bca); \
	(Esu) = bcu ^ ((~bca) & bce); \
} while (0)

void keccak_f1600(keccak_state_t *st)
{
	uint64_t aba = st->a[0], abe = st->a[1], abi = st->a[2], abo = st->a[3], abu = st->a[4];
	uint64_t aga = st->a[5], age = st->a[6], agi = st->a[7], ago = st->a[8], agu = st->a[9];
	uint64_t aka = st->a[10], ake = st->a[11], aki = st->a[12], ako = st->a[13], aku = st->a[14];
	uint64_t ama = st->a[15], ame = st->a[16], ami = st->a[17], amo = st->a[18], amu = st->a[19];
	uint64_t asa = st->a[20], ase = st->a[21], asi = st->a[22], aso = st->a[23], asu = st->a[24];
	uint64_t eba, ebe, ebi, ebo, ebu;
	uint64_t ega, ege, egi, ego, egu;
	uint64_t eka, eke, eki, eko, eku;
	uint64_t ema, eme, emi, emo, emu;
	uint64_t esa, ese, esi, eso, esu;
	int round;

	for (round = 0; round < 24; round += 2) {
		KECCAK_ROUND(aba, abe, abi, abo, abu,
		    aga, age, agi, ago, agu,
		    aka, ake, aki, ako, aku,
		    ama, ame, ami, amo, amu,
		    asa, ase, asi, aso, asu,
		    eba, ebe, ebi, ebo, ebu,
		    ega, ege, egi, ego, egu,
		    eka, eke, eki, eko, eku,
		    ema, eme, emi, emo, emu,
		    esa, ese, esi, eso, esu,
		    keccak_rc[round]);
		KECCAK_ROUND(eba, ebe, ebi, ebo, ebu,
		    ega, ege, egi, ego, egu,
		    eka, eke, eki, eko, eku,
		    ema, eme, emi, emo, emu,
		    esa, ese, esi, eso, esu,
		    aba, abe, abi, abo, abu,
		    aga, age, agi, ago, agu,
		    aka, ake, aki, ako, aku,
		    ama, ame, ami, amo, amu,
		    asa, ase, asi, aso, asu,
		    keccak_rc[round + 1]);
	}

	st->a[0] = aba; st->a[1] = abe; st->a[2] = abi; st->a[3] = abo; st->a[4] = abu;
	st->a[5] = aga; st->a[6] = age; st->a[7] = agi; st->a[8] = ago; st->a[9] = agu;
	st->a[10] = aka; st->a[11] = ake; st->a[12] = aki; st->a[13] = ako; st->a[14] = aku;
	st->a[15] = ama; st->a[16] = ame; st->a[17] = ami; st->a[18] = amo; st->a[19] = amu;
	st->a[20] = asa; st->a[21] = ase; st->a[22] = asi; st->a[23] = aso; st->a[24] = asu;
}

static void xor_bytes(uint64_t *st, const uint8_t *in, size_t n)
{
	size_t i = 0;
	size_t j;

	while (n >= 8U) {
		st[i] ^= (uint64_t)in[0]
		    | ((uint64_t)in[1] << 8)
		    | ((uint64_t)in[2] << 16)
		    | ((uint64_t)in[3] << 24)
		    | ((uint64_t)in[4] << 32)
		    | ((uint64_t)in[5] << 40)
		    | ((uint64_t)in[6] << 48)
		    | ((uint64_t)in[7] << 56);
		in += 8;
		n -= 8U;
		i++;
	}
	for (j = 0; j < n; j++) {
		st[i] ^= ((uint64_t)in[j]) << (j * 8U);
	}
}

static void extract_bytes(const uint64_t *st, uint8_t *out, size_t n)
{
	size_t i = 0;
	size_t j;

	while (n >= 8U) {
		uint64_t v = st[i];
		out[0] = (uint8_t)v;
		out[1] = (uint8_t)(v >> 8);
		out[2] = (uint8_t)(v >> 16);
		out[3] = (uint8_t)(v >> 24);
		out[4] = (uint8_t)(v >> 32);
		out[5] = (uint8_t)(v >> 40);
		out[6] = (uint8_t)(v >> 48);
		out[7] = (uint8_t)(v >> 56);
		out += 8;
		n -= 8U;
		i++;
	}
	for (j = 0; j < n; j++) {
		out[j] = (uint8_t)(st[i] >> (j * 8U));
	}
}

static void keccak_sponge(const uint8_t *in, size_t in_len, uint8_t *out,
    size_t out_len, size_t rate)
{
	keccak_state_t st;
	const uint8_t *p = in;

	memset(&st, 0, sizeof(st));

	while (in_len >= rate) {
		xor_bytes(st.a, p, rate);
		keccak_f1600(&st);
		p += rate;
		in_len -= rate;
	}

	xor_bytes(st.a, p, in_len);
	st.a[in_len >> 3] ^= (uint64_t)0x01U << ((in_len & 7U) * 8U);
	st.a[(rate - 1U) >> 3] ^= (uint64_t)0x80U << (((rate - 1U) & 7U) * 8U);
	keccak_f1600(&st);

	while (out_len >= rate) {
		extract_bytes(st.a, out, rate);
		keccak_f1600(&st);
		out += rate;
		out_len -= rate;
	}
	extract_bytes(st.a, out, out_len);
}

void keccak256(const uint8_t *in, size_t in_len, uint8_t out[32])
{
	keccak_sponge(in, in_len, out, 32, 136);
}

void keccak512(const uint8_t *in, size_t in_len, uint8_t out[64])
{
	keccak_sponge(in, in_len, out, 64, 72);
}
