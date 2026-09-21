#include "crypto_secp256k1.h"
#include "evm_arith256.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static const uint256_t SECP_P = {{
	0xfffffffefffffc2fULL,
	0xffffffffffffffffULL,
	0xffffffffffffffffULL,
	0xffffffffffffffffULL
}};

static const uint256_t SECP_N = {{
	0xbfd25e8cd0364141ULL,
	0xbaaedce6af48a03bULL,
	0xfffffffffffffffeULL,
	0xffffffffffffffffULL
}};

static const uint256_t SECP_NHALF = {{
	0xdfe92f46681b20a0ULL,
	0x5d576e7357a4501dULL,
	0xffffffffffffffffULL,
	0x7fffffffffffffffULL
}};

static const uint256_t SECP_GX = {{
	0x59f2815b16f81798ULL,
	0x029bfcdb2dce28d9ULL,
	0x55a06295ce870b07ULL,
	0x79be667ef9dcbbacULL
}};

static const uint256_t SECP_GY = {{
	0x9c47d08ffb10d4b8ULL,
	0xfd17b448a6855419ULL,
	0x5da4fbfc0e1108a8ULL,
	0x483ada7726a3c465ULL
}};

static const uint256_t SECP_B = {{ 7ULL, 0, 0, 0 }};
static const uint256_t SECP_ONE = {{ 1ULL, 0, 0, 0 }};
static const uint256_t SECP_ZERO = {{ 0, 0, 0, 0 }};

static const uint64_t SECP_P_MINUS_2[4] = {
	0xfffffffefffffc2dULL,
	0xffffffffffffffffULL,
	0xffffffffffffffffULL,
	0xffffffffffffffffULL
};

static const uint64_t SECP_SQRT_EXP[4] = {
	0xffffffffbfffff0cULL,
	0xffffffffffffffffULL,
	0xffffffffffffffffULL,
	0x3fffffffffffffffULL
};

static const uint64_t SECP_N_MINUS_2[4] = {
	0xbfd25e8cd036413fULL,
	0xbaaedce6af48a03bULL,
	0xfffffffffffffffeULL,
	0xffffffffffffffffULL
};

static void u256_cmov(uint256_t *rd, const uint256_t *src, uint64_t mask)
{
	int i;

	for (i = 0; i < 4; i++) {
		rd->w[i] = (rd->w[i] & ~mask) | (src->w[i] & mask);
	}
}

static uint64_t ct_zero_mask(uint64_t t)
{
	uint64_t v;

	v = (t | (0ULL - t)) >> 63;
	return 0ULL - (v ^ 1ULL);
}

static uint64_t u256_zero_mask(const uint256_t *a)
{
	return ct_zero_mask(a->w[0] | a->w[1] | a->w[2] | a->w[3]);
}

static uint64_t u256_eq_mask(const uint256_t *a, const uint256_t *b)
{
	return ct_zero_mask((a->w[0] ^ b->w[0]) | (a->w[1] ^ b->w[1])
	    | (a->w[2] ^ b->w[2]) | (a->w[3] ^ b->w[3]));
}

static int u256_is_zero(const uint256_t *a)
{
	return (a->w[0] | a->w[1] | a->w[2] | a->w[3]) == 0;
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

static void fe_add(const uint256_t *a, const uint256_t *b, uint256_t *out)
{
	evm_addmod256(a, b, &SECP_P, out);
}

static void fe_sub(const uint256_t *a, const uint256_t *b, uint256_t *out)
{
	uint256_t nb;

	evm_sub256(&SECP_P, b, &nb);
	evm_addmod256(a, &nb, &SECP_P, out);
}

static const uint64_t SECP_R = 0x1000003d1ULL;

static void fe_mul64(uint64_t a, uint64_t b, uint64_t *hi, uint64_t *lo)
{
	uint64_t a0 = a & 0xffffffffULL;
	uint64_t a1 = a >> 32;
	uint64_t b0 = b & 0xffffffffULL;
	uint64_t b1 = b >> 32;
	uint64_t p00 = a0 * b0;
	uint64_t p01 = a0 * b1;
	uint64_t p10 = a1 * b0;
	uint64_t p11 = a1 * b1;
	uint64_t mid = (p00 >> 32) + (p01 & 0xffffffffULL) + (p10 & 0xffffffffULL);

	*lo = (p00 & 0xffffffffULL) | (mid << 32);
	*hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
}

static uint64_t fe_addc(uint64_t a, uint64_t b, uint64_t cin, uint64_t *cout)
{
	uint64_t t = a + cin;
	uint64_t c1 = (uint64_t)(t < a);
	uint64_t r = t + b;
	uint64_t c2 = (uint64_t)(r < t);

	*cout = c1 | c2;
	return r;
}

static void fe_mul512(const uint256_t *a, const uint256_t *b, uint64_t p[8])
{
	int i;
	int j;

	for (i = 0; i < 8; i++) {
		p[i] = 0;
	}
	for (i = 0; i < 4; i++) {
		uint64_t carry = 0;

		for (j = 0; j < 4; j++) {
			uint64_t hi;
			uint64_t lo;
			uint64_t s;
			uint64_t h;

			fe_mul64(a->w[i], b->w[j], &hi, &lo);
			s = p[i + j] + lo;
			h = (uint64_t)(s < lo);
			{
				uint64_t s2 = s + carry;

				h += (uint64_t)(s2 < s);
				p[i + j] = s2;
			}
			carry = hi + h;
		}
		p[i + 4] = carry;
	}
}

static void fe_mul256_by_r(uint64_t h0, uint64_t h1, uint64_t h2, uint64_t h3,
    uint64_t *l0, uint64_t *l1, uint64_t *l2, uint64_t *l3, uint64_t *extra)
{
	uint64_t hi;
	uint64_t hi2;
	uint64_t lo;
	uint64_t c;

	fe_mul64(h0, SECP_R, &hi, l0);
	fe_mul64(h1, SECP_R, &hi2, &lo);
	*l1 = fe_addc(lo, hi, 0, &c);
	hi = hi2 + c;
	fe_mul64(h2, SECP_R, &hi2, &lo);
	*l2 = fe_addc(lo, hi, 0, &c);
	hi = hi2 + c;
	fe_mul64(h3, SECP_R, &hi2, &lo);
	*l3 = fe_addc(lo, hi, 0, &c);
	*extra = hi2 + c;
}

static void fe_reduce512(const uint64_t z[8], uint256_t *out)
{
	uint64_t l0 = z[0];
	uint64_t l1 = z[1];
	uint64_t l2 = z[2];
	uint64_t l3 = z[3];
	uint64_t m0;
	uint64_t m1;
	uint64_t m2;
	uint64_t m3;
	uint64_t extra;
	uint64_t c;
	uint64_t hi;
	uint64_t lo;
	uint64_t br;
	uint256_t res;
	uint256_t rp;
	int i;

	fe_mul256_by_r(z[4], z[5], z[6], z[7], &m0, &m1, &m2, &m3, &extra);
	l0 = fe_addc(l0, m0, 0, &c);
	l1 = fe_addc(l1, m1, c, &c);
	l2 = fe_addc(l2, m2, c, &c);
	l3 = fe_addc(l3, m3, c, &c);
	extra = extra + c;
	fe_mul64(extra, SECP_R, &hi, &lo);
	l0 = fe_addc(l0, lo, 0, &c);
	l1 = fe_addc(l1, hi, c, &c);
	l2 = fe_addc(l2, 0, c, &c);
	l3 = fe_addc(l3, 0, c, &c);
	fe_mul64(c, SECP_R, &hi, &lo);
	l0 = fe_addc(l0, lo, 0, &c);
	l1 = fe_addc(l1, hi, c, &c);
	l2 = fe_addc(l2, 0, c, &c);
	l3 = fe_addc(l3, 0, c, &c);
	res.w[0] = l0;
	res.w[1] = l1;
	res.w[2] = l2;
	res.w[3] = l3;
	evm_sub256(&res, &SECP_P, &rp);
	br = 0;
	for (i = 0; i < 4; i++) {
		uint64_t av = res.w[i];
		uint64_t t = av - br;
		uint64_t b1 = (uint64_t)(av < br);
		uint64_t rv = t - SECP_P.w[i];
		uint64_t b2 = (uint64_t)(t < SECP_P.w[i]);

		(void)rv;
		br = b1 | b2;
	}
	u256_cmov(&res, &rp, br - 1ULL);
	*out = res;
}

static void fe_mul(const uint256_t *a, const uint256_t *b, uint256_t *out)
{
	uint256_t aa = *a;
	uint256_t bb = *b;
	uint64_t p[8];

	fe_mul512(&aa, &bb, p);
	fe_reduce512(p, out);
}

static void fe_sqr(const uint256_t *a, uint256_t *out)
{
	fe_mul(a, a, out);
}

static void fe_dbl(const uint256_t *a, uint256_t *out)
{
	evm_addmod256(a, a, &SECP_P, out);
}

static void fe_neg(const uint256_t *a, uint256_t *out)
{
	uint256_t t;
	uint64_t z;

	evm_sub256(&SECP_P, a, &t);
	z = u256_zero_mask(a);
	*out = t;
	u256_cmov(out, &SECP_ZERO, z);
}

static void fe_pow(const uint256_t *base_in, const uint64_t e[4], uint256_t *out)
{
	uint256_t base;
	uint256_t result;
	uint256_t tmp;
	int i;

	base = *base_in;
	result = SECP_ONE;
	for (i = 0; i < 256; i++) {
		uint64_t bit = (e[i >> 6] >> (i & 63)) & 1ULL;
		uint64_t mask = 0ULL - bit;

		fe_mul(&result, &base, &tmp);
		u256_cmov(&result, &tmp, mask);
		fe_sqr(&base, &tmp);
		base = tmp;
	}
	*out = result;
}

void secp256k1_fe_inv(const uint256_t *a, uint256_t *out)
{
	fe_pow(a, SECP_P_MINUS_2, out);
}

static int fe_sqrt(const uint256_t *a, uint256_t *out)
{
	uint256_t y;
	uint256_t y2;

	fe_pow(a, SECP_SQRT_EXP, &y);
	fe_sqr(&y, &y2);
	if (u256_eq_mask(&y2, a) == 0) {
		return -1;
	}
	*out = y;
	return 0;
}

static void jac_cmov(secp256k1_jac_t *rd, const secp256k1_jac_t *src, uint64_t mask)
{
	u256_cmov(&rd->x, &src->x, mask);
	u256_cmov(&rd->y, &src->y, mask);
	u256_cmov(&rd->z, &src->z, mask);
}

static void jac_set_inf(secp256k1_jac_t *p)
{
	p->x = SECP_ZERO;
	p->y = SECP_ONE;
	p->z = SECP_ZERO;
}

static void jac_double_body(const secp256k1_jac_t *p, secp256k1_jac_t *out)
{
	uint256_t a;
	uint256_t b;
	uint256_t c;
	uint256_t d;
	uint256_t e;
	uint256_t f;
	uint256_t t1;
	uint256_t t2;
	uint256_t x3;
	uint256_t y3;
	uint256_t z3;

	fe_sqr(&p->x, &a);
	fe_sqr(&p->y, &b);
	fe_sqr(&b, &c);
	fe_add(&p->x, &b, &t1);
	fe_sqr(&t1, &t2);
	fe_sub(&t2, &a, &t1);
	fe_sub(&t1, &c, &t2);
	fe_dbl(&t2, &d);
	fe_dbl(&a, &t1);
	fe_add(&t1, &a, &e);
	fe_sqr(&e, &f);
	fe_dbl(&d, &t1);
	fe_sub(&f, &t1, &x3);
	fe_sub(&d, &x3, &t1);
	fe_mul(&e, &t1, &t2);
	fe_dbl(&c, &t1);
	fe_dbl(&t1, &t1);
	fe_dbl(&t1, &t1);
	fe_sub(&t2, &t1, &y3);
	fe_add(&p->y, &p->y, &t1);
	fe_mul(&t1, &p->z, &z3);
	out->x = x3;
	out->y = y3;
	out->z = z3;
}

void secp256k1_jac_double(const secp256k1_jac_t *p, secp256k1_jac_t *out)
{
	secp256k1_jac_t pp;
	secp256k1_jac_t inf;
	secp256k1_jac_t r;
	uint64_t zmask;

	pp = *p;
	jac_double_body(&pp, &r);
	jac_set_inf(&inf);
	zmask = u256_zero_mask(&pp.z);
	jac_cmov(&r, &inf, zmask);
	*out = r;
}

static void jac_add_body(const secp256k1_jac_t *p, const secp256k1_jac_t *q,
    secp256k1_jac_t *out, uint256_t *h_out, uint256_t *s1_out, uint256_t *s2_out)
{
	uint256_t z1z1;
	uint256_t z2z2;
	uint256_t u1;
	uint256_t u2;
	uint256_t s1;
	uint256_t s2;
	uint256_t h;
	uint256_t i;
	uint256_t j;
	uint256_t r;
	uint256_t v;
	uint256_t t1;
	uint256_t t2;
	uint256_t x3;
	uint256_t y3;
	uint256_t z3;

	fe_sqr(&p->z, &z1z1);
	fe_sqr(&q->z, &z2z2);
	fe_mul(&p->x, &z2z2, &u1);
	fe_mul(&q->x, &z1z1, &u2);
	fe_mul(&q->z, &z2z2, &t1);
	fe_mul(&p->y, &t1, &s1);
	fe_mul(&p->z, &z1z1, &t1);
	fe_mul(&q->y, &t1, &s2);
	fe_sub(&u2, &u1, &h);
	fe_dbl(&h, &t1);
	fe_sqr(&t1, &i);
	fe_mul(&h, &i, &j);
	fe_sub(&s2, &s1, &t1);
	fe_dbl(&t1, &r);
	fe_mul(&u1, &i, &v);
	fe_sqr(&r, &t1);
	fe_sub(&t1, &j, &t2);
	fe_dbl(&v, &t1);
	fe_sub(&t2, &t1, &x3);
	fe_sub(&v, &x3, &t1);
	fe_mul(&r, &t1, &t2);
	fe_mul(&s1, &j, &t1);
	fe_dbl(&t1, &t1);
	fe_sub(&t2, &t1, &y3);
	fe_add(&p->z, &q->z, &t1);
	fe_sqr(&t1, &t2);
	fe_sub(&t2, &z1z1, &t1);
	fe_sub(&t1, &z2z2, &t2);
	fe_mul(&t2, &h, &z3);
	out->x = x3;
	out->y = y3;
	out->z = z3;
	*h_out = h;
	*s1_out = s1;
	*s2_out = s2;
}

void secp256k1_jac_add(const secp256k1_jac_t *p, const secp256k1_jac_t *q,
    secp256k1_jac_t *out)
{
	secp256k1_jac_t pp;
	secp256k1_jac_t qq;
	secp256k1_jac_t sum;
	secp256k1_jac_t dbl;
	secp256k1_jac_t inf;
	secp256k1_jac_t r;
	uint256_t h;
	uint256_t s1;
	uint256_t s2;
	uint64_t z1m;
	uint64_t z2m;
	uint64_t hm;
	uint64_t sm;

	pp = *p;
	qq = *q;
	jac_add_body(&pp, &qq, &sum, &h, &s1, &s2);
	jac_double_body(&pp, &dbl);
	jac_set_inf(&inf);
	z1m = u256_zero_mask(&pp.z);
	z2m = u256_zero_mask(&qq.z);
	hm = u256_zero_mask(&h);
	sm = u256_eq_mask(&s1, &s2);
	r = sum;
	jac_cmov(&r, &dbl, hm & sm);
	jac_cmov(&r, &inf, hm & ~sm);
	jac_cmov(&r, &qq, z1m);
	jac_cmov(&r, &pp, z2m);
	*out = r;
}

void secp256k1_jac_mul(const secp256k1_jac_t *p, const uint256_t *k,
    secp256k1_jac_t *out)
{
	secp256k1_jac_t base;
	secp256k1_jac_t r;
	secp256k1_jac_t t;
	int i;

	base = *p;
	jac_set_inf(&r);
	for (i = 255; i >= 0; i--) {
		uint64_t bit = (k->w[i >> 6] >> (i & 63)) & 1ULL;
		uint64_t mask = 0ULL - bit;

		secp256k1_jac_double(&r, &r);
		secp256k1_jac_add(&r, &base, &t);
		jac_cmov(&r, &t, mask);
	}
	*out = r;
}

static void sc_mul(const uint256_t *a, const uint256_t *b, uint256_t *out)
{
	evm_mulmod256(a, b, &SECP_N, out);
}

static void sc_inv(const uint256_t *a, uint256_t *out)
{
	uint256_t base;
	uint256_t result;
	uint256_t tmp;
	int i;

	base = *a;
	result = SECP_ONE;
	for (i = 0; i < 256; i++) {
		uint64_t bit = (SECP_N_MINUS_2[i >> 6] >> (i & 63)) & 1ULL;
		uint64_t mask = 0ULL - bit;

		sc_mul(&result, &base, &tmp);
		u256_cmov(&result, &tmp, mask);
		sc_mul(&base, &base, &tmp);
		base = tmp;
	}
	*out = result;
}

static void b32_to_u256(const uint8_t b[32], uint256_t *out)
{
	int i;

	for (i = 0; i < 4; i++) {
		const uint8_t *p = b + (3 - i) * 8;

		out->w[i] = ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48)
		    | ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32)
		    | ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16)
		    | ((uint64_t)p[6] << 8) | (uint64_t)p[7];
	}
}

static void u256_to_b32(const uint256_t *x, uint8_t b[32])
{
	int i;

	for (i = 0; i < 4; i++) {
		uint64_t v = x->w[3 - i];
		int j;

		for (j = 0; j < 8; j++) {
			b[i * 8 + j] = (uint8_t)(v >> (56 - j * 8));
		}
	}
}

static int jac_to_affine(const secp256k1_jac_t *p, uint256_t *x, uint256_t *y)
{
	uint256_t zinv;
	uint256_t zinv2;
	uint256_t zinv3;

	if (u256_is_zero(&p->z)) {
		return -1;
	}
	secp256k1_fe_inv(&p->z, &zinv);
	fe_sqr(&zinv, &zinv2);
	fe_mul(&zinv2, &zinv, &zinv3);
	fe_mul(&p->x, &zinv2, x);
	fe_mul(&p->y, &zinv3, y);
	return 0;
}

static int parse_recid(uint8_t v, uint8_t *recid)
{
	if (v == 27U || v == 28U) {
		*recid = (uint8_t)(v - 27U);
		return 0;
	}
	if (v == 0U || v == 1U) {
		*recid = v;
		return 0;
	}
	return -1;
}

int secp256k1_ecrecover(const uint8_t hash[32], uint8_t v, const uint8_t r[32],
    const uint8_t s[32], uint8_t out_pubkey[64])
{
	uint256_t rr;
	uint256_t ss;
	uint256_t zz;
	uint256_t x;
	uint256_t y;
	uint256_t y2;
	uint256_t x2;
	uint256_t x3;
	uint256_t chk;
	uint256_t rinv;
	uint256_t u1;
	uint256_t u2;
	uint256_t t;
	uint8_t recid;
	secp256k1_jac_t rjac;
	secp256k1_jac_t gjac;
	secp256k1_jac_t q1;
	secp256k1_jac_t q2;
	secp256k1_jac_t q;
	uint256_t qx;
	uint256_t qy;

	if (parse_recid(v, &recid) != 0) {
		return 1;
	}
	b32_to_u256(r, &rr);
	b32_to_u256(s, &ss);
	b32_to_u256(hash, &zz);
	if (u256_is_zero(&rr) || u256_cmp(&rr, &SECP_N) >= 0) {
		return 1;
	}
	if (u256_is_zero(&ss) || u256_cmp(&ss, &SECP_N) >= 0) {
		return 1;
	}
	if (u256_cmp(&ss, &SECP_NHALF) > 0) {
		return 1;
	}
	x = rr;
	fe_sqr(&x, &x2);
	fe_mul(&x2, &x, &x3);
	fe_add(&x3, &SECP_B, &y2);
	if (fe_sqrt(&y2, &y) != 0) {
		return 1;
	}
	fe_sqr(&y, &chk);
	if (u256_eq_mask(&chk, &y2) == 0) {
		return 1;
	}
	if (((int)(y.w[0] & 1ULL)) != (int)recid) {
		fe_neg(&y, &y);
	}
	rjac.x = x;
	rjac.y = y;
	rjac.z = SECP_ONE;
	gjac.x = SECP_GX;
	gjac.y = SECP_GY;
	gjac.z = SECP_ONE;
	evm_mod256(&zz, &SECP_N, &zz);
	sc_inv(&rr, &rinv);
	sc_mul(&zz, &rinv, &t);
	evm_sub256(&SECP_N, &t, &u1);
	u256_cmov(&u1, &SECP_ZERO, u256_zero_mask(&t));
	sc_mul(&ss, &rinv, &u2);
	secp256k1_jac_mul(&gjac, &u1, &q1);
	secp256k1_jac_mul(&rjac, &u2, &q2);
	secp256k1_jac_add(&q1, &q2, &q);
	if (jac_to_affine(&q, &qx, &qy) != 0) {
		return 1;
	}
	u256_to_b32(&qx, out_pubkey);
	u256_to_b32(&qy, out_pubkey + 32);
	return 0;
}
