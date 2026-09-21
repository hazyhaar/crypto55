#include "evm_arith256.h"

static void u256_clear(uint256_t *x)
{
	x->w[0] = 0;
	x->w[1] = 0;
	x->w[2] = 0;
	x->w[3] = 0;
}

static void u256_set_one(uint256_t *x)
{
	x->w[0] = 1;
	x->w[1] = 0;
	x->w[2] = 0;
	x->w[3] = 0;
}

static int u256_is_zero(const uint256_t *x)
{
	return (x->w[0] | x->w[1] | x->w[2] | x->w[3]) == 0;
}

static int u256_is_neg(const uint256_t *x)
{
	return (int)(x->w[3] >> 63);
}

static uint64_t u256_add(const uint256_t *a, const uint256_t *b, uint256_t *out)
{
	uint64_t c = 0;
	int i;
	for (i = 0; i < 4; i++) {
		uint64_t av = a->w[i];
		uint64_t t = av + c;
		uint64_t c1 = (t < av);
		uint64_t r = t + b->w[i];
		uint64_t c2 = (r < t);
		out->w[i] = r;
		c = c1 | c2;
	}
	return c;
}

static void u256_sub(const uint256_t *a, const uint256_t *b, uint256_t *out)
{
	uint64_t br = 0;
	int i;
	for (i = 0; i < 4; i++) {
		uint64_t av = a->w[i];
		uint64_t t = av - br;
		uint64_t b1 = (av < br);
		uint64_t r = t - b->w[i];
		uint64_t b2 = (t < b->w[i]);
		out->w[i] = r;
		br = b1 | b2;
	}
}

static void u256_neg(const uint256_t *x, uint256_t *out)
{
	uint64_t c = 1;
	int i;
	for (i = 0; i < 4; i++) {
		uint64_t t = ~x->w[i];
		uint64_t s = t + c;
		c = (uint64_t)(s < t);
		out->w[i] = s;
	}
}

static void u256_abs(const uint256_t *x, uint256_t *out)
{
	if (u256_is_neg(x)) {
		u256_neg(x, out);
	} else {
		*out = *x;
	}
}

static void u256_shr1(uint256_t *x)
{
	x->w[0] = (x->w[0] >> 1) | (x->w[1] << 63);
	x->w[1] = (x->w[1] >> 1) | (x->w[2] << 63);
	x->w[2] = (x->w[2] >> 1) | (x->w[3] << 63);
	x->w[3] = x->w[3] >> 1;
}

static void mul64(uint64_t a, uint64_t b, uint64_t *hi, uint64_t *lo)
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

static void mul512(const uint256_t *a, const uint256_t *b, uint64_t p[8])
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
			mul64(a->w[i], b->w[j], &hi, &lo);
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

static uint64_t add_to_un(uint64_t un[9], int j, const uint64_t dn[4], int n)
{
	uint64_t carry = 0;
	int i;
	for (i = 0; i < n; i++) {
		uint64_t av = un[j + i];
		uint64_t t = av + carry;
		uint64_t c1 = (uint64_t)(t < av);
		uint64_t s = t + dn[i];
		uint64_t c2 = (uint64_t)(s < t);
		un[j + i] = s;
		carry = c1 | c2;
	}
	return carry;
}

static uint64_t sub_mul_to_un(uint64_t un[9], int j, const uint64_t dn[4], int n, uint64_t m)
{
	uint64_t borrow = 0;
	int i;
	for (i = 0; i < n; i++) {
		uint64_t s;
		uint64_t t;
		uint64_t ph;
		uint64_t pl;
		uint64_t c1;
		uint64_t c2;
		s = un[j + i] - borrow;
		c1 = (uint64_t)(un[j + i] < borrow);
		mul64(dn[i], m, &ph, &pl);
		t = s - pl;
		c2 = (uint64_t)(s < pl);
		un[j + i] = t;
		borrow = ph + c1 + c2;
	}
	return borrow;
}

static uint64_t div64(uint64_t hi, uint64_t lo, uint64_t y, uint64_t *r)
{
	unsigned __int128 n = ((unsigned __int128)hi << 64) | lo;
	*r = (uint64_t)(n % y);
	return (uint64_t)(n / y);
}

static uint64_t reciprocal2by1(uint64_t d)
{
	uint64_t r;
	return div64(~d, ~0ULL, d, &r);
}

static uint64_t add64(uint64_t a, uint64_t b, uint64_t cin, uint64_t *cout)
{
	uint64_t s = a + cin;
	uint64_t c1 = (uint64_t)(s < a);
	uint64_t r = s + b;
	uint64_t c2 = (uint64_t)(r < s);
	*cout = c1 | c2;
	return r;
}

static uint64_t udivrem2by1(uint64_t uh, uint64_t ul, uint64_t d, uint64_t reciprocal, uint64_t *rem)
{
	uint64_t qh;
	uint64_t ql;
	uint64_t carry;
	uint64_t dummy;
	uint64_t r;
	mul64(reciprocal, uh, &qh, &ql);
	ql = add64(ql, ul, 0, &carry);
	qh = add64(qh, uh, carry, &dummy);
	(void)dummy;
	qh++;
	r = ul - qh * d;
	if (r > ql) {
		qh--;
		r += d;
	}
	if (r >= d) {
		qh++;
		r -= d;
	}
	*rem = r;
	return qh;
}

static void udivrem(uint64_t quot[8], const uint64_t *u, int ulen_in, const uint256_t *d, uint256_t *rem)
{
	int dlen = 4;
	int ulen;
	int i;
	int j;
	unsigned shift;
	uint64_t dn[4];
	uint64_t un[9];

	for (i = 0; i < 8; i++) {
		quot[i] = 0;
	}
	u256_clear(rem);
	for (i = 0; i < 9; i++) {
		un[i] = 0;
	}
	for (i = 0; i < 4; i++) {
		dn[i] = 0;
	}

	while (dlen > 0 && d->w[dlen - 1] == 0) {
		dlen--;
	}
	if (dlen == 0) {
		return;
	}
	ulen = ulen_in;
	if (ulen > 8) {
		ulen = 8;
	}
	while (ulen > 0 && u[ulen - 1] == 0) {
		ulen--;
	}
	if (ulen == 0) {
		return;
	}
	if (ulen < dlen) {
		for (i = 0; i < ulen; i++) {
			rem->w[i] = u[i];
		}
		return;
	}

	shift = (unsigned)__builtin_clzll(d->w[dlen - 1]);
	if (shift == 0) {
		for (i = 0; i < dlen; i++) {
			dn[i] = d->w[i];
		}
		for (i = 0; i < ulen; i++) {
			un[i] = u[i];
		}
	} else {
		unsigned rsh = 64U - shift;
		dn[0] = d->w[0] << shift;
		for (i = 1; i < dlen; i++) {
			dn[i] = (d->w[i] << shift) | (d->w[i - 1] >> rsh);
		}
		un[0] = u[0] << shift;
		for (i = 1; i < ulen; i++) {
			un[i] = (u[i] << shift) | (u[i - 1] >> rsh);
		}
		un[ulen] = u[ulen - 1] >> rsh;
	}

	if (dlen == 1) {
		uint64_t r = un[ulen];
		uint64_t rec = reciprocal2by1(dn[0]);
		for (j = ulen - 1; j >= 0; j--) {
			quot[j] = udivrem2by1(r, un[j], dn[0], rec, &r);
		}
		rem->w[0] = r >> shift;
		return;
	}

	{
		uint64_t dh = dn[dlen - 1];
		uint64_t dl = dn[dlen - 2];
		uint64_t rec = reciprocal2by1(dh);
		for (j = ulen - dlen; j >= 0; j--) {
			uint64_t u2 = un[j + dlen];
			uint64_t u1 = un[j + dlen - 1];
			uint64_t u0 = un[j + dlen - 2];
			uint64_t qhat;
			uint64_t rhat;
			uint64_t borrow;
			if (u2 >= dh) {
				qhat = ~0ULL;
			} else {
				uint64_t ph;
				uint64_t pl;
				qhat = udivrem2by1(u2, u1, dh, rec, &rhat);
				mul64(qhat, dl, &ph, &pl);
				if (ph > rhat || (ph == rhat && pl > u0)) {
					qhat--;
				}
			}
			borrow = sub_mul_to_un(un, j, dn, dlen, qhat);
			un[j + dlen] = u2 - borrow;
			if (u2 < borrow) {
				qhat--;
				un[j + dlen] += add_to_un(un, j, dn, dlen);
			}
			quot[j] = qhat;
		}
	}

	if (shift == 0) {
		for (i = 0; i < dlen; i++) {
			rem->w[i] = un[i];
		}
		return;
	}
	{
		unsigned rsh = 64U - shift;
		for (i = 0; i < dlen - 1; i++) {
			rem->w[i] = (un[i] >> shift) | (un[i + 1] << rsh);
		}
		rem->w[dlen - 1] = un[dlen - 1] >> shift;
	}
}

static void rem_limbs(const uint64_t *num, int nlimbs, const uint256_t *m, uint256_t *out)
{
	uint64_t quot[8];
	udivrem(quot, num, nlimbs, m, out);
}

static void divmod256(const uint256_t *n, const uint256_t *d, uint256_t *q, uint256_t *r)
{
	uint64_t u[8];
	uint64_t quot[8];
	uint256_t rem;
	u[0] = n->w[0];
	u[1] = n->w[1];
	u[2] = n->w[2];
	u[3] = n->w[3];
	u[4] = 0;
	u[5] = 0;
	u[6] = 0;
	u[7] = 0;
	udivrem(quot, u, 4, d, &rem);
	if (q) {
		q->w[0] = quot[0];
		q->w[1] = quot[1];
		q->w[2] = quot[2];
		q->w[3] = quot[3];
	}
	if (r) {
		*r = rem;
	}
}

void evm_add256(const uint256_t *a, const uint256_t *b, uint256_t *out)
{
	uint256_t aa = *a;
	uint256_t bb = *b;
	(void)u256_add(&aa, &bb, out);
}

void evm_sub256(const uint256_t *a, const uint256_t *b, uint256_t *out)
{
	uint256_t aa = *a;
	uint256_t bb = *b;
	u256_sub(&aa, &bb, out);
}

void evm_mul256(const uint256_t *a, const uint256_t *b, uint256_t *out)
{
	uint256_t aa = *a;
	uint256_t bb = *b;
	uint64_t p[8];
	mul512(&aa, &bb, p);
	out->w[0] = p[0];
	out->w[1] = p[1];
	out->w[2] = p[2];
	out->w[3] = p[3];
}

void evm_div256(const uint256_t *a, const uint256_t *b, uint256_t *out)
{
	uint256_t aa = *a;
	uint256_t bb = *b;
	if (u256_is_zero(&bb)) {
		u256_clear(out);
		return;
	}
	divmod256(&aa, &bb, out, 0);
}

void evm_mod256(const uint256_t *a, const uint256_t *b, uint256_t *out)
{
	uint256_t aa = *a;
	uint256_t bb = *b;
	if (u256_is_zero(&bb)) {
		u256_clear(out);
		return;
	}
	divmod256(&aa, &bb, 0, out);
}

void evm_sdiv256(const uint256_t *a, const uint256_t *b, uint256_t *out)
{
	uint256_t aa = *a;
	uint256_t bb = *b;
	uint256_t ua;
	uint256_t ub;
	uint256_t q;
	int na;
	int nb;
	if (u256_is_zero(&bb)) {
		u256_clear(out);
		return;
	}
	na = u256_is_neg(&aa);
	nb = u256_is_neg(&bb);
	u256_abs(&aa, &ua);
	u256_abs(&bb, &ub);
	divmod256(&ua, &ub, &q, 0);
	if (na != nb) {
		u256_neg(&q, out);
	} else {
		*out = q;
	}
}

void evm_smod256(const uint256_t *a, const uint256_t *b, uint256_t *out)
{
	uint256_t aa = *a;
	uint256_t bb = *b;
	uint256_t ua;
	uint256_t ub;
	uint256_t r;
	if (u256_is_zero(&bb)) {
		u256_clear(out);
		return;
	}
	u256_abs(&aa, &ua);
	u256_abs(&bb, &ub);
	divmod256(&ua, &ub, 0, &r);
	if (u256_is_neg(&aa)) {
		u256_neg(&r, out);
	} else {
		*out = r;
	}
}

void evm_addmod256(const uint256_t *a, const uint256_t *b, const uint256_t *m, uint256_t *out)
{
	uint256_t aa = *a;
	uint256_t bb = *b;
	uint256_t mm = *m;
	uint256_t sum;
	uint64_t limbs[5];
	uint64_t c;
	if (u256_is_zero(&mm)) {
		u256_clear(out);
		return;
	}
	c = u256_add(&aa, &bb, &sum);
	limbs[0] = sum.w[0];
	limbs[1] = sum.w[1];
	limbs[2] = sum.w[2];
	limbs[3] = sum.w[3];
	limbs[4] = c;
	rem_limbs(limbs, 5, &mm, out);
}

void evm_mulmod256(const uint256_t *a, const uint256_t *b, const uint256_t *m, uint256_t *out)
{
	uint256_t aa = *a;
	uint256_t bb = *b;
	uint256_t mm = *m;
	uint64_t p[8];
	if (u256_is_zero(&mm)) {
		u256_clear(out);
		return;
	}
	mul512(&aa, &bb, p);
	rem_limbs(p, 8, &mm, out);
}

void evm_exp256(const uint256_t *base, const uint256_t *exp, uint256_t *out)
{
	uint256_t r;
	uint256_t b = *base;
	uint256_t e = *exp;
	u256_set_one(&r);
	while (!u256_is_zero(&e)) {
		if (e.w[0] & 1ULL) {
			uint256_t t;
			evm_mul256(&r, &b, &t);
			r = t;
		}
		{
			uint256_t t;
			evm_mul256(&b, &b, &t);
			b = t;
		}
		u256_shr1(&e);
	}
	*out = r;
}

void evm_signextend256(uint64_t b, const uint256_t *x, uint256_t *out)
{
	uint256_t xx = *x;
	unsigned t;
	unsigned wi;
	unsigned bi;
	unsigned i;
	uint64_t sign;
	uint64_t keep;
	if (b >= 31ULL) {
		*out = xx;
		return;
	}
	t = (unsigned)(b * 8ULL + 7ULL);
	wi = t >> 6;
	bi = t & 63U;
	sign = (xx.w[wi] >> bi) & 1ULL;
	if (bi == 63U) {
		keep = UINT64_MAX;
	} else {
		keep = (1ULL << (bi + 1U)) - 1ULL;
	}
	for (i = 0; i < 4; i++) {
		if (i < wi) {
			out->w[i] = xx.w[i];
		} else if (i == wi) {
			if (sign) {
				out->w[i] = xx.w[i] | ~keep;
			} else {
				out->w[i] = xx.w[i] & keep;
			}
		} else if (sign) {
			out->w[i] = UINT64_MAX;
		} else {
			out->w[i] = 0;
		}
	}
}
