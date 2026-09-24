// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. See LICENSE and NOTICE.

package evm256

import "math/bits"

func addCarry(a, b, out *Uint256) uint64 {
	aa, bb := *a, *b
	var c uint64
	var r Uint256
	r[0], c = bits.Add64(aa[0], bb[0], 0)
	r[1], c = bits.Add64(aa[1], bb[1], c)
	r[2], c = bits.Add64(aa[2], bb[2], c)
	r[3], c = bits.Add64(aa[3], bb[3], c)
	*out = r
	return c
}

func Add256(a, b, out *Uint256) {
	_ = addCarry(a, b, out)
}

func Sub256(a, b, out *Uint256) {
	aa, bb := *a, *b
	var br uint64
	var r Uint256
	r[0], br = bits.Sub64(aa[0], bb[0], 0)
	r[1], br = bits.Sub64(aa[1], bb[1], br)
	r[2], br = bits.Sub64(aa[2], bb[2], br)
	r[3], _ = bits.Sub64(aa[3], bb[3], br)
	*out = r
}

func mul512(a, b *Uint256, p *[8]uint64) {
	*p = [8]uint64{}
	for i := 0; i < 4; i++ {
		var carry uint64
		for j := 0; j < 4; j++ {
			hi, lo := bits.Mul64(a[i], b[j])
			s, c1 := bits.Add64(p[i+j], lo, 0)
			s2, c2 := bits.Add64(s, carry, 0)
			p[i+j] = s2
			carry, _ = bits.Add64(hi, c1, c2)
		}
		p[i+4] = carry
	}
}

func Mul256(a, b, out *Uint256) {
	aa, bb := *a, *b
	var p [8]uint64
	mul512(&aa, &bb, &p)
	*out = Uint256{p[0], p[1], p[2], p[3]}
}

func shr1(x *Uint256) {
	x[0] = (x[0] >> 1) | (x[1] << 63)
	x[1] = (x[1] >> 1) | (x[2] << 63)
	x[2] = (x[2] >> 1) | (x[3] << 63)
	x[3] >>= 1
}

func addToUn(un *[9]uint64, j int, dn *[4]uint64, n int) uint64 {
	var carry uint64
	for i := 0; i < n; i++ {
		un[j+i], carry = bits.Add64(un[j+i], dn[i], carry)
	}
	return carry
}

func subMulToUn(un *[9]uint64, j int, dn *[4]uint64, n int, m uint64) uint64 {
	var borrow uint64
	for i := 0; i < n; i++ {
		s, c1 := bits.Sub64(un[j+i], borrow, 0)
		ph, pl := bits.Mul64(dn[i], m)
		t, c2 := bits.Sub64(s, pl, 0)
		un[j+i] = t
		borrow = ph + c1 + c2
	}
	return borrow
}

func reciprocal2by1(d uint64) uint64 {
	reciprocal, _ := bits.Div64(^d, ^uint64(0), d)
	return reciprocal
}

func udivrem2by1(uh, ul, d, reciprocal uint64) (quot, rem uint64) {
	qh, ql := bits.Mul64(reciprocal, uh)
	ql, carry := bits.Add64(ql, ul, 0)
	qh, _ = bits.Add64(qh, uh, carry)
	qh++
	r := ul - qh*d
	if r > ql {
		qh--
		r += d
	}
	if r >= d {
		qh++
		r -= d
	}
	return qh, r
}

func udivrem(quot *[8]uint64, u *[8]uint64, uLenIn int, d *Uint256) (rem Uint256) {
	dLen := 4
	for dLen > 0 && d[dLen-1] == 0 {
		dLen--
	}
	if dLen == 0 {
		return
	}
	uLen := uLenIn
	if uLen > 8 {
		uLen = 8
	}
	for uLen > 0 && u[uLen-1] == 0 {
		uLen--
	}
	if uLen == 0 {
		return
	}
	if uLen < dLen {
		for i := 0; i < uLen; i++ {
			rem[i] = u[i]
		}
		return
	}

	shift := uint(bits.LeadingZeros64(d[dLen-1]))
	var dn [4]uint64
	var un [9]uint64
	if shift == 0 {
		for i := 0; i < dLen; i++ {
			dn[i] = d[i]
		}
		for i := 0; i < uLen; i++ {
			un[i] = u[i]
		}
	} else {
		rsh := 64 - shift
		dn[0] = d[0] << shift
		for i := 1; i < dLen; i++ {
			dn[i] = (d[i] << shift) | (d[i-1] >> rsh)
		}
		un[0] = u[0] << shift
		for i := 1; i < uLen; i++ {
			un[i] = (u[i] << shift) | (u[i-1] >> rsh)
		}
		un[uLen] = u[uLen-1] >> rsh
	}

	if dLen == 1 {
		r := un[uLen]
		rec := reciprocal2by1(dn[0])
		for j := uLen - 1; j >= 0; j-- {
			quot[j], r = udivrem2by1(r, un[j], dn[0], rec)
		}
		rem[0] = r >> shift
		return
	}

	dh := dn[dLen-1]
	dl := dn[dLen-2]
	rec := reciprocal2by1(dh)
	for j := uLen - dLen; j >= 0; j-- {
		u2 := un[j+dLen]
		u1 := un[j+dLen-1]
		u0 := un[j+dLen-2]
		var qhat, rhat uint64
		if u2 >= dh {
			qhat = ^uint64(0)
		} else {
			qhat, rhat = udivrem2by1(u2, u1, dh, rec)
			ph, pl := bits.Mul64(qhat, dl)
			if ph > rhat || (ph == rhat && pl > u0) {
				qhat--
			}
		}
		borrow := subMulToUn(&un, j, &dn, dLen, qhat)
		un[j+dLen] = u2 - borrow
		if u2 < borrow {
			qhat--
			un[j+dLen] += addToUn(&un, j, &dn, dLen)
		}
		quot[j] = qhat
	}

	if shift == 0 {
		for i := 0; i < dLen; i++ {
			rem[i] = un[i]
		}
		return
	}
	rsh := 64 - shift
	for i := 0; i < dLen-1; i++ {
		rem[i] = (un[i] >> shift) | (un[i+1] << rsh)
	}
	rem[dLen-1] = un[dLen-1] >> shift
	return
}

func remLimbs(num *[8]uint64, nlimbs int, m, out *Uint256) {
	var quot [8]uint64
	*out = udivrem(&quot, num, nlimbs, m)
}

func divmod256(n, d *Uint256) (q, r Uint256) {
	var u [8]uint64
	u[0], u[1], u[2], u[3] = n[0], n[1], n[2], n[3]
	var quot [8]uint64
	r = udivrem(&quot, &u, 4, d)
	q = Uint256{quot[0], quot[1], quot[2], quot[3]}
	return
}

func Div256(a, b, out *Uint256) {
	aa, bb := *a, *b
	if IsZero(&bb) {
		*out = Uint256{}
		return
	}
	q, _ := divmod256(&aa, &bb)
	*out = q
}

func Mod256(a, b, out *Uint256) {
	aa, bb := *a, *b
	if IsZero(&bb) {
		*out = Uint256{}
		return
	}
	_, r := divmod256(&aa, &bb)
	*out = r
}

func neg256(x, out *Uint256) {
	xx := *x
	c := uint64(1)
	var r Uint256
	r[0], c = bits.Add64(^xx[0], 0, c)
	r[1], c = bits.Add64(^xx[1], 0, c)
	r[2], c = bits.Add64(^xx[2], 0, c)
	r[3], _ = bits.Add64(^xx[3], 0, c)
	*out = r
}

func abs256(x, out *Uint256) {
	if isNeg(x) {
		neg256(x, out)
		return
	}
	*out = *x
}

func SDiv256(a, b, out *Uint256) {
	aa, bb := *a, *b
	if IsZero(&bb) {
		*out = Uint256{}
		return
	}
	na := isNeg(&aa)
	nb := isNeg(&bb)
	var ua, ub Uint256
	abs256(&aa, &ua)
	abs256(&bb, &ub)
	q, _ := divmod256(&ua, &ub)
	if na != nb {
		neg256(&q, out)
		return
	}
	*out = q
}

func SMod256(a, b, out *Uint256) {
	aa, bb := *a, *b
	if IsZero(&bb) {
		*out = Uint256{}
		return
	}
	var ua, ub Uint256
	abs256(&aa, &ua)
	abs256(&bb, &ub)
	_, r := divmod256(&ua, &ub)
	if isNeg(&aa) {
		neg256(&r, out)
		return
	}
	*out = r
}

func AddMod256(a, b, m, out *Uint256) {
	aa, bb, mm := *a, *b, *m
	if IsZero(&mm) {
		*out = Uint256{}
		return
	}
	var sum Uint256
	c := addCarry(&aa, &bb, &sum)
	var limbs [8]uint64
	limbs[0] = sum[0]
	limbs[1] = sum[1]
	limbs[2] = sum[2]
	limbs[3] = sum[3]
	limbs[4] = c
	remLimbs(&limbs, 5, &mm, out)
}

func MulMod256(a, b, m, out *Uint256) {
	aa, bb, mm := *a, *b, *m
	if IsZero(&mm) {
		*out = Uint256{}
		return
	}
	var p [8]uint64
	mul512(&aa, &bb, &p)
	remLimbs(&p, 8, &mm, out)
}

func Exp256(base, exp, out *Uint256) {
	var r Uint256
	r[0] = 1
	b := *base
	e := *exp
	for !IsZero(&e) {
		if e[0]&1 != 0 {
			var t Uint256
			Mul256(&r, &b, &t)
			r = t
		}
		var t Uint256
		Mul256(&b, &b, &t)
		b = t
		shr1(&e)
	}
	*out = r
}

func SignExtend256(b uint64, x, out *Uint256) {
	xx := *x
	if b >= 31 {
		*out = xx
		return
	}
	t := uint(b*8 + 7)
	wi := t >> 6
	bi := t & 63
	sign := (xx[wi] >> bi) & 1
	var keep uint64
	if bi == 63 {
		keep = ^uint64(0)
	} else {
		keep = (uint64(1) << (bi + 1)) - 1
	}
	var r Uint256
	for i := uint(0); i < 4; i++ {
		switch {
		case i < wi:
			r[i] = xx[i]
		case i == wi:
			if sign != 0 {
				r[i] = xx[i] | ^keep
			} else {
				r[i] = xx[i] & keep
			}
		case sign != 0:
			r[i] = ^uint64(0)
		}
	}
	*out = r
}
