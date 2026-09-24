// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. See LICENSE and NOTICE.

package c2crypto

import (
	"errors"
	"math/bits"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
)

var ErrInvalidSignature = errors.New("secp256k1: invalid signature")

var (
	secpP = evm256.Uint256{
		0xfffffffefffffc2f,
		0xffffffffffffffff,
		0xffffffffffffffff,
		0xffffffffffffffff,
	}
	secpN = evm256.Uint256{
		0xbfd25e8cd0364141,
		0xbaaedce6af48a03b,
		0xfffffffffffffffe,
		0xffffffffffffffff,
	}
	secpNHalf = evm256.Uint256{
		0xdfe92f46681b20a0,
		0x5d576e7357a4501d,
		0xffffffffffffffff,
		0x7fffffffffffffff,
	}
	secpGX = evm256.Uint256{
		0x59f2815b16f81798,
		0x029bfcdb2dce28d9,
		0x55a06295ce870b07,
		0x79be667ef9dcbbac,
	}
	secpGY = evm256.Uint256{
		0x9c47d08ffb10d4b8,
		0xfd17b448a6855419,
		0x5da4fbfc0e1108a8,
		0x483ada7726a3c465,
	}
	secpB       = evm256.Uint256{7, 0, 0, 0}
	secpOne     = evm256.Uint256{1, 0, 0, 0}
	secpZero    = evm256.Uint256{}
	secpPMinus2 = [4]uint64{
		0xfffffffefffffc2d,
		0xffffffffffffffff,
		0xffffffffffffffff,
		0xffffffffffffffff,
	}
	secpSqrtExp = [4]uint64{
		0xffffffffbfffff0c,
		0xffffffffffffffff,
		0xffffffffffffffff,
		0x3fffffffffffffff,
	}
	secpNMinus2 = [4]uint64{
		0xbfd25e8cd036413f,
		0xbaaedce6af48a03b,
		0xfffffffffffffffe,
		0xffffffffffffffff,
	}
)

const secpR = uint64(0x1000003d1)

type secpJac struct {
	x, y, z evm256.Uint256
}

func u256Cmov(rd, src *evm256.Uint256, mask uint64) {
	rd[0] = (rd[0] &^ mask) | (src[0] & mask)
	rd[1] = (rd[1] &^ mask) | (src[1] & mask)
	rd[2] = (rd[2] &^ mask) | (src[2] & mask)
	rd[3] = (rd[3] &^ mask) | (src[3] & mask)
}

func ctZeroMask(t uint64) uint64 {
	v := (t | (0 - t)) >> 63
	return 0 - (v ^ 1)
}

func u256ZeroMask(a *evm256.Uint256) uint64 {
	return ctZeroMask(a[0] | a[1] | a[2] | a[3])
}

func u256EqMask(a, b *evm256.Uint256) uint64 {
	return ctZeroMask((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]) | (a[3] ^ b[3]))
}

func feAdd(a, b, out *evm256.Uint256) {
	evm256.AddMod256(a, b, &secpP, out)
}

func feSub(a, b, out *evm256.Uint256) {
	var nb evm256.Uint256
	evm256.Sub256(&secpP, b, &nb)
	evm256.AddMod256(a, &nb, &secpP, out)
}

func feMul512(a, b *evm256.Uint256, p *[8]uint64) {
	*p = [8]uint64{}
	aa, bb := *a, *b
	for i := 0; i < 4; i++ {
		var carry uint64
		for j := 0; j < 4; j++ {
			hi, lo := bits.Mul64(aa[i], bb[j])
			s, c1 := bits.Add64(p[i+j], lo, 0)
			s2, c2 := bits.Add64(s, carry, 0)
			p[i+j] = s2
			carry, _ = bits.Add64(hi, c1, c2)
		}
		p[i+4] = carry
	}
}

func mul256ByR(h0, h1, h2, h3 uint64) (l0, l1, l2, l3, extra uint64) {
	var c uint64
	hi, l0 := bits.Mul64(h0, secpR)
	hi2, lo := bits.Mul64(h1, secpR)
	l1, c = bits.Add64(lo, hi, 0)
	hi, _ = bits.Add64(hi2, c, 0)
	hi2, lo = bits.Mul64(h2, secpR)
	l2, c = bits.Add64(lo, hi, 0)
	hi, _ = bits.Add64(hi2, c, 0)
	hi2, lo = bits.Mul64(h3, secpR)
	l3, c = bits.Add64(lo, hi, 0)
	extra, _ = bits.Add64(hi2, c, 0)
	return
}

func feReduce512(z *[8]uint64, out *evm256.Uint256) {
	l0, l1, l2, l3 := z[0], z[1], z[2], z[3]
	m0, m1, m2, m3, extra := mul256ByR(z[4], z[5], z[6], z[7])
	var c uint64
	l0, c = bits.Add64(l0, m0, 0)
	l1, c = bits.Add64(l1, m1, c)
	l2, c = bits.Add64(l2, m2, c)
	l3, c = bits.Add64(l3, m3, c)
	extra, _ = bits.Add64(extra, c, 0)
	hi, lo := bits.Mul64(extra, secpR)
	l0, c = bits.Add64(l0, lo, 0)
	l1, c = bits.Add64(l1, hi, c)
	l2, c = bits.Add64(l2, 0, c)
	l3, c = bits.Add64(l3, 0, c)
	hi, lo = bits.Mul64(c, secpR)
	l0, c = bits.Add64(l0, lo, 0)
	l1, c = bits.Add64(l1, hi, c)
	l2, c = bits.Add64(l2, 0, c)
	l3, _ = bits.Add64(l3, 0, c)
	res := evm256.Uint256{l0, l1, l2, l3}
	var rp evm256.Uint256
	evm256.Sub256(&res, &secpP, &rp)
	_, br := bits.Sub64(res[0], secpP[0], 0)
	_, br = bits.Sub64(res[1], secpP[1], br)
	_, br = bits.Sub64(res[2], secpP[2], br)
	_, br = bits.Sub64(res[3], secpP[3], br)
	u256Cmov(&res, &rp, br-1)
	*out = res
}

func feMul(a, b, out *evm256.Uint256) {
	var p [8]uint64
	feMul512(a, b, &p)
	feReduce512(&p, out)
}

func feSqr(a, out *evm256.Uint256) {
	feMul(a, a, out)
}

func feDbl(a, out *evm256.Uint256) {
	evm256.AddMod256(a, a, &secpP, out)
}

func feNeg(a, out *evm256.Uint256) {
	var t evm256.Uint256
	evm256.Sub256(&secpP, a, &t)
	z := u256ZeroMask(a)
	*out = t
	u256Cmov(out, &secpZero, z)
}

func fePow(baseIn *evm256.Uint256, e [4]uint64, out *evm256.Uint256) {
	base := *baseIn
	result := secpOne
	for i := 0; i < 256; i++ {
		bit := (e[i>>6] >> (uint(i) & 63)) & 1
		mask := 0 - bit
		var tmp evm256.Uint256
		feMul(&result, &base, &tmp)
		u256Cmov(&result, &tmp, mask)
		feSqr(&base, &tmp)
		base = tmp
	}
	*out = result
}

func secp256k1FeInv(a, out *evm256.Uint256) {
	fePow(a, secpPMinus2, out)
}

func feSqrt(a, out *evm256.Uint256) int {
	var y, y2 evm256.Uint256
	fePow(a, secpSqrtExp, &y)
	feSqr(&y, &y2)
	if u256EqMask(&y2, a) == 0 {
		return -1
	}
	*out = y
	return 0
}

func jacCmov(rd, src *secpJac, mask uint64) {
	u256Cmov(&rd.x, &src.x, mask)
	u256Cmov(&rd.y, &src.y, mask)
	u256Cmov(&rd.z, &src.z, mask)
}

func jacSetInf(p *secpJac) {
	p.x = secpZero
	p.y = secpOne
	p.z = secpZero
}

func jacDoubleBody(p, out *secpJac) {
	var a, b, c, d, e, f, t1, t2, x3, y3, z3 evm256.Uint256
	feSqr(&p.x, &a)
	feSqr(&p.y, &b)
	feSqr(&b, &c)
	feAdd(&p.x, &b, &t1)
	feSqr(&t1, &t2)
	feSub(&t2, &a, &t1)
	feSub(&t1, &c, &t2)
	feDbl(&t2, &d)
	feDbl(&a, &t1)
	feAdd(&t1, &a, &e)
	feSqr(&e, &f)
	feDbl(&d, &t1)
	feSub(&f, &t1, &x3)
	feSub(&d, &x3, &t1)
	feMul(&e, &t1, &t2)
	feDbl(&c, &t1)
	feDbl(&t1, &t1)
	feDbl(&t1, &t1)
	feSub(&t2, &t1, &y3)
	feAdd(&p.y, &p.y, &t1)
	feMul(&t1, &p.z, &z3)
	out.x = x3
	out.y = y3
	out.z = z3
}

func secp256k1JacDouble(p, out *secpJac) {
	pp := *p
	var r, inf secpJac
	jacDoubleBody(&pp, &r)
	jacSetInf(&inf)
	zmask := u256ZeroMask(&pp.z)
	jacCmov(&r, &inf, zmask)
	*out = r
}

func jacAddBody(p, q, out *secpJac, hOut, s1Out, s2Out *evm256.Uint256) {
	var z1z1, z2z2, u1, u2, s1, s2, h, i, j, r, v, t1, t2, x3, y3, z3 evm256.Uint256
	feSqr(&p.z, &z1z1)
	feSqr(&q.z, &z2z2)
	feMul(&p.x, &z2z2, &u1)
	feMul(&q.x, &z1z1, &u2)
	feMul(&q.z, &z2z2, &t1)
	feMul(&p.y, &t1, &s1)
	feMul(&p.z, &z1z1, &t1)
	feMul(&q.y, &t1, &s2)
	feSub(&u2, &u1, &h)
	feDbl(&h, &t1)
	feSqr(&t1, &i)
	feMul(&h, &i, &j)
	feSub(&s2, &s1, &t1)
	feDbl(&t1, &r)
	feMul(&u1, &i, &v)
	feSqr(&r, &t1)
	feSub(&t1, &j, &t2)
	feDbl(&v, &t1)
	feSub(&t2, &t1, &x3)
	feSub(&v, &x3, &t1)
	feMul(&r, &t1, &t2)
	feMul(&s1, &j, &t1)
	feDbl(&t1, &t1)
	feSub(&t2, &t1, &y3)
	feAdd(&p.z, &q.z, &t1)
	feSqr(&t1, &t2)
	feSub(&t2, &z1z1, &t1)
	feSub(&t1, &z2z2, &t2)
	feMul(&t2, &h, &z3)
	out.x = x3
	out.y = y3
	out.z = z3
	*hOut = h
	*s1Out = s1
	*s2Out = s2
}

func secp256k1JacAdd(p, q, out *secpJac) {
	pp := *p
	qq := *q
	var sum, dbl, inf, r secpJac
	var h, s1, s2 evm256.Uint256
	jacAddBody(&pp, &qq, &sum, &h, &s1, &s2)
	jacDoubleBody(&pp, &dbl)
	jacSetInf(&inf)
	z1m := u256ZeroMask(&pp.z)
	z2m := u256ZeroMask(&qq.z)
	hm := u256ZeroMask(&h)
	sm := u256EqMask(&s1, &s2)
	r = sum
	jacCmov(&r, &dbl, hm&sm)
	jacCmov(&r, &inf, hm&^sm)
	jacCmov(&r, &qq, z1m)
	jacCmov(&r, &pp, z2m)
	*out = r
}

func secp256k1JacMul(p *secpJac, k *evm256.Uint256, out *secpJac) {
	base := *p
	var r secpJac
	jacSetInf(&r)
	for i := 255; i >= 0; i-- {
		bit := (k[i>>6] >> (uint(i) & 63)) & 1
		mask := 0 - bit
		secp256k1JacDouble(&r, &r)
		var t secpJac
		secp256k1JacAdd(&r, &base, &t)
		jacCmov(&r, &t, mask)
	}
	*out = r
}

func scMul(a, b, out *evm256.Uint256) {
	evm256.MulMod256(a, b, &secpN, out)
}

func scInv(a, out *evm256.Uint256) {
	base := *a
	result := secpOne
	for i := 0; i < 256; i++ {
		bit := (secpNMinus2[i>>6] >> (uint(i) & 63)) & 1
		mask := 0 - bit
		var tmp evm256.Uint256
		scMul(&result, &base, &tmp)
		u256Cmov(&result, &tmp, mask)
		scMul(&base, &base, &tmp)
		base = tmp
	}
	*out = result
}

func jacToAffine(p *secpJac, x, y *evm256.Uint256) int {
	if evm256.IsZero(&p.z) {
		return -1
	}
	var zinv, zinv2, zinv3 evm256.Uint256
	secp256k1FeInv(&p.z, &zinv)
	feSqr(&zinv, &zinv2)
	feMul(&zinv2, &zinv, &zinv3)
	feMul(&p.x, &zinv2, x)
	feMul(&p.y, &zinv3, y)
	return 0
}

func parseRecid(v uint8, recid *uint8) int {
	if v == 27 || v == 28 {
		*recid = v - 27
		return 0
	}
	if v == 0 || v == 1 {
		*recid = v
		return 0
	}
	return -1
}

func EcRecover(hash []byte, v uint8, r, s []byte, outPubkey *[64]byte) error {
	if len(hash) != 32 || len(r) != 32 || len(s) != 32 || outPubkey == nil {
		return ErrInvalidSignature
	}
	var recid uint8
	if parseRecid(v, &recid) != 0 {
		return ErrInvalidSignature
	}
	rr := evm256.FromBytesBE(r)
	ss := evm256.FromBytesBE(s)
	zz := evm256.FromBytesBE(hash)
	if evm256.IsZero(&rr) || evm256.Cmp(&rr, &secpN) >= 0 {
		return ErrInvalidSignature
	}
	if evm256.IsZero(&ss) || evm256.Cmp(&ss, &secpN) >= 0 {
		return ErrInvalidSignature
	}
	if evm256.Cmp(&ss, &secpNHalf) > 0 {
		return ErrInvalidSignature
	}
	x := rr
	var x2, x3, y2, y, chk evm256.Uint256
	feSqr(&x, &x2)
	feMul(&x2, &x, &x3)
	feAdd(&x3, &secpB, &y2)
	if feSqrt(&y2, &y) != 0 {
		return ErrInvalidSignature
	}
	feSqr(&y, &chk)
	if u256EqMask(&chk, &y2) == 0 {
		return ErrInvalidSignature
	}
	if int(y[0]&1) != int(recid) {
		feNeg(&y, &y)
	}
	var rjac, gjac secpJac
	rjac.x = x
	rjac.y = y
	rjac.z = secpOne
	gjac.x = secpGX
	gjac.y = secpGY
	gjac.z = secpOne
	evm256.Mod256(&zz, &secpN, &zz)
	var rinv, t, u1, u2 evm256.Uint256
	scInv(&rr, &rinv)
	scMul(&zz, &rinv, &t)
	evm256.Sub256(&secpN, &t, &u1)
	u256Cmov(&u1, &secpZero, u256ZeroMask(&t))
	scMul(&ss, &rinv, &u2)
	var q1, q2, q secpJac
	secp256k1JacMul(&gjac, &u1, &q1)
	secp256k1JacMul(&rjac, &u2, &q2)
	secp256k1JacAdd(&q1, &q2, &q)
	var qx, qy evm256.Uint256
	if jacToAffine(&q, &qx, &qy) != 0 {
		return ErrInvalidSignature
	}
	xb := evm256.BytesBE(qx)
	yb := evm256.BytesBE(qy)
	copy(outPubkey[:32], xb[:])
	copy(outPubkey[32:], yb[:])
	return nil
}

var ErrInvalidPrivateKey = errors.New("secp256k1: invalid private key")

func Secp256k1PubkeyFromSeckey(seckey []byte, outPubkey *[64]byte) error {
	if len(seckey) != 32 || outPubkey == nil {
		return ErrInvalidPrivateKey
	}
	k := evm256.FromBytesBE(seckey)
	if evm256.IsZero(&k) || evm256.Cmp(&k, &secpN) >= 0 {
		return ErrInvalidPrivateKey
	}
	var gjac, q secpJac
	gjac.x = secpGX
	gjac.y = secpGY
	gjac.z = secpOne
	secp256k1JacMul(&gjac, &k, &q)
	var qx, qy evm256.Uint256
	if jacToAffine(&q, &qx, &qy) != 0 {
		return ErrInvalidPrivateKey
	}
	xb := evm256.BytesBE(qx)
	yb := evm256.BytesBE(qy)
	copy(outPubkey[:32], xb[:])
	copy(outPubkey[32:], yb[:])
	return nil
}

func AddressFromPrivateKey(seckey []byte) ([20]byte, error) {
	var pub [64]byte
	if err := Secp256k1PubkeyFromSeckey(seckey, &pub); err != nil {
		return [20]byte{}, err
	}
	var h [32]byte
	Keccak256(pub[:], &h)
	var addr [20]byte
	copy(addr[:], h[12:32])
	return addr, nil
}
