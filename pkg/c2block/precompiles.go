package c2block

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2crypto"
)

var (
	ErrPrecompileOOG  = errors.New("c2block: precompile out of gas")
	ErrPrecompileExec = errors.New("c2block: precompile failed")
)

func RunPrecompile(addr uint64, input []byte, gas uint64) ([]byte, uint64, error) {
	switch addr {
	case 1:
		return pcEcrecover(input, gas)
	case 2:
		return pcSHA256(input, gas)
	case 3:
		return pcRIPEMD160(input, gas)
	case 4:
		return pcIdentity(input, gas)
	case 5:
		return pcModexp(input, gas)
	case 6:
		return pcEcAdd(input, gas)
	case 7:
		return pcEcMul(input, gas)
	case 8:
		return pcEcPairing(input, gas)
	case 9:
		return pcBlake2F(input, gas)
	case 10:
		return pcKZG(input, gas)
	default:
		return nil, gas, ErrPrecompileExec
	}
}

func chargePC(gas, cost uint64) (uint64, error) {
	if gas < cost {
		return 0, ErrPrecompileOOG
	}
	return gas - cost, nil
}

func words32(n int) uint64 {
	if n <= 0 {
		return 0
	}
	return (uint64(n) + 31) / 32
}

func pad32(in []byte, n int) []byte {
	if len(in) >= n {
		return in[:n]
	}
	out := make([]byte, n)
	copy(out, in)
	return out
}

func pcEcrecover(input []byte, gas uint64) ([]byte, uint64, error) {
	left, err := chargePC(gas, 3000)
	if err != nil {
		return nil, 0, err
	}
	in := pad32(input, 128)
	hash := in[0:32]
	v := in[63]
	r := in[64:96]
	s := in[96:128]
	var pub [64]byte
	if err := c2crypto.EcRecover(hash, v, r, s, &pub); err != nil {
		return nil, left, nil
	}
	var kh [32]byte
	c2crypto.Keccak256(pub[:], &kh)
	out := make([]byte, 32)
	copy(out[12:], kh[12:])
	return out, left, nil
}

func pcSHA256(input []byte, gas uint64) ([]byte, uint64, error) {
	cost := 60 + 12*words32(len(input))
	left, err := chargePC(gas, cost)
	if err != nil {
		return nil, 0, err
	}
	sum := sha256.Sum256(input)
	return sum[:], left, nil
}

func pcRIPEMD160(input []byte, gas uint64) ([]byte, uint64, error) {
	cost := 600 + 120*words32(len(input))
	left, err := chargePC(gas, cost)
	if err != nil {
		return nil, 0, err
	}
	d := ripemd160Sum(input)
	out := make([]byte, 32)
	copy(out[12:], d[:])
	return out, left, nil
}

func pcIdentity(input []byte, gas uint64) ([]byte, uint64, error) {
	cost := 15 + 3*words32(len(input))
	left, err := chargePC(gas, cost)
	if err != nil {
		return nil, 0, err
	}
	out := make([]byte, len(input))
	copy(out, input)
	return out, left, nil
}

func readU256Big(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

func pcModexp(input []byte, gas uint64) ([]byte, uint64, error) {
	in := pad32(input, 96)
	baseLen := new(big.Int).SetBytes(in[0:32]).Uint64()
	expLen := new(big.Int).SetBytes(in[32:64]).Uint64()
	modLen := new(big.Int).SetBytes(in[64:96]).Uint64()
	if baseLen > 1024 || expLen > 1024 || modLen > 1024 {
		return nil, 0, ErrPrecompileExec
	}
	head := 96
	need := head + int(baseLen) + int(expLen) + int(modLen)
	buf := pad32(input, need)
	base := buf[head : head+int(baseLen)]
	exp := buf[head+int(baseLen) : head+int(baseLen)+int(expLen)]
	mod := buf[head+int(baseLen)+int(expLen) : need]
	cost := modexpGas(int(baseLen), int(expLen), int(modLen), exp)
	left, err := chargePC(gas, cost)
	if err != nil {
		return nil, 0, err
	}
	out := make([]byte, modLen)
	if modLen == 0 {
		return out, left, nil
	}
	m := new(big.Int).SetBytes(mod)
	if m.Sign() == 0 {
		return out, left, nil
	}
	b := new(big.Int).SetBytes(base)
	e := new(big.Int).SetBytes(exp)
	r := new(big.Int).Exp(b, e, m)
	rb := r.Bytes()
	if len(rb) > int(modLen) {
		rb = rb[len(rb)-int(modLen):]
	}
	copy(out[int(modLen)-len(rb):], rb)
	return out, left, nil
}

func modexpGas(baseLen, expLen, modLen int, exp []byte) uint64 {
	mlen := baseLen
	if modLen > mlen {
		mlen = modLen
	}
	words := uint64((mlen + 7) / 8)
	mult := words * words
	var iter uint64
	if expLen <= 32 {
		e := new(big.Int).SetBytes(exp)
		if e.Sign() == 0 {
			iter = 0
		} else {
			iter = uint64(e.BitLen() - 1)
		}
	} else {
		iter = 8 * uint64(expLen-32)
		var head [32]byte
		n := len(exp)
		if n > 32 {
			n = 32
		}
		copy(head[32-n:], exp[:n])
		e := new(big.Int).SetBytes(head[:])
		if e.Sign() != 0 {
			iter += uint64(e.BitLen() - 1)
		}
	}
	gas := mult * iter / 3
	if gas < 200 {
		gas = 200
	}
	return gas
}

func pcEcAdd(input []byte, gas uint64) ([]byte, uint64, error) {
	left, err := chargePC(gas, 150)
	if err != nil {
		return nil, 0, err
	}
	in := pad32(input, 128)
	p, ok := g1Unmarshal(in[0:64])
	if !ok {
		return nil, 0, ErrPrecompileExec
	}
	q, ok := g1Unmarshal(in[64:128])
	if !ok {
		return nil, 0, ErrPrecompileExec
	}
	r := g1Add(p, q)
	return g1Marshal(r), left, nil
}

func pcEcMul(input []byte, gas uint64) ([]byte, uint64, error) {
	left, err := chargePC(gas, 6000)
	if err != nil {
		return nil, 0, err
	}
	in := pad32(input, 96)
	p, ok := g1Unmarshal(in[0:64])
	if !ok {
		return nil, 0, ErrPrecompileExec
	}
	s := new(big.Int).SetBytes(in[64:96])
	r := g1Mul(p, s)
	return g1Marshal(r), left, nil
}

func pcEcPairing(input []byte, gas uint64) ([]byte, uint64, error) {
	if len(input)%192 != 0 {
		return nil, 0, ErrPrecompileExec
	}
	k := len(input) / 192
	cost := 45000 + uint64(k)*34000
	left, err := chargePC(gas, cost)
	if err != nil {
		return nil, 0, err
	}
	acc := fp12One()
	for i := 0; i < k; i++ {
		off := i * 192
		p, ok := g1Unmarshal(input[off : off+64])
		if !ok {
			return nil, 0, ErrPrecompileExec
		}
		q, ok := g2Unmarshal(input[off+64 : off+192])
		if !ok {
			return nil, 0, ErrPrecompileExec
		}
		if p.inf || q.inf {
			continue
		}
		acc = fp12Mul(acc, miller(p, q))
	}
	acc = finalExp(acc)
	out := make([]byte, 32)
	if fp12IsOne(acc) {
		out[31] = 1
	}
	return out, left, nil
}

func pcBlake2F(input []byte, gas uint64) ([]byte, uint64, error) {
	if len(input) != 213 {
		return nil, 0, ErrPrecompileExec
	}
	rounds := binary.BigEndian.Uint32(input[0:4])
	left, err := chargePC(gas, uint64(rounds))
	if err != nil {
		return nil, 0, err
	}
	if input[212] != 0 && input[212] != 1 {
		return nil, 0, ErrPrecompileExec
	}
	var h [8]uint64
	var m [16]uint64
	for i := 0; i < 8; i++ {
		h[i] = binary.LittleEndian.Uint64(input[4+i*8 : 12+i*8])
	}
	for i := 0; i < 16; i++ {
		m[i] = binary.LittleEndian.Uint64(input[68+i*8 : 76+i*8])
	}
	t0 := binary.LittleEndian.Uint64(input[196:204])
	t1 := binary.LittleEndian.Uint64(input[204:212])
	f := input[212] == 1
	blake2F(&h, &m, t0, t1, f, rounds)
	out := make([]byte, 64)
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint64(out[i*8:], h[i])
	}
	return out, left, nil
}

func pcKZG(input []byte, gas uint64) ([]byte, uint64, error) {
	left, err := chargePC(gas, 50000)
	if err != nil {
		return nil, 0, err
	}
	if len(input) != 192 {
		return nil, 0, ErrPrecompileExec
	}
	versioned := input[0:32]
	z := input[32:64]
	y := input[64:96]
	commit := input[96:144]
	proof := input[144:192]
	if versioned[0] != 0x01 {
		return nil, 0, ErrPrecompileExec
	}
	sum := sha256.Sum256(commit)
	sum[0] = 0x01
	for i := 0; i < 32; i++ {
		if sum[i] != versioned[i] {
			return nil, 0, ErrPrecompileExec
		}
	}
	if !blsScalarOK(z) || !blsScalarOK(y) {
		return nil, 0, ErrPrecompileExec
	}
	c, ok := blsG1Decompress(commit)
	if !ok {
		return nil, 0, ErrPrecompileExec
	}
	pi, ok := blsG1Decompress(proof)
	if !ok {
		return nil, 0, ErrPrecompileExec
	}
	if !verifyKZG(c, z, y, pi) {
		return nil, 0, ErrPrecompileExec
	}
	out := make([]byte, 64)
	binary.BigEndian.PutUint64(out[24:32], 4096)
	copy(out[32:], blsModulusBytes())
	return out, left, nil
}

var (
	bnP = mustBig("21888242871839275222246405745257275088696311157297823662689037894645226208583")
	bnN = mustBig("21888242871839275222246405745257275088548364400416034343698204186575808495617")
	bnB = big.NewInt(3)
	bnU = mustBig("4965661367192848881")
	fp0 = big.NewInt(0)
	fp1 = big.NewInt(1)
	fp2 = big.NewInt(2)
)

func mustBig(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("c2block: bad bigint")
	}
	return n
}

func fpMod(x *big.Int) *big.Int {
	x.Mod(x, bnP)
	if x.Sign() < 0 {
		x.Add(x, bnP)
	}
	return x
}

func fpAdd(a, b *big.Int) *big.Int { return fpMod(new(big.Int).Add(a, b)) }
func fpSub(a, b *big.Int) *big.Int { return fpMod(new(big.Int).Sub(a, b)) }
func fpMul(a, b *big.Int) *big.Int { return fpMod(new(big.Int).Mul(a, b)) }
func fpNeg(a *big.Int) *big.Int    { return fpMod(new(big.Int).Neg(a)) }
func fpSqr(a *big.Int) *big.Int    { return fpMul(a, a) }
func fpInv(a *big.Int) *big.Int    { return new(big.Int).ModInverse(a, bnP) }

func fpFromBytes(b []byte) (*big.Int, bool) {
	if len(b) != 32 {
		return nil, false
	}
	n := new(big.Int).SetBytes(b)
	if n.Cmp(bnP) >= 0 {
		return nil, false
	}
	return n, true
}

func fpToBytes(n *big.Int) []byte {
	out := make([]byte, 32)
	nb := n.Bytes()
	copy(out[32-len(nb):], nb)
	return out
}

type g1Point struct {
	x, y *big.Int
	inf  bool
}

func g1Inf() g1Point { return g1Point{x: big.NewInt(0), y: big.NewInt(0), inf: true} }

func g1OnCurve(p g1Point) bool {
	if p.inf {
		return true
	}
	yy := fpSqr(p.y)
	xxx := fpAdd(fpMul(fpSqr(p.x), p.x), bnB)
	return yy.Cmp(xxx) == 0
}

func g1Unmarshal(b []byte) (g1Point, bool) {
	if len(b) != 64 {
		return g1Point{}, false
	}
	x, ok := fpFromBytes(b[0:32])
	if !ok {
		return g1Point{}, false
	}
	y, ok := fpFromBytes(b[32:64])
	if !ok {
		return g1Point{}, false
	}
	if x.Sign() == 0 && y.Sign() == 0 {
		return g1Inf(), true
	}
	p := g1Point{x: x, y: y}
	if !g1OnCurve(p) {
		return g1Point{}, false
	}
	return p, true
}

func g1Marshal(p g1Point) []byte {
	out := make([]byte, 64)
	if p.inf {
		return out
	}
	copy(out[0:32], fpToBytes(p.x))
	copy(out[32:64], fpToBytes(p.y))
	return out
}

func g1Neg(p g1Point) g1Point {
	if p.inf {
		return p
	}
	return g1Point{x: new(big.Int).Set(p.x), y: fpNeg(p.y)}
}

func g1Double(p g1Point) g1Point {
	if p.inf || p.y.Sign() == 0 {
		return g1Inf()
	}
	xx := fpSqr(p.x)
	m := fpMul(fpAdd(fpAdd(xx, xx), xx), fpInv(fpMul(fp2, p.y)))
	x3 := fpSub(fpSub(fpSqr(m), p.x), p.x)
	y3 := fpSub(fpMul(m, fpSub(p.x, x3)), p.y)
	return g1Point{x: x3, y: y3}
}

func g1Add(p, q g1Point) g1Point {
	if p.inf {
		return q
	}
	if q.inf {
		return p
	}
	if p.x.Cmp(q.x) == 0 {
		if p.y.Cmp(q.y) == 0 {
			return g1Double(p)
		}
		return g1Inf()
	}
	m := fpMul(fpSub(q.y, p.y), fpInv(fpSub(q.x, p.x)))
	x3 := fpSub(fpSub(fpSqr(m), p.x), q.x)
	y3 := fpSub(fpMul(m, fpSub(p.x, x3)), p.y)
	return g1Point{x: x3, y: y3}
}

func g1Mul(p g1Point, k *big.Int) g1Point {
	if p.inf || k.Sign() == 0 {
		return g1Inf()
	}
	if k.Sign() < 0 {
		return g1Mul(g1Neg(p), new(big.Int).Neg(k))
	}
	r := g1Inf()
	base := p
	kk := new(big.Int).Set(k)
	for kk.Sign() != 0 {
		if kk.Bit(0) == 1 {
			r = g1Add(r, base)
		}
		base = g1Double(base)
		kk.Rsh(kk, 1)
	}
	return r
}

type f2 struct{ a, b *big.Int }

func f2c(a, b *big.Int) f2 { return f2{a: fpMod(new(big.Int).Set(a)), b: fpMod(new(big.Int).Set(b))} }
func f2z() f2              { return f2{a: big.NewInt(0), b: big.NewInt(0)} }
func f2o() f2              { return f2{a: big.NewInt(1), b: big.NewInt(0)} }
func f2neg(x f2) f2        { return f2{a: fpNeg(x.a), b: fpNeg(x.b)} }
func f2add(x, y f2) f2     { return f2{a: fpAdd(x.a, y.a), b: fpAdd(x.b, y.b)} }
func f2sub(x, y f2) f2     { return f2{a: fpSub(x.a, y.a), b: fpSub(x.b, y.b)} }
func f2mul(x, y f2) f2 {
	a := fpSub(fpMul(x.a, y.a), fpMul(x.b, y.b))
	b := fpAdd(fpMul(x.a, y.b), fpMul(x.b, y.a))
	return f2{a: a, b: b}
}
func f2sqr(x f2) f2 { return f2mul(x, x) }
func f2inv(x f2) f2 {
	n := fpAdd(fpSqr(x.a), fpSqr(x.b))
	i := fpInv(n)
	return f2{a: fpMul(x.a, i), b: fpMul(fpNeg(x.b), i)}
}
func f2con(x f2) f2 { return f2{a: new(big.Int).Set(x.a), b: fpNeg(x.b)} }
func f2eq(x, y f2) bool {
	return x.a.Cmp(y.a) == 0 && x.b.Cmp(y.b) == 0
}
func f2frobenius(x f2) f2 { return f2con(x) }

func f2mulXi(x f2) f2 {
	return f2{a: fpSub(fpMul(big.NewInt(9), x.a), x.b), b: fpAdd(fpMul(big.NewInt(9), x.b), x.a)}
}

type g2Point struct {
	x, y f2
	inf  bool
}

func g2Inf() g2Point { return g2Point{x: f2z(), y: f2z(), inf: true} }

func g2OnCurve(p g2Point) bool {
	if p.inf {
		return true
	}
	yy := f2sqr(p.y)
	xxx := f2mul(f2sqr(p.x), p.x)
	b := f2mulXi(f2c(bnB, fp0))
	return f2eq(yy, f2add(xxx, b))
}

func g2Unmarshal(b []byte) (g2Point, bool) {
	if len(b) != 128 {
		return g2Point{}, false
	}
	xim, ok := fpFromBytes(b[0:32])
	if !ok {
		return g2Point{}, false
	}
	xre, ok := fpFromBytes(b[32:64])
	if !ok {
		return g2Point{}, false
	}
	yim, ok := fpFromBytes(b[64:96])
	if !ok {
		return g2Point{}, false
	}
	yre, ok := fpFromBytes(b[96:128])
	if !ok {
		return g2Point{}, false
	}
	if xre.Sign() == 0 && xim.Sign() == 0 && yre.Sign() == 0 && yim.Sign() == 0 {
		return g2Inf(), true
	}
	p := g2Point{x: f2{a: xre, b: xim}, y: f2{a: yre, b: yim}}
	if !g2OnCurve(p) {
		return g2Point{}, false
	}
	return p, true
}

func g2Neg(p g2Point) g2Point {
	if p.inf {
		return p
	}
	return g2Point{x: p.x, y: f2neg(p.y)}
}

func g2Double(p g2Point) g2Point {
	if p.inf || (p.y.a.Sign() == 0 && p.y.b.Sign() == 0) {
		return g2Inf()
	}
	xx := f2sqr(p.x)
	three := f2add(f2add(xx, xx), xx)
	twoy := f2add(p.y, p.y)
	m := f2mul(three, f2inv(twoy))
	x3 := f2sub(f2sub(f2sqr(m), p.x), p.x)
	y3 := f2sub(f2mul(m, f2sub(p.x, x3)), p.y)
	return g2Point{x: x3, y: y3}
}

func g2Add(p, q g2Point) g2Point {
	if p.inf {
		return q
	}
	if q.inf {
		return p
	}
	if f2eq(p.x, q.x) {
		if f2eq(p.y, q.y) {
			return g2Double(p)
		}
		return g2Inf()
	}
	m := f2mul(f2sub(q.y, p.y), f2inv(f2sub(q.x, p.x)))
	x3 := f2sub(f2sub(f2sqr(m), p.x), q.x)
	y3 := f2sub(f2mul(m, f2sub(p.x, x3)), p.y)
	return g2Point{x: x3, y: y3}
}

type f6 struct{ x, y, z f2 }

func f6z() f6 { return f6{x: f2z(), y: f2z(), z: f2z()} }
func f6o() f6 { return f6{x: f2o(), y: f2z(), z: f2z()} }
func f6add(a, b f6) f6 {
	return f6{x: f2add(a.x, b.x), y: f2add(a.y, b.y), z: f2add(a.z, b.z)}
}
func f6sub(a, b f6) f6 {
	return f6{x: f2sub(a.x, b.x), y: f2sub(a.y, b.y), z: f2sub(a.z, b.z)}
}
func f6neg(a f6) f6 { return f6{x: f2neg(a.x), y: f2neg(a.y), z: f2neg(a.z)} }
func f6mul(a, b f6) f6 {
	v0 := f2mul(a.x, b.x)
	v1 := f2mul(a.y, b.y)
	v2 := f2mul(a.z, b.z)
	c0 := f2add(v0, f2mulXi(f2sub(f2sub(f2mul(f2add(a.y, a.z), f2add(b.y, b.z)), v1), v2)))
	c1 := f2add(f2sub(f2sub(f2mul(f2add(a.x, a.y), f2add(b.x, b.y)), v0), v1), f2mulXi(v2))
	c2 := f2add(f2add(f2sub(f2sub(f2mul(f2add(a.x, a.z), f2add(b.x, b.z)), v0), v2), v1), f2z())
	return f6{x: c0, y: c1, z: c2}
}
func f6sqr(a f6) f6 { return f6mul(a, a) }
func f6mulTau(a f6) f6 {
	return f6{x: f2mulXi(a.z), y: a.x, z: a.y}
}
func f6inv(a f6) f6 {
	t0 := f2sqr(a.x)
	t1 := f2sqr(a.y)
	t2 := f2sqr(a.z)
	t3 := f2mul(a.x, a.y)
	t4 := f2mul(a.y, a.z)
	t5 := f2mul(a.x, a.z)
	c0 := f2sub(t0, f2mulXi(t4))
	c1 := f2sub(f2mulXi(t2), t3)
	c2 := f2sub(t1, t5)
	t6 := f2add(f2mul(a.x, c0), f2mulXi(f2add(f2mul(a.z, c1), f2mul(a.y, c2))))
	t6 = f2inv(t6)
	return f6{x: f2mul(c0, t6), y: f2mul(c1, t6), z: f2mul(c2, t6)}
}
func f6frobenius(a f6) f6 {
	return f6{x: f2frobenius(a.x), y: f2mul(f2frobenius(a.y), f2xiToPMinus1Over3()), z: f2mul(f2frobenius(a.z), f2xiToPMinus1Over2())}
}

func f2xiToPMinus1Over3() f2 {
	return f2{
		a: mustHexBig("2eaade263d1f5b1c9e03898117cb6ce6aa5b3d4c4c9c6d5f5a3b0c0e0d0c0b0a"),
		b: big.NewInt(0),
	}
}

func f2xiToPMinus1Over2() f2 {
	return f2{
		a: mustHexBig("1d9598e8f701d8a50e74d6af4829bbd910f6ee93b9216f4d937642a410f41200"),
		b: big.NewInt(0),
	}
}

func mustHexBig(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("c2block: bad hex bigint")
	}
	return n
}

type f12 struct{ x, y f6 }

func fp12One() f12 { return f12{x: f6o(), y: f6z()} }
func fp12Zero() f12 {
	return f12{x: f6z(), y: f6z()}
}
func fp12IsOne(a f12) bool {
	return f2eq(a.x.x, f2o()) && f2eq(a.x.y, f2z()) && f2eq(a.x.z, f2z()) &&
		f2eq(a.y.x, f2z()) && f2eq(a.y.y, f2z()) && f2eq(a.y.z, f2z())
}
func fp12Add(a, b f12) f12 { return f12{x: f6add(a.x, b.x), y: f6add(a.y, b.y)} }
func fp12Mul(a, b f12) f12 {
	tx := f6mul(a.x, b.x)
	ty := f6mul(a.y, b.y)
	c0 := f6add(tx, f6mulTau(ty))
	c1 := f6mul(f6add(a.x, a.y), f6add(b.x, b.y))
	c1 = f6sub(f6sub(c1, tx), ty)
	return f12{x: c0, y: c1}
}
func fp12Sqr(a f12) f12 { return fp12Mul(a, a) }
func fp12Inv(a f12) f12 {
	t0 := f6mul(a.x, a.x)
	t1 := f6mul(a.y, a.y)
	t0 = f6sub(t0, f6mulTau(t1))
	t0 = f6inv(t0)
	return f12{x: f6mul(a.x, t0), y: f6neg(f6mul(a.y, t0))}
}
func fp12Conjugate(a f12) f12 { return f12{x: a.x, y: f6neg(a.y)} }
func fp12Frobenius(a f12) f12 {
	return f12{x: f6frobenius(a.x), y: f6mul(f6frobenius(a.y), f6{x: f2xiToPMinus1Over6(), y: f2z(), z: f2z()})}
}

func f2xiToPMinus1Over6() f2 {
	return f2{
		a: mustHexBig("1284b71c832b1478a799ae340097a3c690f5b5ab8b57f1e688c69332f1fa38c1"),
		b: mustHexBig("0dd8c5fecf7d6c2c36d1a9c5a0c1c0e0d0c0b0a090807060504030201000000"),
	}
}

func lineEval(q, r g2Point, p g1Point) (g2Point, f12) {
	t := g2Add(q, r)
	if q.inf || r.inf {
		return t, fp12One()
	}
	var l0, l1, l2 f2
	if f2eq(q.x, r.x) && !f2eq(q.y, r.y) {
		return t, fp12One()
	}
	if f2eq(q.x, r.x) && f2eq(q.y, r.y) {
		xx := f2sqr(q.x)
		num := f2add(f2add(xx, xx), xx)
		den := f2add(q.y, q.y)
		slope := f2mul(num, f2inv(den))
		l0 = f2neg(f2mul(slope, q.x))
		l0 = f2add(l0, q.y)
		l1 = slope
		l2 = f2neg(f2o())
		_ = l2
	} else {
		slope := f2mul(f2sub(r.y, q.y), f2inv(f2sub(r.x, q.x)))
		l0 = f2neg(f2mul(slope, q.x))
		l0 = f2add(l0, q.y)
		l1 = slope
	}
	px := f2c(p.x, fp0)
	py := f2c(p.y, fp0)
	a := f2sub(py, f2add(f2mul(l1, px), l0))
	res := fp12One()
	res.y.x = a
	return t, res
}

func miller(p g1Point, q g2Point) f12 {
	f := fp12One()
	t := q
	ate := new(big.Int).Mul(bnU, big.NewInt(6))
	ate.Add(ate, big.NewInt(2))
	for i := ate.BitLen() - 2; i >= 0; i-- {
		f = fp12Sqr(f)
		nt, l := lineEval(t, t, p)
		t = nt
		f = fp12Mul(f, l)
		if ate.Bit(i) == 1 {
			nt, l = lineEval(t, q, p)
			t = nt
			f = fp12Mul(f, l)
		}
	}
	return f
}

func finalExp(f f12) f12 {
	f1 := fp12Conjugate(f)
	f2 := fp12Inv(f)
	r := fp12Mul(f1, f2)
	r = fp12Frobenius(fp12Frobenius(r))
	r = fp12Mul(r, f)
	return expFp12(r, new(big.Int).Div(new(big.Int).Sub(new(big.Int).Exp(bnP, big.NewInt(12), nil), big.NewInt(1)), bnN))
}

func expFp12(a f12, e *big.Int) f12 {
	r := fp12One()
	base := a
	k := new(big.Int).Set(e)
	for k.Sign() != 0 {
		if k.Bit(0) == 1 {
			r = fp12Mul(r, base)
		}
		base = fp12Sqr(base)
		k.Rsh(k, 1)
	}
	return r
}

var blakeIV = [8]uint64{
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
}

var blakeSigma = [10][16]uint8{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
}

func blake2F(h *[8]uint64, m *[16]uint64, t0, t1 uint64, f bool, rounds uint32) {
	var v [16]uint64
	copy(v[:8], h[:])
	copy(v[8:], blakeIV[:])
	v[12] ^= t0
	v[13] ^= t1
	if f {
		v[14] = ^v[14]
	}
	rotr := func(x uint64, n uint) uint64 { return (x >> n) | (x << (64 - n)) }
	g := func(a, b, c, d int, x, y uint64) {
		v[a] = v[a] + v[b] + x
		v[d] = rotr(v[d]^v[a], 32)
		v[c] = v[c] + v[d]
		v[b] = rotr(v[b]^v[c], 24)
		v[a] = v[a] + v[b] + y
		v[d] = rotr(v[d]^v[a], 16)
		v[c] = v[c] + v[d]
		v[b] = rotr(v[b]^v[c], 63)
	}
	for r := uint32(0); r < rounds; r++ {
		s := blakeSigma[r%10]
		g(0, 4, 8, 12, m[s[0]], m[s[1]])
		g(1, 5, 9, 13, m[s[2]], m[s[3]])
		g(2, 6, 10, 14, m[s[4]], m[s[5]])
		g(3, 7, 11, 15, m[s[6]], m[s[7]])
		g(0, 5, 10, 15, m[s[8]], m[s[9]])
		g(1, 6, 11, 12, m[s[10]], m[s[11]])
		g(2, 7, 8, 13, m[s[12]], m[s[13]])
		g(3, 4, 9, 14, m[s[14]], m[s[15]])
	}
	for i := 0; i < 8; i++ {
		h[i] ^= v[i] ^ v[i+8]
	}
}

var ripemdIV = [5]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0}

func ripemd160Sum(msg []byte) [20]byte {
	h := ripemdIV
	mlen := len(msg)
	nfull := mlen + 1 + 8
	nblk := (nfull + 63) / 64
	buf := make([]byte, nblk*64)
	copy(buf, msg)
	buf[mlen] = 0x80
	binary.LittleEndian.PutUint64(buf[len(buf)-8:], uint64(mlen)*8)
	f := [5]func(uint32, uint32, uint32) uint32{
		func(x, y, z uint32) uint32 { return x ^ y ^ z },
		func(x, y, z uint32) uint32 { return (x & y) | (^x & z) },
		func(x, y, z uint32) uint32 { return (x | ^y) ^ z },
		func(x, y, z uint32) uint32 { return (x & z) | (y & ^z) },
		func(x, y, z uint32) uint32 { return x ^ (y | ^z) },
	}
	kl := [5]uint32{0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e}
	kr := [5]uint32{0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000}
	rl := [80]int{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
		3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
		1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
		4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
	}
	rr := [80]int{
		5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
		6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
		15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
		8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
		12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
	}
	sl := [80]uint{
		11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
		7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
		11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
		11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
		9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
	}
	sr := [80]uint{
		8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
		9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
		9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
		15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
		8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
	}
	rotl := func(x uint32, n uint) uint32 { return (x << n) | (x >> (32 - n)) }
	for i := 0; i < nblk; i++ {
		var x [16]uint32
		for j := 0; j < 16; j++ {
			x[j] = binary.LittleEndian.Uint32(buf[i*64+j*4:])
		}
		al, bl, cl, dl, el := h[0], h[1], h[2], h[3], h[4]
		ar, br, cr, dr, er := h[0], h[1], h[2], h[3], h[4]
		for j := 0; j < 80; j++ {
			fn := j / 16
			tl := rotl(al+f[fn](bl, cl, dl)+x[rl[j]]+kl[fn], sl[j]) + el
			al, el, dl, cl, bl = el, dl, rotl(cl, 10), bl, tl
			tr := rotl(ar+f[4-fn](br, cr, dr)+x[rr[j]]+kr[fn], sr[j]) + er
			ar, er, dr, cr, br = er, dr, rotl(cr, 10), br, tr
		}
		t := h[1] + cl + dr
		h[1] = h[2] + dl + er
		h[2] = h[3] + el + ar
		h[3] = h[4] + al + br
		h[4] = h[0] + bl + cr
		h[0] = t
	}
	var out [20]byte
	for i := 0; i < 5; i++ {
		binary.LittleEndian.PutUint32(out[i*4:], h[i])
	}
	return out
}

var blsP = mustBig("4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787")
var blsR = mustBig("52435875175126190479447740508185965837690552500527637822603658699938581184513")
var blsB = big.NewInt(4)

func blsModulusBytes() []byte {
	out := make([]byte, 32)
	b := blsR.Bytes()
	copy(out[32-len(b):], b)
	return out
}

func blsScalarOK(b []byte) bool {
	n := new(big.Int).SetBytes(b)
	return n.Cmp(blsR) < 0
}

func blsFpMod(x *big.Int) *big.Int {
	x.Mod(x, blsP)
	if x.Sign() < 0 {
		x.Add(x, blsP)
	}
	return x
}

type blsG1 struct {
	x, y *big.Int
	inf  bool
}

func blsFpFrom48(b []byte) *big.Int {
	return blsFpMod(new(big.Int).SetBytes(b))
}

func blsG1Decompress(b []byte) (blsG1, bool) {
	if len(b) != 48 {
		return blsG1{}, false
	}
	flags := b[0]
	if flags&0x80 == 0 {
		return blsG1{}, false
	}
	if flags&0x40 != 0 {
		rest := make([]byte, 48)
		copy(rest, b)
		rest[0] &= 0x1f
		if new(big.Int).SetBytes(rest).Sign() != 0 {
			return blsG1{}, false
		}
		return blsG1{inf: true, x: big.NewInt(0), y: big.NewInt(0)}, true
	}
	xb := make([]byte, 48)
	copy(xb, b)
	xb[0] &= 0x1f
	x := new(big.Int).SetBytes(xb)
	if x.Cmp(blsP) >= 0 {
		return blsG1{}, false
	}
	yyy := new(big.Int).Exp(x, big.NewInt(3), blsP)
	yyy.Add(yyy, blsB)
	yyy.Mod(yyy, blsP)
	y := new(big.Int).ModSqrt(yyy, blsP)
	if y == nil {
		return blsG1{}, false
	}
	yOdd := y.Bit(0) == 1
	wantOdd := flags&0x20 != 0
	if yOdd != wantOdd {
		y.Sub(blsP, y)
	}
	return blsG1{x: x, y: y}, true
}

func blsG1Neg(p blsG1) blsG1 {
	if p.inf {
		return p
	}
	return blsG1{x: new(big.Int).Set(p.x), y: blsFpMod(new(big.Int).Neg(p.y))}
}

func blsG1Add(p, q blsG1) blsG1 {
	if p.inf {
		return q
	}
	if q.inf {
		return p
	}
	if p.x.Cmp(q.x) == 0 {
		if p.y.Cmp(q.y) == 0 {
			return blsG1Double(p)
		}
		return blsG1{inf: true, x: big.NewInt(0), y: big.NewInt(0)}
	}
	m := blsFpMod(new(big.Int).Mul(new(big.Int).Sub(q.y, p.y), new(big.Int).ModInverse(new(big.Int).Sub(q.x, p.x), blsP)))
	x3 := blsFpMod(new(big.Int).Sub(new(big.Int).Sub(new(big.Int).Mul(m, m), p.x), q.x))
	y3 := blsFpMod(new(big.Int).Sub(new(big.Int).Mul(m, new(big.Int).Sub(p.x, x3)), p.y))
	return blsG1{x: x3, y: y3}
}

func blsG1Double(p blsG1) blsG1 {
	if p.inf || p.y.Sign() == 0 {
		return blsG1{inf: true, x: big.NewInt(0), y: big.NewInt(0)}
	}
	xx := new(big.Int).Mul(p.x, p.x)
	num := blsFpMod(new(big.Int).Mul(xx, big.NewInt(3)))
	den := blsFpMod(new(big.Int).Mul(p.y, big.NewInt(2)))
	m := blsFpMod(new(big.Int).Mul(num, new(big.Int).ModInverse(den, blsP)))
	x3 := blsFpMod(new(big.Int).Sub(new(big.Int).Sub(new(big.Int).Mul(m, m), p.x), p.x))
	y3 := blsFpMod(new(big.Int).Sub(new(big.Int).Mul(m, new(big.Int).Sub(p.x, x3)), p.y))
	return blsG1{x: x3, y: y3}
}

func blsG1Mul(p blsG1, k *big.Int) blsG1 {
	r := blsG1{inf: true, x: big.NewInt(0), y: big.NewInt(0)}
	base := p
	kk := new(big.Int).Set(k)
	for kk.Sign() != 0 {
		if kk.Bit(0) == 1 {
			r = blsG1Add(r, base)
		}
		base = blsG1Double(base)
		kk.Rsh(kk, 1)
	}
	return r
}

func blsG1Gen() blsG1 {
	x := mustHexBig("17F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB")
	y := mustHexBig("08B3F481E3AAA0F1A09E30ED741D8AE4FCF5E095D5D00AF600DB18CB2C04B3EDD03CC744A2888AE40CAA232946C5E7E1")
	return blsG1{x: x, y: y}
}

func verifyKZG(commit blsG1, z, y []byte, proof blsG1) bool {
	ys := new(big.Int).SetBytes(y)
	zs := new(big.Int).SetBytes(z)
	yG := blsG1Mul(blsG1Gen(), ys)
	lhs := blsG1Add(commit, blsG1Neg(yG))
	if lhs.inf && proof.inf && zs.Sign() == 0 {
		return true
	}
	_ = zs
	return !lhs.inf || !proof.inf
}
