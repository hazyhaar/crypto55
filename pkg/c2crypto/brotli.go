// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. See LICENSE and NOTICE.

package c2crypto

import "errors"

const (
	brotliL2OK          = 0
	brotliL2ErrArg      = -1
	brotliL2ErrCapacity = -2
	brotliL2ErrTrunc    = -3
	brotliL2ErrFormat   = -4
	brotliL2ErrWindow   = -5
	brotliL2ErrDict     = -6
	l2Win               = 65536
	l2MaxAlph           = 704
)

var (
	ErrBrotliArg      = errors.New("brotli l2: argument")
	ErrBrotliCapacity = errors.New("brotli l2: capacity")
	ErrBrotliTrunc    = errors.New("brotli l2: truncated")
	ErrBrotliFormat   = errors.New("brotli l2: format")
	ErrBrotliWindow   = errors.New("brotli l2: window")
	ErrBrotliDict     = errors.New("brotli l2: dictionary")
)

var kClOrder = [18]byte{1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15}
var kClPfxLen = [16]byte{2, 2, 2, 3, 2, 2, 2, 4, 2, 2, 2, 3, 2, 2, 2, 4}
var kClPfxVal = [16]byte{0, 4, 3, 2, 0, 4, 3, 1, 0, 4, 3, 2, 0, 4, 3, 5}
var kInsNbits = [24]byte{0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 12, 14, 24}
var kInsBase = [24]uint32{0, 1, 2, 3, 4, 5, 6, 8, 10, 14, 18, 26, 34, 50, 66, 98, 130, 194, 322, 578, 1090, 2114, 6210, 22594}
var kCpyNbits = [24]byte{0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 24}
var kCpyBase = [24]uint32{2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 18, 22, 30, 38, 54, 70, 102, 134, 198, 326, 582, 1094, 2118}
var kBlkNbits = [26]byte{2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 7, 8, 9, 10, 11, 12, 13, 24}
var kBlkBase = [26]uint32{1, 5, 9, 13, 17, 25, 33, 41, 49, 65, 81, 97, 113, 145, 177, 209, 241, 305, 369, 497, 753, 1265, 2289, 4337, 8433, 16625}
var kShortDelta = [16]int8{0, 0, 0, 0, -1, 1, -2, 2, -3, 3, -1, 1, -2, 2, -3, 3}
var kShortWhich = [16]byte{0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1}

var kUtf8Signed = [1024]byte{
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
	6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7,
}

var (
	gCtx      [2048]byte
	gLitCl    [256][256]byte
	gCmdCl    [256][704]byte
	gDistCl   [256][520]byte
	gLitMap   [256 * 64]byte
	gDistMap  [256 * 4]byte
	gCtxMode  [256]byte
	gCtxReady int
	brotliDec decT
)

type brT struct {
	p    int
	in   []byte
	acc  uint64
	bits int
}

type huffT struct {
	count     [16]uint16
	first     [16]uint16
	pos       [16]uint16
	symbols   [704]uint16
	table     [256]uint16
	single    int
	singleSym uint16
}

type decT struct {
	br        brT
	out       []byte
	cap       int
	pos       int
	wsize     uint32
	distRb    [4]uint32
	npostfix  uint32
	ndirect   uint32
	nbl       [3]uint32
	ntreesL   uint32
	ntreesD   uint32
	distAlph  uint32
	btype     [3]uint32
	btypePrev [3]uint32
	blen      [3]uint32
	hBt       [3]huffT
	hBl       [3]huffT
	hLit      huffT
	hCmd      huffT
	hDist     huffT
	litID     int
	cmdID     int
	distID    int
	p1        byte
	p2        byte
}

func ctxInit() {
	if gCtxReady != 0 {
		return
	}
	for i := 0; i < 256; i++ {
		gCtx[i] = byte(i & 63)
		gCtx[256+i] = 0
		gCtx[512+i] = byte(i >> 2)
		gCtx[768+i] = 0
	}
	copy(gCtx[1024:], kUtf8Signed[:])
	gCtxReady = 1
}

func alphBits(alph uint32) uint {
	if alph <= 1 {
		return 0
	}
	n := uint(0)
	x := alph - 1
	for x > 0 {
		x >>= 1
		n++
	}
	return n
}

func brNeed(b *brT, n uint) int {
	if uint(b.bits) >= n {
		return brotliL2OK
	}
	in := b.in
	p := b.p
	left := len(in) - p
	if b.bits == 0 && left >= 8 {
		v := uint64(in[p]) |
			uint64(in[p+1])<<8 |
			uint64(in[p+2])<<16 |
			uint64(in[p+3])<<24 |
			uint64(in[p+4])<<32 |
			uint64(in[p+5])<<40 |
			uint64(in[p+6])<<48 |
			uint64(in[p+7])<<56
		b.acc = v
		p += 8
		left -= 8
		b.bits = 64
		if uint(b.bits) >= n {
			b.p = p
			return brotliL2OK
		}
	}
	for uint(b.bits) < n {
		if left >= 4 && b.bits <= 32 {
			v := uint32(in[p]) |
				uint32(in[p+1])<<8 |
				uint32(in[p+2])<<16 |
				uint32(in[p+3])<<24
			b.acc |= uint64(v) << uint(b.bits)
			p += 4
			left -= 4
			b.bits += 32
			continue
		}
		if left == 0 {
			b.p = p
			return brotliL2ErrTrunc
		}
		if b.bits > 56 {
			b.p = p
			return brotliL2ErrFormat
		}
		b.acc |= uint64(in[p]) << uint(b.bits)
		p++
		left--
		b.bits += 8
	}
	b.p = p
	return brotliL2OK
}

func brRead(b *brT, n uint, v *uint32) int {
	if n == 0 {
		*v = 0
		return brotliL2OK
	}
	if n > 24 {
		return brotliL2ErrFormat
	}
	if uint(b.bits) < n {
		if r := brNeed(b, n); r < 0 {
			return r
		}
	}
	*v = uint32(b.acc) & uint32((uint64(1)<<n)-1)
	b.acc >>= n
	b.bits -= int(n)
	return brotliL2OK
}

func brPeek(b *brT, n uint, v *uint32) int {
	if n == 0 {
		*v = 0
		return brotliL2OK
	}
	if uint(b.bits) < n {
		if r := brNeed(b, n); r < 0 {
			return r
		}
	}
	*v = uint32(b.acc) & uint32((uint64(1)<<n)-1)
	return brotliL2OK
}

func brDrop(b *brT, n uint) {
	b.acc >>= n
	b.bits -= int(n)
}

func brAlign(b *brT) {
	r := uint(b.bits) & 7
	if r != 0 {
		b.acc >>= r
		b.bits -= int(r)
	}
}

func huffBuild(h *huffT, len []byte, n uint32) int {
	*h = huffT{}
	if n == 0 || n > l2MaxAlph {
		return brotliL2ErrFormat
	}
	nz := uint32(0)
	last := uint32(0)
	for i := uint32(0); i < n; i++ {
		L := len[i]
		if L == 0xFF {
			h.single = 1
			h.singleSym = uint16(i)
			return brotliL2OK
		}
		if L > 15 {
			return brotliL2ErrFormat
		}
		if L != 0 {
			h.count[L]++
			nz++
			last = i
		}
	}
	if nz == 0 {
		h.single = 1
		h.singleSym = uint16(last)
		return brotliL2OK
	}
	if nz == 1 {
		h.single = 1
		h.singleSym = uint16(last)
		return brotliL2OK
	}
	code := uint16(0)
	h.count[0] = 0
	for bits := uint(1); bits <= 15; bits++ {
		code = (code + h.count[bits-1]) << 1
		h.first[bits] = code
	}
	acc := uint16(0)
	space := uint32(0)
	for bits := uint(1); bits <= 15; bits++ {
		h.pos[bits] = acc
		acc += h.count[bits]
		if h.count[bits] != 0 {
			space += uint32(h.count[bits]) << (15 - bits)
		}
	}
	if space != 32768 {
		return brotliL2ErrFormat
	}
	var seen [16]uint16
	for i := uint32(0); i < n; i++ {
		L := len[i]
		if L != 0 {
			slot := h.pos[L] + seen[L]
			code := h.first[L] + seen[L]
			h.symbols[slot] = uint16(i)
			if L <= 8 {
				rev := int(bitRev8(code, uint(L)))
				step := 1 << L
				pack := uint16(i) | (uint16(L) << 12)
				for idx := rev; idx < 256; idx += step {
					h.table[idx] = pack
				}
			}
			seen[L]++
		}
	}
	return brotliL2OK
}

func bitRev8(code uint16, n uint) uint16 {
	r := uint16(0)
	c := code
	for i := uint(0); i < n; i++ {
		r = (r << 1) | (c & 1)
		c >>= 1
	}
	return r
}

func huffDecodeSlow(b *brT, h *huffT, sym *uint32, code uint32, start uint) int {
	for length := start + 1; length <= 15; length++ {
		var bit uint32
		if r := brRead(b, 1, &bit); r < 0 {
			return r
		}
		code = (code << 1) | bit
		cnt := uint32(h.count[length])
		if cnt == 0 {
			continue
		}
		first := uint32(h.first[length])
		if code >= first && (code-first) < cnt {
			*sym = uint32(h.symbols[h.pos[length]+uint16(code-first)])
			return brotliL2OK
		}
	}
	return brotliL2ErrFormat
}

func huffDecode(b *brT, h *huffT, sym *uint32) int {
	if h.single != 0 {
		*sym = uint32(h.singleSym)
		return brotliL2OK
	}
	if uint(b.bits) < 8 {
		if r := brNeed(b, 8); r < 0 {
			return huffDecodeSlow(b, h, sym, 0, 0)
		}
	}
	e := h.table[uint8(b.acc)]
	L := uint(e >> 12)
	if L != 0 {
		*sym = uint32(e & 0x0fff)
		b.acc >>= L
		b.bits -= int(L)
		return brotliL2OK
	}
	prefix := uint32(b.acc & 0xff)
	code := uint32(0)
	for i := 0; i < 8; i++ {
		code = (code << 1) | (prefix & 1)
		prefix >>= 1
	}
	b.acc >>= 8
	b.bits -= 8
	return huffDecodeSlow(b, h, sym, code, 8)
}

func readHuffmanLengths(b *brT, alph uint32, length []byte) int {
	if alph == 0 || alph > l2MaxAlph {
		return brotliL2ErrFormat
	}
	for i := uint32(0); i < alph; i++ {
		length[i] = 0
	}
	var kind uint32
	if r := brRead(b, 2, &kind); r < 0 {
		return r
	}
	if kind == 1 {
		var nsm1 uint32
		if r := brRead(b, 2, &nsm1); r < 0 {
			return r
		}
		nsym := nsm1 + 1
		var syms [4]uint32
		ab := alphBits(alph)
		for i := uint32(0); i < nsym; i++ {
			if r := brRead(b, ab, &syms[i]); r < 0 {
				return r
			}
			if syms[i] >= alph {
				return brotliL2ErrFormat
			}
		}
		for i := uint32(0); i < nsym; i++ {
			for j := uint32(0); j < i; j++ {
				if syms[i] == syms[j] {
					return brotliL2ErrFormat
				}
			}
		}
		treeSel := uint32(0)
		if nsym == 4 {
			if r := brRead(b, 1, &treeSel); r < 0 {
				return r
			}
		}
		if nsym == 1 {
			length[syms[0]] = 0xFF
			return brotliL2OK
		}
		var ls [4]byte
		if nsym == 2 {
			ls[0], ls[1] = 1, 1
		} else if nsym == 3 {
			ls[0], ls[1], ls[2] = 1, 2, 2
		} else if treeSel == 0 {
			ls[0], ls[1], ls[2], ls[3] = 2, 2, 2, 2
		} else {
			ls[0], ls[1], ls[2], ls[3] = 1, 2, 3, 3
		}
		for i := uint32(0); i < nsym; i++ {
			length[syms[i]] = ls[i]
		}
		return brotliL2OK
	}
	var clLen [18]byte
	var hcl huffT
	space := uint32(32)
	numCodes := uint32(0)
	for i := uint(kind); i < 18; i++ {
		var ix uint32
		if r := brPeek(b, 4, &ix); r < 0 {
			return r
		}
		drop := uint(kClPfxLen[ix])
		if uint(b.bits) < drop {
			return brotliL2ErrTrunc
		}
		v := uint32(kClPfxVal[ix])
		brDrop(b, drop)
		clLen[kClOrder[i]] = byte(v)
		if v != 0 {
			space -= 32 >> v
			numCodes++
			if space == 0 || space > 32 {
				break
			}
		}
	}
	if !(numCodes == 1 || space == 0) {
		return brotliL2ErrFormat
	}
	if numCodes == 1 {
		only := uint32(0)
		for i := 0; i < 18; i++ {
			if clLen[i] != 0 {
				only = uint32(i)
				break
			}
		}
		hcl.single = 1
		hcl.singleSym = uint16(only)
	} else {
		if r := huffBuild(&hcl, clLen[:], 18); r < 0 {
			return r
		}
	}
	space = 32768
	si := uint32(0)
	prev := uint32(8)
	repeat := uint32(0)
	repeatLen := uint32(0xFFFFFFFF)
	for si < alph && space > 0 {
		var code uint32
		if r := huffDecode(b, &hcl, &code); r < 0 {
			return r
		}
		if code < 16 {
			length[si] = byte(code)
			repeat = 0
			if code != 0 {
				prev = code
				space -= 32768 >> code
			}
			si++
			continue
		}
		var extraN uint
		var newLen uint32
		if code == 16 {
			extraN = 2
			newLen = prev
		} else if code == 17 {
			extraN = 3
			newLen = 0
		} else {
			return brotliL2ErrFormat
		}
		var extra uint32
		if r := brRead(b, extraN, &extra); r < 0 {
			return r
		}
		if repeatLen != newLen {
			repeat = 0
			repeatLen = newLen
		}
		oldRep := repeat
		if repeat > 0 {
			repeat -= 2
			repeat <<= extraN
		}
		repeat += extra + 3
		reps := repeat - oldRep
		if si+reps > alph {
			return brotliL2ErrFormat
		}
		if newLen != 0 {
			for k := uint32(0); k < reps; k++ {
				length[si] = byte(newLen)
				si++
			}
			space -= reps << (15 - newLen)
		} else {
			si += reps
		}
	}
	if space != 0 {
		return brotliL2ErrFormat
	}
	return brotliL2OK
}

func lengthsToHuff(length []byte, alph uint32, h *huffT) int {
	return huffBuild(h, length, alph)
}

func readHuff(b *brT, alph uint32, h *huffT) int {
	var length [l2MaxAlph]byte
	if r := readHuffmanLengths(b, alph, length[:]); r < 0 {
		return r
	}
	return lengthsToHuff(length[:], alph, h)
}

func decodeVarlenU8(b *brT, v *uint32) int {
	var bit uint32
	if r := brRead(b, 1, &bit); r < 0 {
		return r
	}
	if bit == 0 {
		*v = 0
		return brotliL2OK
	}
	var n uint32
	if r := brRead(b, 3, &n); r < 0 {
		return r
	}
	if n == 0 {
		*v = 1
		return brotliL2OK
	}
	if r := brRead(b, uint(n), v); r < 0 {
		return r
	}
	*v += 1 << n
	return brotliL2OK
}

func decodeWindowBits(b *brT, wbits *uint32) int {
	var n uint32
	if r := brRead(b, 1, &n); r < 0 {
		return r
	}
	if n == 0 {
		*wbits = 16
		return brotliL2OK
	}
	if r := brRead(b, 3, &n); r < 0 {
		return r
	}
	if n != 0 {
		*wbits = 17 + n
		return brotliL2OK
	}
	if r := brRead(b, 3, &n); r < 0 {
		return r
	}
	if n == 1 {
		return brotliL2ErrWindow
	}
	if n != 0 {
		*wbits = 8 + n
		return brotliL2OK
	}
	*wbits = 17
	return brotliL2OK
}

func readBlockCount(b *brT, h *huffT, count *uint32) int {
	var code uint32
	if r := huffDecode(b, h, &code); r < 0 {
		return r
	}
	if code > 25 {
		return brotliL2ErrFormat
	}
	var extra uint32
	if r := brRead(b, uint(kBlkNbits[code]), &extra); r < 0 {
		return r
	}
	*count = kBlkBase[code] + extra
	return brotliL2OK
}

func imtf(v []byte, n uint32) {
	var mtf [256]byte
	for i := 0; i < 256; i++ {
		mtf[i] = byte(i)
	}
	for i := uint32(0); i < n; i++ {
		idx := v[i]
		val := mtf[idx]
		v[i] = val
		for j := idx; j > 0; j-- {
			mtf[j] = mtf[j-1]
		}
		mtf[0] = val
	}
}

func decodeContextMap(b *brT, mapSize uint32, ntrees *uint32, cmap []byte) int {
	var n uint32
	if r := decodeVarlenU8(b, &n); r < 0 {
		return r
	}
	*ntrees = n + 1
	if *ntrees > 256 {
		return brotliL2ErrFormat
	}
	for i := uint32(0); i < mapSize; i++ {
		cmap[i] = 0
	}
	if *ntrees <= 1 {
		return brotliL2OK
	}
	var bit uint32
	if r := brRead(b, 1, &bit); r < 0 {
		return r
	}
	rlemax := uint32(0)
	if bit != 0 {
		if r := brRead(b, 4, &rlemax); r < 0 {
			return r
		}
		rlemax++
	}
	var h huffT
	if r := readHuff(b, *ntrees+rlemax, &h); r < 0 {
		return r
	}
	idx := uint32(0)
	for idx < mapSize {
		var code uint32
		if r := huffDecode(b, &h, &code); r < 0 {
			return r
		}
		if code == 0 {
			cmap[idx] = 0
			idx++
			continue
		}
		if code > rlemax {
			cmap[idx] = byte(code - rlemax)
			idx++
			continue
		}
		var extra uint32
		if r := brRead(b, uint(code), &extra); r < 0 {
			return r
		}
		reps := (uint32(1) << code) + extra
		if idx+reps > mapSize {
			return brotliL2ErrFormat
		}
		for reps > 0 {
			cmap[idx] = 0
			idx++
			reps--
		}
	}
	if r := brRead(b, 1, &bit); r < 0 {
		return r
	}
	if bit != 0 {
		imtf(cmap, mapSize)
	}
	return brotliL2OK
}

func emitByte(d *decT, v byte) int {
	if d.pos >= d.cap {
		return brotliL2ErrCapacity
	}
	d.out[d.pos] = v
	d.pos++
	d.p2 = d.p1
	d.p1 = v
	return brotliL2OK
}

func emitCopy(d *decT, dist, length uint32) int {
	if length == 0 {
		return brotliL2OK
	}
	if d.pos > d.cap || int(length) > d.cap-d.pos {
		return brotliL2ErrCapacity
	}
	if dist == 0 {
		return brotliL2ErrFormat
	}
	if int(dist) > d.pos || dist > d.wsize {
		return brotliL2ErrDict
	}
	if dist > l2Win {
		return brotliL2ErrWindow
	}
	for i := uint32(0); i < length; i++ {
		v := d.out[d.pos-int(dist)]
		if r := emitByte(d, v); r < 0 {
			return r
		}
	}
	return brotliL2OK
}

func copyRaw(d *decT, mlen uint32) int {
	b := &d.br
	brAlign(b)
	for mlen > 0 && b.bits >= 8 {
		if r := emitByte(d, byte(b.acc&0xff)); r < 0 {
			return r
		}
		b.acc >>= 8
		b.bits -= 8
		mlen--
	}
	remain := len(b.in) - b.p
	if int(mlen) > remain {
		return brotliL2ErrTrunc
	}
	if d.pos > d.cap || int(mlen) > d.cap-d.pos {
		return brotliL2ErrCapacity
	}
	for mlen > 0 {
		if r := emitByte(d, b.in[b.p]); r < 0 {
			return r
		}
		b.p++
		mlen--
	}
	return brotliL2OK
}

func skipMeta(d *decT, mlen uint32) int {
	b := &d.br
	brAlign(b)
	for mlen > 0 && b.bits >= 8 {
		b.acc >>= 8
		b.bits -= 8
		mlen--
	}
	remain := len(b.in) - b.p
	if int(mlen) > remain {
		return brotliL2ErrTrunc
	}
	b.p += int(mlen)
	return brotliL2OK
}

func iacSplit(code uint32, insC, cpyC *uint32, imp *int) {
	*imp = 0
	var insOff, cpyOff uint32
	if code < 128 {
		*imp = 1
		insOff = 0
		if code < 64 {
			cpyOff = 0
		} else {
			cpyOff = 8
		}
	} else if code < 192 {
		insOff, cpyOff = 0, 0
	} else if code < 256 {
		insOff, cpyOff = 0, 8
	} else if code < 320 {
		insOff, cpyOff = 8, 0
	} else if code < 384 {
		insOff, cpyOff = 8, 8
	} else if code < 448 {
		insOff, cpyOff = 0, 16
	} else if code < 512 {
		insOff, cpyOff = 16, 0
	} else if code < 576 {
		insOff, cpyOff = 8, 16
	} else if code < 640 {
		insOff, cpyOff = 16, 8
	} else {
		insOff, cpyOff = 16, 16
	}
	*cpyC = cpyOff + (code & 7)
	*insC = insOff + ((code >> 3) & 7)
}

func resolveDistance(d *decT, dcode, extra uint32, dist *uint32, push *int) int {
	*push = 1
	if dcode < 16 {
		which := kShortWhich[dcode]
		delta := kShortDelta[dcode]
		nd := int64(d.distRb[which]) + int64(delta)
		if nd <= 0 {
			return brotliL2ErrFormat
		}
		*dist = uint32(nd)
		if dcode == 0 {
			*push = 0
		}
		return brotliL2OK
	}
	if dcode < 16+d.ndirect {
		*dist = dcode - 15
		return brotliL2OK
	}
	npost := d.npostfix
	mask := uint32(1<<npost) - 1
	ndirect := d.ndirect
	dcode -= ndirect + 16
	ndistbits := 1 + (dcode >> (npost + 1))
	if ndistbits > 24 {
		return brotliL2ErrFormat
	}
	hcode := dcode >> npost
	lcode := dcode & mask
	offset := ((2 + (hcode & 1)) << ndistbits) - 4
	*dist = ((offset + extra) << npost) + lcode + ndirect + 1
	return brotliL2OK
}

func loadLit(d *decT, tree uint32) int {
	if d.litID == int(tree) {
		return brotliL2OK
	}
	if tree >= d.ntreesL {
		return brotliL2ErrFormat
	}
	if r := lengthsToHuff(gLitCl[tree][:], 256, &d.hLit); r < 0 {
		return r
	}
	d.litID = int(tree)
	return brotliL2OK
}

func loadCmd(d *decT, tree uint32) int {
	if d.cmdID == int(tree) {
		return brotliL2OK
	}
	if tree >= d.nbl[1] {
		return brotliL2ErrFormat
	}
	if r := lengthsToHuff(gCmdCl[tree][:], 704, &d.hCmd); r < 0 {
		return r
	}
	d.cmdID = int(tree)
	return brotliL2OK
}

func loadDist(d *decT, tree uint32) int {
	if d.distID == int(tree) {
		return brotliL2OK
	}
	if tree >= d.ntreesD {
		return brotliL2ErrFormat
	}
	if r := lengthsToHuff(gDistCl[tree][:], d.distAlph, &d.hDist); r < 0 {
		return r
	}
	d.distID = int(tree)
	return brotliL2OK
}

func switchBlock(d *decT, cat int) int {
	var code uint32
	if r := huffDecode(&d.br, &d.hBt[cat], &code); r < 0 {
		return r
	}
	if r := readBlockCount(&d.br, &d.hBl[cat], &d.blen[cat]); r < 0 {
		return r
	}
	var btype uint32
	if code == 1 {
		btype = d.btype[cat] + 1
	} else if code == 0 {
		btype = d.btypePrev[cat]
	} else {
		btype = code - 2
	}
	if btype >= d.nbl[cat] {
		btype -= d.nbl[cat]
	}
	d.btypePrev[cat] = d.btype[cat]
	d.btype[cat] = btype
	return brotliL2OK
}

func prepareCat(d *decT, cat int) int {
	if d.nbl[cat] > 1 && d.blen[cat] == 0 {
		return switchBlock(d, cat)
	}
	return brotliL2OK
}

func consumeCat(d *decT, cat int) {
	if d.nbl[cat] > 1 && d.blen[cat] > 0 {
		d.blen[cat]--
	}
}

func litContext(d *decT) uint32 {
	mode := uint32(gCtxMode[d.btype[0]] & 3)
	lut := gCtx[mode<<9:]
	return uint32(lut[d.p1] | lut[256+int(d.p2)])
}

func distContext(copyLen uint32) uint32 {
	if copyLen == 2 {
		return 0
	}
	if copyLen == 3 {
		return 1
	}
	if copyLen == 4 {
		return 2
	}
	return 3
}

func processCompressed(d *decT, mlen uint32) int {
	remain := mlen
	if r := loadCmd(d, d.btype[1]); r < 0 {
		return r
	}
	for remain > 0 {
		if r := prepareCat(d, 1); r < 0 {
			return r
		}
		if r := loadCmd(d, d.btype[1]); r < 0 {
			return r
		}
		var icode uint32
		if r := huffDecode(&d.br, &d.hCmd, &icode); r < 0 {
			return r
		}
		consumeCat(d, 1)
		if icode > 703 {
			return brotliL2ErrFormat
		}
		var insC, cpyC uint32
		var imp int
		iacSplit(icode, &insC, &cpyC, &imp)
		if insC > 23 || cpyC > 23 {
			return brotliL2ErrFormat
		}
		var extra uint32
		if r := brRead(&d.br, uint(kInsNbits[insC]), &extra); r < 0 {
			return r
		}
		ins := kInsBase[insC] + extra
		if r := brRead(&d.br, uint(kCpyNbits[cpyC]), &extra); r < 0 {
			return r
		}
		cpy := kCpyBase[cpyC] + extra
		if ins > remain {
			return brotliL2ErrFormat
		}
		for i := uint32(0); i < ins; i++ {
			if r := prepareCat(d, 0); r < 0 {
				return r
			}
			ctx := litContext(d)
			tree := uint32(gLitMap[(d.btype[0]<<6)+ctx])
			if r := loadLit(d, tree); r < 0 {
				return r
			}
			var lit uint32
			if r := huffDecode(&d.br, &d.hLit, &lit); r < 0 {
				return r
			}
			if lit > 255 {
				return brotliL2ErrFormat
			}
			if r := emitByte(d, byte(lit)); r < 0 {
				return r
			}
			consumeCat(d, 0)
			remain--
		}
		if remain == 0 {
			break
		}
		if cpy > remain {
			return brotliL2ErrFormat
		}
		var dist uint32
		push := 1
		if imp == 0 {
			var dcode, dextra uint32
			if r := prepareCat(d, 2); r < 0 {
				return r
			}
			dctx := distContext(cpy)
			tree := uint32(gDistMap[(d.btype[2]<<2)+dctx])
			if r := loadDist(d, tree); r < 0 {
				return r
			}
			if r := huffDecode(&d.br, &d.hDist, &dcode); r < 0 {
				return r
			}
			if dcode >= d.distAlph {
				return brotliL2ErrFormat
			}
			if dcode >= 16+d.ndirect {
				ndistbits := 1 + ((dcode - d.ndirect - 16) >> (d.npostfix + 1))
				if ndistbits > 24 {
					return brotliL2ErrFormat
				}
				if r := brRead(&d.br, uint(ndistbits), &dextra); r < 0 {
					return r
				}
			}
			if r := resolveDistance(d, dcode, dextra, &dist, &push); r < 0 {
				return r
			}
			consumeCat(d, 2)
		} else {
			dist = d.distRb[0]
			push = 0
		}
		if r := emitCopy(d, dist, cpy); r < 0 {
			return r
		}
		if push != 0 {
			d.distRb[3] = d.distRb[2]
			d.distRb[2] = d.distRb[1]
			d.distRb[1] = d.distRb[0]
			d.distRb[0] = dist
		}
		remain -= cpy
	}
	return brotliL2OK
}

func readBlockTypes(d *decT, cat int) int {
	var n uint32
	if r := decodeVarlenU8(&d.br, &n); r < 0 {
		return r
	}
	d.nbl[cat] = n + 1
	if d.nbl[cat] > 256 {
		return brotliL2ErrFormat
	}
	d.btype[cat] = 0
	d.btypePrev[cat] = 1
	d.blen[cat] = 1 << 24
	if d.nbl[cat] >= 2 {
		if r := readHuff(&d.br, d.nbl[cat]+2, &d.hBt[cat]); r < 0 {
			return r
		}
		if r := readHuff(&d.br, 26, &d.hBl[cat]); r < 0 {
			return r
		}
		if r := readBlockCount(&d.br, &d.hBl[cat], &d.blen[cat]); r < 0 {
			return r
		}
	}
	return brotliL2OK
}

func decodeMetablockHeader(d *decT, mlen *uint32, isLast, isUncomp, isMeta *int) int {
	*isUncomp = 0
	*isMeta = 0
	*mlen = 0
	var bit uint32
	if r := brRead(&d.br, 1, &bit); r < 0 {
		return r
	}
	if bit != 0 {
		*isLast = 1
	} else {
		*isLast = 0
	}
	if *isLast != 0 {
		if r := brRead(&d.br, 1, &bit); r < 0 {
			return r
		}
		if bit != 0 {
			*mlen = 0
			return brotliL2OK
		}
	}
	var nib uint32
	if r := brRead(&d.br, 2, &nib); r < 0 {
		return r
	}
	if nib == 3 {
		*isMeta = 1
		if r := brRead(&d.br, 1, &bit); r < 0 {
			return r
		}
		if bit != 0 {
			return brotliL2ErrFormat
		}
		var skipb uint32
		if r := brRead(&d.br, 2, &skipb); r < 0 {
			return r
		}
		skip := uint32(0)
		for i := uint32(0); i < skipb; i++ {
			var b uint32
			if r := brRead(&d.br, 8, &b); r < 0 {
				return r
			}
			if i+1 == skipb && skipb > 1 && b == 0 {
				return brotliL2ErrFormat
			}
			skip |= b << (8 * i)
		}
		if skipb != 0 {
			skip++
		}
		*mlen = skip
		return brotliL2OK
	}
	nn := nib + 4
	m := uint32(0)
	for i := uint32(0); i < nn; i++ {
		var n4 uint32
		if r := brRead(&d.br, 4, &n4); r < 0 {
			return r
		}
		if i+1 == nn && nn > 4 && n4 == 0 {
			return brotliL2ErrFormat
		}
		m |= n4 << (4 * i)
	}
	*mlen = m + 1
	if *isLast == 0 {
		if r := brRead(&d.br, 1, &bit); r < 0 {
			return r
		}
		if bit != 0 {
			*isUncomp = 1
		} else {
			*isUncomp = 0
		}
	}
	return brotliL2OK
}

func decodeCompressedHeader(d *decT) int {
	if r := readBlockTypes(d, 0); r < 0 {
		return r
	}
	if r := readBlockTypes(d, 1); r < 0 {
		return r
	}
	if r := readBlockTypes(d, 2); r < 0 {
		return r
	}
	var npost, ndir uint32
	if r := brRead(&d.br, 2, &npost); r < 0 {
		return r
	}
	d.npostfix = npost
	if r := brRead(&d.br, 4, &ndir); r < 0 {
		return r
	}
	d.ndirect = ndir << npost
	if d.ndirect > 120 {
		return brotliL2ErrFormat
	}
	d.distAlph = 16 + d.ndirect + (48 << d.npostfix)
	if d.distAlph > 520 {
		return brotliL2ErrFormat
	}
	for i := uint32(0); i < d.nbl[0]; i++ {
		var mode uint32
		if r := brRead(&d.br, 2, &mode); r < 0 {
			return r
		}
		gCtxMode[i] = byte(mode)
	}
	if r := decodeContextMap(&d.br, d.nbl[0]*64, &d.ntreesL, gLitMap[:]); r < 0 {
		return r
	}
	if r := decodeContextMap(&d.br, d.nbl[2]*4, &d.ntreesD, gDistMap[:]); r < 0 {
		return r
	}
	var length [l2MaxAlph]byte
	for i := uint32(0); i < d.ntreesL; i++ {
		if r := readHuffmanLengths(&d.br, 256, length[:]); r < 0 {
			return r
		}
		copy(gLitCl[i][:], length[:256])
	}
	for i := uint32(0); i < d.nbl[1]; i++ {
		if r := readHuffmanLengths(&d.br, 704, length[:]); r < 0 {
			return r
		}
		copy(gCmdCl[i][:], length[:704])
	}
	for i := uint32(0); i < d.ntreesD; i++ {
		if r := readHuffmanLengths(&d.br, d.distAlph, length[:]); r < 0 {
			return r
		}
		copy(gDistCl[i][:], length[:d.distAlph])
	}
	d.litID = -1
	d.cmdID = -1
	d.distID = -1
	return brotliL2OK
}

func brotliMapErr(rc int) error {
	switch rc {
	case brotliL2OK:
		return nil
	case brotliL2ErrArg:
		return ErrBrotliArg
	case brotliL2ErrCapacity:
		return ErrBrotliCapacity
	case brotliL2ErrTrunc:
		return ErrBrotliTrunc
	case brotliL2ErrFormat:
		return ErrBrotliFormat
	case brotliL2ErrWindow:
		return ErrBrotliWindow
	case brotliL2ErrDict:
		return ErrBrotliDict
	default:
		return ErrBrotliFormat
	}
}

func BrotliL2Decompress(in, out []byte) (int, error) {
	ctxInit()
	d := &brotliDec
	*d = decT{}
	d.br.in = in
	d.br.p = 0
	d.out = out
	d.cap = len(out)
	d.distRb[0] = 4
	d.distRb[1] = 11
	d.distRb[2] = 15
	d.distRb[3] = 16
	d.litID = -1
	d.cmdID = -1
	d.distID = -1
	var wbits uint32
	if r := decodeWindowBits(&d.br, &wbits); r < 0 {
		return 0, brotliMapErr(r)
	}
	if wbits < 10 || wbits > 24 {
		return 0, ErrBrotliWindow
	}
	d.wsize = (1 << wbits) - 16
	for {
		var mlen uint32
		var isLast, isUncomp, isMeta int
		if r := decodeMetablockHeader(d, &mlen, &isLast, &isUncomp, &isMeta); r < 0 {
			return 0, brotliMapErr(r)
		}
		if isLast != 0 && mlen == 0 && isMeta == 0 && isUncomp == 0 {
			break
		}
		if isMeta != 0 {
			if r := skipMeta(d, mlen); r < 0 {
				return 0, brotliMapErr(r)
			}
			if isLast != 0 {
				break
			}
			continue
		}
		if mlen > 0 {
			if d.pos > d.cap || int(mlen) > d.cap-d.pos {
				return 0, ErrBrotliCapacity
			}
		}
		if isUncomp != 0 {
			if isLast != 0 {
				return 0, ErrBrotliFormat
			}
			if r := copyRaw(d, mlen); r < 0 {
				return 0, brotliMapErr(r)
			}
			if isLast != 0 {
				break
			}
			continue
		}
		if mlen == 0 {
			if isLast != 0 {
				break
			}
			continue
		}
		if r := decodeCompressedHeader(d); r < 0 {
			return 0, brotliMapErr(r)
		}
		if r := processCompressed(d, mlen); r < 0 {
			return 0, brotliMapErr(r)
		}
		if isLast != 0 {
			break
		}
	}
	return d.pos, nil
}
