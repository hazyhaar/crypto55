package evm256

func Lt256(a, b *Uint256) bool {
	return Cmp(a, b) < 0
}

func Gt256(a, b *Uint256) bool {
	return Cmp(a, b) > 0
}

func Slt256(a, b *Uint256) bool {
	na := isNeg(a)
	nb := isNeg(b)
	if na != nb {
		return na
	}
	return Cmp(a, b) < 0
}

func Sgt256(a, b *Uint256) bool {
	na := isNeg(a)
	nb := isNeg(b)
	if na != nb {
		return nb
	}
	return Cmp(a, b) > 0
}

func And256(a, b, out *Uint256) {
	aa, bb := *a, *b
	*out = Uint256{aa[0] & bb[0], aa[1] & bb[1], aa[2] & bb[2], aa[3] & bb[3]}
}

func Or256(a, b, out *Uint256) {
	aa, bb := *a, *b
	*out = Uint256{aa[0] | bb[0], aa[1] | bb[1], aa[2] | bb[2], aa[3] | bb[3]}
}

func Xor256(a, b, out *Uint256) {
	aa, bb := *a, *b
	*out = Uint256{aa[0] ^ bb[0], aa[1] ^ bb[1], aa[2] ^ bb[2], aa[3] ^ bb[3]}
}

func Not256(a, out *Uint256) {
	aa := *a
	*out = Uint256{^aa[0], ^aa[1], ^aa[2], ^aa[3]}
}

func Byte256(i uint64, x, out *Uint256) {
	xx := *x
	*out = Uint256{}
	if i < 32 {
		idx := 31 - uint(i)
		wi := idx >> 3
		sh := (idx & 7) * 8
		out[0] = (xx[wi] >> sh) & 0xff
	}
}

func shiftGE256(shift *Uint256) bool {
	return (shift[1]|shift[2]|shift[3]) != 0 || shift[0] >= 256
}

func Shl256(shift, val, out *Uint256) {
	s, v := *shift, *val
	if shiftGE256(&s) {
		*out = Uint256{}
		return
	}
	wsh := uint(s[0] / 64)
	bsh := uint(s[0] % 64)
	var r Uint256
	for i := 0; i < 4; i++ {
		src := i - int(wsh)
		var lo, hi uint64
		if src >= 0 && src < 4 {
			lo = v[src]
		}
		src = i - int(wsh) - 1
		if src >= 0 && src < 4 {
			hi = v[src]
		}
		if bsh == 0 {
			r[i] = lo
		} else {
			r[i] = (lo << bsh) | (hi >> (64 - bsh))
		}
	}
	*out = r
}

func Shr256(shift, val, out *Uint256) {
	s, v := *shift, *val
	if shiftGE256(&s) {
		*out = Uint256{}
		return
	}
	wsh := uint(s[0] / 64)
	bsh := uint(s[0] % 64)
	var r Uint256
	for i := 0; i < 4; i++ {
		src := i + int(wsh)
		var lo, hi uint64
		if src >= 0 && src < 4 {
			lo = v[src]
		}
		src = i + int(wsh) + 1
		if src >= 0 && src < 4 {
			hi = v[src]
		}
		if bsh == 0 {
			r[i] = lo
		} else {
			r[i] = (lo >> bsh) | (hi << (64 - bsh))
		}
	}
	*out = r
}

func Sar256(shift, val, out *Uint256) {
	s, v := *shift, *val
	var fill uint64
	if isNeg(&v) {
		fill = ^uint64(0)
	}
	if shiftGE256(&s) {
		*out = Uint256{fill, fill, fill, fill}
		return
	}
	wsh := uint(s[0] / 64)
	bsh := uint(s[0] % 64)
	var r Uint256
	for i := 0; i < 4; i++ {
		src := i + int(wsh)
		lo, hi := fill, fill
		if src >= 0 && src < 4 {
			lo = v[src]
		}
		src = i + int(wsh) + 1
		if src >= 0 && src < 4 {
			hi = v[src]
		}
		if bsh == 0 {
			r[i] = lo
		} else {
			r[i] = (lo >> bsh) | (hi << (64 - bsh))
		}
	}
	*out = r
}
