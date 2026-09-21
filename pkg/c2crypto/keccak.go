package c2crypto

import "math/bits"

var keccakRC = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
	0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
	0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
	0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
	0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
	0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

func KeccakF1600(st *[25]uint64) {
	aba, abe, abi, abo, abu := st[0], st[1], st[2], st[3], st[4]
	aga, age, agi, ago, agu := st[5], st[6], st[7], st[8], st[9]
	aka, ake, aki, ako, aku := st[10], st[11], st[12], st[13], st[14]
	ama, ame, ami, amo, amu := st[15], st[16], st[17], st[18], st[19]
	asa, ase, asi, aso, asu := st[20], st[21], st[22], st[23], st[24]

	for round := 0; round < 24; round += 2 {
		bca := aba ^ aga ^ aka ^ ama ^ asa
		bce := abe ^ age ^ ake ^ ame ^ ase
		bci := abi ^ agi ^ aki ^ ami ^ asi
		bco := abo ^ ago ^ ako ^ amo ^ aso
		bcu := abu ^ agu ^ aku ^ amu ^ asu
		da := bcu ^ bits.RotateLeft64(bce, 1)
		de := bca ^ bits.RotateLeft64(bci, 1)
		di := bce ^ bits.RotateLeft64(bco, 1)
		do := bci ^ bits.RotateLeft64(bcu, 1)
		du := bco ^ bits.RotateLeft64(bca, 1)

		aba ^= da
		bca = aba
		age ^= de
		bce = bits.RotateLeft64(age, 44)
		aki ^= di
		bci = bits.RotateLeft64(aki, 43)
		amo ^= do
		bco = bits.RotateLeft64(amo, 21)
		asu ^= du
		bcu = bits.RotateLeft64(asu, 14)
		eba := bca ^ (^bce & bci) ^ keccakRC[round]
		ebe := bce ^ (^bci & bco)
		ebi := bci ^ (^bco & bcu)
		ebo := bco ^ (^bcu & bca)
		ebu := bcu ^ (^bca & bce)

		abo ^= do
		bca = bits.RotateLeft64(abo, 28)
		agu ^= du
		bce = bits.RotateLeft64(agu, 20)
		aka ^= da
		bci = bits.RotateLeft64(aka, 3)
		ame ^= de
		bco = bits.RotateLeft64(ame, 45)
		asi ^= di
		bcu = bits.RotateLeft64(asi, 61)
		ega := bca ^ (^bce & bci)
		ege := bce ^ (^bci & bco)
		egi := bci ^ (^bco & bcu)
		ego := bco ^ (^bcu & bca)
		egu := bcu ^ (^bca & bce)

		abe ^= de
		bca = bits.RotateLeft64(abe, 1)
		agi ^= di
		bce = bits.RotateLeft64(agi, 6)
		ako ^= do
		bci = bits.RotateLeft64(ako, 25)
		amu ^= du
		bco = bits.RotateLeft64(amu, 8)
		asa ^= da
		bcu = bits.RotateLeft64(asa, 18)
		eka := bca ^ (^bce & bci)
		eke := bce ^ (^bci & bco)
		eki := bci ^ (^bco & bcu)
		eko := bco ^ (^bcu & bca)
		eku := bcu ^ (^bca & bce)

		abu ^= du
		bca = bits.RotateLeft64(abu, 27)
		aga ^= da
		bce = bits.RotateLeft64(aga, 36)
		ake ^= de
		bci = bits.RotateLeft64(ake, 10)
		ami ^= di
		bco = bits.RotateLeft64(ami, 15)
		aso ^= do
		bcu = bits.RotateLeft64(aso, 56)
		ema := bca ^ (^bce & bci)
		eme := bce ^ (^bci & bco)
		emi := bci ^ (^bco & bcu)
		emo := bco ^ (^bcu & bca)
		emu := bcu ^ (^bca & bce)

		abi ^= di
		bca = bits.RotateLeft64(abi, 62)
		ago ^= do
		bce = bits.RotateLeft64(ago, 55)
		aku ^= du
		bci = bits.RotateLeft64(aku, 39)
		ama ^= da
		bco = bits.RotateLeft64(ama, 41)
		ase ^= de
		bcu = bits.RotateLeft64(ase, 2)
		esa := bca ^ (^bce & bci)
		ese := bce ^ (^bci & bco)
		esi := bci ^ (^bco & bcu)
		eso := bco ^ (^bcu & bca)
		esu := bcu ^ (^bca & bce)

		bca = eba ^ ega ^ eka ^ ema ^ esa
		bce = ebe ^ ege ^ eke ^ eme ^ ese
		bci = ebi ^ egi ^ eki ^ emi ^ esi
		bco = ebo ^ ego ^ eko ^ emo ^ eso
		bcu = ebu ^ egu ^ eku ^ emu ^ esu
		da = bcu ^ bits.RotateLeft64(bce, 1)
		de = bca ^ bits.RotateLeft64(bci, 1)
		di = bce ^ bits.RotateLeft64(bco, 1)
		do = bci ^ bits.RotateLeft64(bcu, 1)
		du = bco ^ bits.RotateLeft64(bca, 1)

		eba ^= da
		bca = eba
		ege ^= de
		bce = bits.RotateLeft64(ege, 44)
		eki ^= di
		bci = bits.RotateLeft64(eki, 43)
		emo ^= do
		bco = bits.RotateLeft64(emo, 21)
		esu ^= du
		bcu = bits.RotateLeft64(esu, 14)
		aba = bca ^ (^bce & bci) ^ keccakRC[round+1]
		abe = bce ^ (^bci & bco)
		abi = bci ^ (^bco & bcu)
		abo = bco ^ (^bcu & bca)
		abu = bcu ^ (^bca & bce)

		ebo ^= do
		bca = bits.RotateLeft64(ebo, 28)
		egu ^= du
		bce = bits.RotateLeft64(egu, 20)
		eka ^= da
		bci = bits.RotateLeft64(eka, 3)
		eme ^= de
		bco = bits.RotateLeft64(eme, 45)
		esi ^= di
		bcu = bits.RotateLeft64(esi, 61)
		aga = bca ^ (^bce & bci)
		age = bce ^ (^bci & bco)
		agi = bci ^ (^bco & bcu)
		ago = bco ^ (^bcu & bca)
		agu = bcu ^ (^bca & bce)

		ebe ^= de
		bca = bits.RotateLeft64(ebe, 1)
		egi ^= di
		bce = bits.RotateLeft64(egi, 6)
		eko ^= do
		bci = bits.RotateLeft64(eko, 25)
		emu ^= du
		bco = bits.RotateLeft64(emu, 8)
		esa ^= da
		bcu = bits.RotateLeft64(esa, 18)
		aka = bca ^ (^bce & bci)
		ake = bce ^ (^bci & bco)
		aki = bci ^ (^bco & bcu)
		ako = bco ^ (^bcu & bca)
		aku = bcu ^ (^bca & bce)

		ebu ^= du
		bca = bits.RotateLeft64(ebu, 27)
		ega ^= da
		bce = bits.RotateLeft64(ega, 36)
		eke ^= de
		bci = bits.RotateLeft64(eke, 10)
		emi ^= di
		bco = bits.RotateLeft64(emi, 15)
		eso ^= do
		bcu = bits.RotateLeft64(eso, 56)
		ama = bca ^ (^bce & bci)
		ame = bce ^ (^bci & bco)
		ami = bci ^ (^bco & bcu)
		amo = bco ^ (^bcu & bca)
		amu = bcu ^ (^bca & bce)

		ebi ^= di
		bca = bits.RotateLeft64(ebi, 62)
		ego ^= do
		bce = bits.RotateLeft64(ego, 55)
		eku ^= du
		bci = bits.RotateLeft64(eku, 39)
		ema ^= da
		bco = bits.RotateLeft64(ema, 41)
		ese ^= de
		bcu = bits.RotateLeft64(ese, 2)
		asa = bca ^ (^bce & bci)
		ase = bce ^ (^bci & bco)
		asi = bci ^ (^bco & bcu)
		aso = bco ^ (^bcu & bca)
		asu = bcu ^ (^bca & bce)
	}

	st[0], st[1], st[2], st[3], st[4] = aba, abe, abi, abo, abu
	st[5], st[6], st[7], st[8], st[9] = aga, age, agi, ago, agu
	st[10], st[11], st[12], st[13], st[14] = aka, ake, aki, ako, aku
	st[15], st[16], st[17], st[18], st[19] = ama, ame, ami, amo, amu
	st[20], st[21], st[22], st[23], st[24] = asa, ase, asi, aso, asu
}

func xorBytes(st *[25]uint64, in []byte, n int) {
	i := 0
	for n >= 8 {
		_ = in[7]
		st[i] ^= uint64(in[0]) | uint64(in[1])<<8 | uint64(in[2])<<16 | uint64(in[3])<<24 |
			uint64(in[4])<<32 | uint64(in[5])<<40 | uint64(in[6])<<48 | uint64(in[7])<<56
		in = in[8:]
		n -= 8
		i++
	}
	for j := 0; j < n; j++ {
		st[i] ^= uint64(in[j]) << (uint(j) * 8)
	}
}

func extractBytes(st *[25]uint64, out []byte, n int) {
	i := 0
	for n >= 8 {
		v := st[i]
		_ = out[7]
		out[0] = byte(v)
		out[1] = byte(v >> 8)
		out[2] = byte(v >> 16)
		out[3] = byte(v >> 24)
		out[4] = byte(v >> 32)
		out[5] = byte(v >> 40)
		out[6] = byte(v >> 48)
		out[7] = byte(v >> 56)
		out = out[8:]
		n -= 8
		i++
	}
	for j := 0; j < n; j++ {
		out[j] = byte(st[i] >> (uint(j) * 8))
	}
}

func keccakSponge(in []byte, out []byte, rate int) {
	var st [25]uint64
	off := 0
	inLen := len(in)
	for inLen >= rate {
		xorBytes(&st, in[off:off+rate], rate)
		KeccakF1600(&st)
		off += rate
		inLen -= rate
	}
	if inLen != 0 {
		xorBytes(&st, in[off:off+inLen], inLen)
	}
	st[inLen>>3] ^= uint64(0x01) << ((uint(inLen) & 7) * 8)
	st[(rate-1)>>3] ^= uint64(0x80) << ((uint(rate-1) & 7) * 8)
	KeccakF1600(&st)
	outOff := 0
	outLen := len(out)
	for outLen >= rate {
		extractBytes(&st, out[outOff:outOff+rate], rate)
		KeccakF1600(&st)
		outOff += rate
		outLen -= rate
	}
	extractBytes(&st, out[outOff:outOff+outLen], outLen)
}

func Keccak256(in []byte, out *[32]byte) {
	keccakSponge(in, out[:], 136)
}

func Keccak512(in []byte, out *[64]byte) {
	keccakSponge(in, out[:], 72)
}
