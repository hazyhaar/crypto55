// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. See LICENSE and NOTICE.

package c2crypto

func rlpIntLen(n int) int {
	lenN := 0
	for n != 0 {
		lenN++
		n >>= 8
	}
	return lenN
}

func rlpWriteInt(n int, out []byte, length int) {
	for i := 0; i < length; i++ {
		out[length-1-i] = byte(n & 0xff)
		n >>= 8
	}
}

func rlpBytesSize(data []byte) int {
	dataLen := len(data)
	if dataLen == 1 && data[0] < 0x80 {
		return 1
	}
	if dataLen < 56 {
		return 1 + dataLen
	}
	return 1 + rlpIntLen(dataLen) + dataLen
}

func MptCompactEncode(nibbles []byte, isLeaf bool, out []byte) int {
	flag := byte(0)
	if isLeaf {
		flag = 2
	}
	var i, n int
	numNibbles := len(nibbles)
	if numNibbles&1 != 0 {
		flag |= 1
		out[0] = (flag << 4) | (nibbles[0] & 0x0f)
		i = 1
		n = 1
	} else {
		out[0] = flag << 4
		i = 0
		n = 1
	}
	for i < numNibbles {
		out[n] = ((nibbles[i] & 0x0f) << 4) | (nibbles[i+1] & 0x0f)
		n++
		i += 2
	}
	return n
}

func RlpEncodeBytes(data []byte, out []byte) int {
	dataLen := len(data)
	if dataLen == 1 && data[0] < 0x80 {
		out[0] = data[0]
		return 1
	}
	if dataLen < 56 {
		out[0] = byte(0x80 + dataLen)
		if dataLen != 0 {
			copy(out[1:], data)
		}
		return 1 + dataLen
	}
	llen := rlpIntLen(dataLen)
	out[0] = byte(0xb7 + llen)
	rlpWriteInt(dataLen, out[1:], llen)
	copy(out[1+llen:], data)
	return 1 + llen + dataLen
}

func RlpEncodeListHeader(payloadLen int, out []byte) int {
	if payloadLen < 56 {
		out[0] = byte(0xc0 + payloadLen)
		return 1
	}
	llen := rlpIntLen(payloadLen)
	out[0] = byte(0xf7 + llen)
	rlpWriteInt(payloadLen, out[1:], llen)
	return 1 + llen
}

// MptHashNode calcule l'empreinte keccak256 d'un nœud déjà encodé en RLP.
// L'arbre de Merkle Patricia Ethereum ne référence un enfant par cette
// empreinte que lorsque son encodage RLP atteint 32 octets ; les enfants plus
// courts sont insérés bruts dans la liste parente (voir MptChildRefSize et
// MptEncodeChildRef).
func MptHashNode(rlpData []byte, out *[32]byte) {
	Keccak256(rlpData, out)
}

// MptChildRefSize renvoie la taille RLP de la référence qu'un nœud parent,
// extension ou branche, porte pour un enfant dont l'encodage RLP est fourni.
// Un enfant de moins de 32 octets est inséré brut ; sinon le parent porte son
// empreinte keccak256 de 32 octets.
func MptChildRefSize(childRLP []byte) int {
	if len(childRLP) < 32 {
		return len(childRLP)
	}
	return 1 + 32
}

// MptEncodeChildRef écrit dans out la référence parente d'un enfant déjà
// encodé en RLP, selon la règle standard : insertion brute sous 32 octets,
// empreinte keccak256 au-delà. Elle renvoie le nombre d'octets écrits.
func MptEncodeChildRef(childRLP, out []byte) int {
	if len(childRLP) < 32 {
		copy(out, childRLP)
		return len(childRLP)
	}
	var h [32]byte
	Keccak256(childRLP, &h)
	return RlpEncodeBytes(h[:], out)
}

func MptEncodeLeaf(keyNibbles, value, out []byte) int {
	var compact [256]byte
	compactLen := MptCompactEncode(keyNibbles, true, compact[:])
	payload := rlpBytesSize(compact[:compactLen]) + rlpBytesSize(value)
	n := RlpEncodeListHeader(payload, out)
	n += RlpEncodeBytes(compact[:compactLen], out[n:])
	n += RlpEncodeBytes(value, out[n:])
	return n
}

// MptEncodeExtension encode un nœud d'extension dont l'enfant est fourni sous
// sa forme RLP complète (childRLP). La référence écrite respecte la règle
// d'insertion brute pour les enfants courts.
func MptEncodeExtension(keyNibbles, childRLP, out []byte) int {
	var compact [256]byte
	compactLen := MptCompactEncode(keyNibbles, false, compact[:])
	payload := rlpBytesSize(compact[:compactLen]) + MptChildRefSize(childRLP)
	n := RlpEncodeListHeader(payload, out)
	n += RlpEncodeBytes(compact[:compactLen], out[n:])
	n += MptEncodeChildRef(childRLP, out[n:])
	return n
}

// MptEncodeBranch encode un nœud de branche dont chaque enfant est fourni sous
// sa forme RLP complète. Les enfants courts sont insérés bruts dans la liste.
func MptEncodeBranch(children *[16][]byte, hasChild *[16]int, value, out []byte) int {
	payload := 0
	for i := 0; i < 16; i++ {
		if hasChild[i] != 0 {
			payload += MptChildRefSize(children[i])
		} else {
			payload += 1
		}
	}
	if len(value) == 0 {
		payload += 1
	} else {
		payload += rlpBytesSize(value)
	}
	n := RlpEncodeListHeader(payload, out)
	for i := 0; i < 16; i++ {
		if hasChild[i] != 0 {
			n += MptEncodeChildRef(children[i], out[n:])
		} else {
			out[n] = 0x80
			n++
		}
	}
	if len(value) == 0 {
		out[n] = 0x80
		n++
	} else {
		n += RlpEncodeBytes(value, out[n:])
	}
	return n
}
