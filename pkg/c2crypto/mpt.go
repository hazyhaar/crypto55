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

func MptHashNode(rlpData []byte, out *[32]byte) {
	rlpLen := len(rlpData)
	if rlpLen < 32 {
		*out = [32]byte{}
		if rlpLen != 0 {
			copy(out[:], rlpData)
		}
		return
	}
	Keccak256(rlpData, out)
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

func MptEncodeExtension(keyNibbles []byte, childHash *[32]byte, out []byte) int {
	var compact [256]byte
	compactLen := MptCompactEncode(keyNibbles, false, compact[:])
	payload := rlpBytesSize(compact[:compactLen]) + rlpBytesSize(childHash[:])
	n := RlpEncodeListHeader(payload, out)
	n += RlpEncodeBytes(compact[:compactLen], out[n:])
	n += RlpEncodeBytes(childHash[:], out[n:])
	return n
}

func MptEncodeBranch(children *[16][32]byte, hasChild *[16]int, value, out []byte) int {
	payload := 0
	for i := 0; i < 16; i++ {
		if hasChild[i] != 0 {
			payload += rlpBytesSize(children[i][:])
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
			n += RlpEncodeBytes(children[i][:], out[n:])
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
