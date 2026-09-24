// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. See LICENSE and NOTICE.

package evm256

import "encoding/binary"

type Uint256 [4]uint64

func FromU64(v uint64) Uint256 {
	return Uint256{v, 0, 0, 0}
}

func FromBytesBE(b []byte) Uint256 {
	var buf [32]byte
	if n := len(b); n >= 32 {
		copy(buf[:], b[n-32:])
	} else {
		copy(buf[32-n:], b)
	}
	return Uint256{
		binary.BigEndian.Uint64(buf[24:32]),
		binary.BigEndian.Uint64(buf[16:24]),
		binary.BigEndian.Uint64(buf[8:16]),
		binary.BigEndian.Uint64(buf[0:8]),
	}
}

func BytesBE(z Uint256) [32]byte {
	var buf [32]byte
	binary.BigEndian.PutUint64(buf[0:8], z[3])
	binary.BigEndian.PutUint64(buf[8:16], z[2])
	binary.BigEndian.PutUint64(buf[16:24], z[1])
	binary.BigEndian.PutUint64(buf[24:32], z[0])
	return buf
}

func IsZero(z *Uint256) bool {
	return (z[0] | z[1] | z[2] | z[3]) == 0
}

func Eq(a, b *Uint256) bool {
	return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3]
}

func Cmp(a, b *Uint256) int {
	for i := 3; i >= 0; i-- {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

func isNeg(z *Uint256) bool {
	return z[3]>>63 != 0
}
