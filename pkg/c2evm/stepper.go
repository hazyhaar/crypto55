package c2evm

import (
	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2crypto"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
)

const gasInvalid = ^uint64(0)

var opGas = func() [256]uint64 {
	var g [256]uint64
	for i := range g {
		g[i] = gasInvalid
	}
	g[0x00] = 0
	g[0x01] = 3
	g[0x02] = 5
	g[0x03] = 3
	g[0x04] = 5
	g[0x05] = 5
	g[0x06] = 5
	g[0x07] = 5
	g[0x08] = 8
	g[0x09] = 8
	g[0x0a] = 10
	g[0x0b] = 5
	for op := 0x10; op <= 0x1d; op++ {
		g[op] = 3
	}
	g[0x20] = 30
	g[0x50] = 2
	g[0x51] = 3
	g[0x52] = 3
	g[0x53] = 3
	g[0x54] = 800
	g[0x55] = 5000
	g[0x56] = 8
	g[0x57] = 10
	g[0x58] = 2
	g[0x59] = 2
	g[0x5a] = 2
	g[0x5b] = 1
	g[0x5f] = 2
	for op := 0x60; op <= 0x7f; op++ {
		g[op] = 3
	}
	for op := 0x80; op <= 0x9f; op++ {
		g[op] = 3
	}
	g[0xfd] = 0
	return g
}()

func haltEx(f *ExecutionFrame, st int) int {
	f.Status = st
	f.Gas = 0
	return st
}

func requireStack(f *ExecutionFrame, n int32) int {
	if f.SP < n {
		return haltEx(f, StatusStackUnderflow)
	}
	return 0
}

func requireRoom(f *ExecutionFrame) int {
	if f.SP >= stackMax {
		return haltEx(f, StatusStackOverflow)
	}
	return 0
}

func u256AsU64(x *evm256.Uint256, out *uint64) int {
	if (x[1] | x[2] | x[3]) != 0 {
		return -1
	}
	*out = x[0]
	return 0
}

func u256ByteLen(x *evm256.Uint256) uint {
	for i := 31; i >= 0; i-- {
		limb := uint(i) >> 3
		sh := (uint(i) & 7) * 8
		if ((x[limb] >> sh) & 0xff) != 0 {
			return uint(i) + 1
		}
	}
	return 0
}

func memGas(words uint64) uint64 {
	return 3*words + (words*words)/512
}

func chargeMem(f *ExecutionFrame, offset, size uint64) int {
	if size == 0 {
		return 0
	}
	if offset >= memMax {
		return -1
	}
	if size > memMax-offset {
		return -1
	}
	end := offset + size
	words := (end + 31) / 32
	newSize := words * 32
	if newSize > memMax {
		return -1
	}
	if newSize <= uint64(f.MemorySize) {
		return 0
	}
	oldWords := (uint64(f.MemorySize) + 31) / 32
	oldCost := memGas(oldWords)
	newCost := memGas(words)
	if newCost < oldCost {
		return -1
	}
	delta := newCost - oldCost
	if f.Gas < delta {
		return -1
	}
	f.Gas -= delta
	f.MemorySize = uint32(newSize)
	return 0
}

func jumpdestOK(code []byte, dest uint32) bool {
	if int(dest) >= len(code) {
		return false
	}
	if code[dest] != 0x5b {
		return false
	}
	i := 0
	d := int(dest)
	for i < d {
		op := code[i]
		if op >= 0x60 && op <= 0x7f {
			i += 1 + int(op-0x5f)
		} else {
			i++
		}
	}
	return i == d
}

func execBinop(f *ExecutionFrame, fn func(a, b, out *evm256.Uint256)) int {
	if requireStack(f, 2) != 0 {
		return -1
	}
	fn(&f.Stack[f.SP-2], &f.Stack[f.SP-1], &f.Stack[f.SP-2])
	f.SP--
	return 0
}

func execCmp(f *ExecutionFrame, fn func(a, b *evm256.Uint256) bool) int {
	if requireStack(f, 2) != 0 {
		return -1
	}
	var v uint64
	if fn(&f.Stack[f.SP-2], &f.Stack[f.SP-1]) {
		v = 1
	}
	f.Stack[f.SP-2] = evm256.FromU64(v)
	f.SP--
	return 0
}

func execPush(f *ExecutionFrame, code []byte, n uint) int {
	if requireRoom(f) != 0 {
		return -1
	}
	var buf [32]byte
	var i uint
	for i = 0; i < n; i++ {
		var b byte
		if int(f.PC) < len(code) {
			b = code[f.PC]
		}
		f.PC++
		buf[32-n+i] = b
	}
	f.Stack[f.SP] = evm256.FromBytesBE(buf[:])
	f.SP++
	return 0
}

func zeroAddr() evm256.Uint256 {
	return evm256.Uint256{}
}

func StepOne(f *ExecutionFrame, code []byte) int {
	if f.Status != StatusRunning {
		return f.Status
	}
	if int(f.PC) >= len(code) {
		f.Status = StatusSuccess
		return f.Status
	}
	op := code[f.PC]
	cost := opGas[op]
	if cost == gasInvalid {
		return haltEx(f, StatusInvalidOpcode)
	}
	if f.Gas < cost {
		return haltEx(f, StatusOutOfGas)
	}
	f.Gas -= cost
	f.PC++

	switch op {
	case 0x00:
		f.Status = StatusSuccess
	case 0x01:
		if execBinop(f, evm256.Add256) < 0 {
			return f.Status
		}
	case 0x02:
		if execBinop(f, evm256.Mul256) < 0 {
			return f.Status
		}
	case 0x03:
		if execBinop(f, evm256.Sub256) < 0 {
			return f.Status
		}
	case 0x04:
		if execBinop(f, evm256.Div256) < 0 {
			return f.Status
		}
	case 0x05:
		if execBinop(f, evm256.SDiv256) < 0 {
			return f.Status
		}
	case 0x06:
		if execBinop(f, evm256.Mod256) < 0 {
			return f.Status
		}
	case 0x07:
		if execBinop(f, evm256.SMod256) < 0 {
			return f.Status
		}
	case 0x08:
		if requireStack(f, 3) != 0 {
			return f.Status
		}
		evm256.AddMod256(&f.Stack[f.SP-3], &f.Stack[f.SP-2], &f.Stack[f.SP-1], &f.Stack[f.SP-3])
		f.SP -= 2
	case 0x09:
		if requireStack(f, 3) != 0 {
			return f.Status
		}
		evm256.MulMod256(&f.Stack[f.SP-3], &f.Stack[f.SP-2], &f.Stack[f.SP-1], &f.Stack[f.SP-3])
		f.SP -= 2
	case 0x0a:
		if requireStack(f, 2) != 0 {
			return f.Status
		}
		blen := u256ByteLen(&f.Stack[f.SP-1])
		extra := 50 * uint64(blen)
		if f.Gas < extra {
			return haltEx(f, StatusOutOfGas)
		}
		f.Gas -= extra
		evm256.Exp256(&f.Stack[f.SP-2], &f.Stack[f.SP-1], &f.Stack[f.SP-2])
		f.SP--
	case 0x0b:
		if requireStack(f, 2) != 0 {
			return f.Status
		}
		var b uint64
		if u256AsU64(&f.Stack[f.SP-1], &b) < 0 {
			b = 31
		}
		evm256.SignExtend256(b, &f.Stack[f.SP-2], &f.Stack[f.SP-2])
		f.SP--
	case 0x10:
		if execCmp(f, evm256.Lt256) < 0 {
			return f.Status
		}
	case 0x11:
		if execCmp(f, evm256.Gt256) < 0 {
			return f.Status
		}
	case 0x12:
		if execCmp(f, evm256.Slt256) < 0 {
			return f.Status
		}
	case 0x13:
		if execCmp(f, evm256.Sgt256) < 0 {
			return f.Status
		}
	case 0x14:
		if execCmp(f, evm256.Eq) < 0 {
			return f.Status
		}
	case 0x15:
		if requireStack(f, 1) != 0 {
			return f.Status
		}
		var v uint64
		if evm256.IsZero(&f.Stack[f.SP-1]) {
			v = 1
		}
		f.Stack[f.SP-1] = evm256.FromU64(v)
	case 0x16:
		if execBinop(f, evm256.And256) < 0 {
			return f.Status
		}
	case 0x17:
		if execBinop(f, evm256.Or256) < 0 {
			return f.Status
		}
	case 0x18:
		if execBinop(f, evm256.Xor256) < 0 {
			return f.Status
		}
	case 0x19:
		if requireStack(f, 1) != 0 {
			return f.Status
		}
		evm256.Not256(&f.Stack[f.SP-1], &f.Stack[f.SP-1])
	case 0x1a:
		if requireStack(f, 2) != 0 {
			return f.Status
		}
		var i uint64
		if u256AsU64(&f.Stack[f.SP-1], &i) < 0 {
			i = 32
		}
		evm256.Byte256(i, &f.Stack[f.SP-2], &f.Stack[f.SP-2])
		f.SP--
	case 0x1b:
		if requireStack(f, 2) != 0 {
			return f.Status
		}
		evm256.Shl256(&f.Stack[f.SP-1], &f.Stack[f.SP-2], &f.Stack[f.SP-2])
		f.SP--
	case 0x1c:
		if requireStack(f, 2) != 0 {
			return f.Status
		}
		evm256.Shr256(&f.Stack[f.SP-1], &f.Stack[f.SP-2], &f.Stack[f.SP-2])
		f.SP--
	case 0x1d:
		if requireStack(f, 2) != 0 {
			return f.Status
		}
		evm256.Sar256(&f.Stack[f.SP-1], &f.Stack[f.SP-2], &f.Stack[f.SP-2])
		f.SP--
	case 0x20:
		if requireStack(f, 2) != 0 {
			return f.Status
		}
		var off, sz uint64
		if u256AsU64(&f.Stack[f.SP-1], &off) < 0 {
			return haltEx(f, StatusOutOfGas)
		}
		if u256AsU64(&f.Stack[f.SP-2], &sz) < 0 {
			return haltEx(f, StatusOutOfGas)
		}
		if chargeMem(f, off, sz) < 0 {
			return haltEx(f, StatusOutOfGas)
		}
		words := (sz + 31) / 32
		if sz == 0 {
			words = 0
		}
		extra := 6 * words
		if f.Gas < extra {
			return haltEx(f, StatusOutOfGas)
		}
		f.Gas -= extra
		var digest [32]byte
		if sz == 0 {
			c2crypto.Keccak256(nil, &digest)
		} else {
			c2crypto.Keccak256(f.Memory[off:off+sz], &digest)
		}
		outv := evm256.FromBytesBE(digest[:])
		f.SP--
		f.Stack[f.SP-1] = outv
	case 0x50:
		if requireStack(f, 1) != 0 {
			return f.Status
		}
		f.SP--
	case 0x51:
		if requireStack(f, 1) != 0 {
			return f.Status
		}
		var off uint64
		if u256AsU64(&f.Stack[f.SP-1], &off) < 0 {
			return haltEx(f, StatusOutOfGas)
		}
		if chargeMem(f, off, 32) < 0 {
			return haltEx(f, StatusOutOfGas)
		}
		f.Stack[f.SP-1] = evm256.FromBytesBE(f.Memory[off : off+32])
	case 0x52:
		if requireStack(f, 2) != 0 {
			return f.Status
		}
		var off uint64
		if u256AsU64(&f.Stack[f.SP-1], &off) < 0 {
			return haltEx(f, StatusOutOfGas)
		}
		if chargeMem(f, off, 32) < 0 {
			return haltEx(f, StatusOutOfGas)
		}
		be := evm256.BytesBE(f.Stack[f.SP-2])
		copy(f.Memory[off:off+32], be[:])
		f.SP -= 2
	case 0x53:
		if requireStack(f, 2) != 0 {
			return f.Status
		}
		var off uint64
		if u256AsU64(&f.Stack[f.SP-1], &off) < 0 {
			return haltEx(f, StatusOutOfGas)
		}
		if chargeMem(f, off, 1) < 0 {
			return haltEx(f, StatusOutOfGas)
		}
		f.Memory[off] = byte(f.Stack[f.SP-2][0] & 0xff)
		f.SP -= 2
	case 0x54:
		if requireStack(f, 1) != 0 {
			return f.Status
		}
		if f.StateDB != nil {
			addr := zeroAddr()
			f.StateDB.GetStorage(&addr, &f.Stack[f.SP-1], &f.Stack[f.SP-1])
		} else {
			f.Stack[f.SP-1] = evm256.Uint256{}
		}
	case 0x55:
		if requireStack(f, 2) != 0 {
			return f.Status
		}
		if f.StateDB != nil {
			addr := zeroAddr()
			var old evm256.Uint256
			f.StateDB.GetStorage(&addr, &f.Stack[f.SP-1], &old)
			f.StateDB.SetStorage(&addr, &f.Stack[f.SP-1], &f.Stack[f.SP-2])
			if !evm256.IsZero(&old) && evm256.IsZero(&f.Stack[f.SP-2]) {
				f.Refund += 15000
			}
		}
		f.SP -= 2
	case 0x56:
		if requireStack(f, 1) != 0 {
			return f.Status
		}
		var dest uint64
		if u256AsU64(&f.Stack[f.SP-1], &dest) < 0 || dest > 0xffffffff || !jumpdestOK(code, uint32(dest)) {
			return haltEx(f, StatusJumpDestInvalid)
		}
		f.SP--
		f.PC = uint32(dest)
	case 0x57:
		if requireStack(f, 2) != 0 {
			return f.Status
		}
		take := !evm256.IsZero(&f.Stack[f.SP-2])
		if take {
			var dest uint64
			if u256AsU64(&f.Stack[f.SP-1], &dest) < 0 || dest > 0xffffffff || !jumpdestOK(code, uint32(dest)) {
				return haltEx(f, StatusJumpDestInvalid)
			}
			f.PC = uint32(dest)
		}
		f.SP -= 2
	case 0x58:
		if requireRoom(f) != 0 {
			return f.Status
		}
		f.Stack[f.SP] = evm256.FromU64(uint64(f.PC - 1))
		f.SP++
	case 0x59:
		if requireRoom(f) != 0 {
			return f.Status
		}
		f.Stack[f.SP] = evm256.FromU64(uint64(f.MemorySize))
		f.SP++
	case 0x5a:
		if requireRoom(f) != 0 {
			return f.Status
		}
		f.Stack[f.SP] = evm256.FromU64(f.Gas)
		f.SP++
	case 0x5b:
	case 0x5f:
		if requireRoom(f) != 0 {
			return f.Status
		}
		f.Stack[f.SP] = evm256.Uint256{}
		f.SP++
	case 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
		0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
		0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
		0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f:
		if execPush(f, code, uint(op-0x5f)) < 0 {
			return f.Status
		}
	case 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
		0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f:
		n := int32(op-0x80) + 1
		if requireStack(f, n) != 0 {
			return f.Status
		}
		if requireRoom(f) != 0 {
			return f.Status
		}
		f.Stack[f.SP] = f.Stack[f.SP-n]
		f.SP++
	case 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
		0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f:
		n := int32(op-0x90) + 1
		if requireStack(f, n+1) != 0 {
			return f.Status
		}
		t := f.Stack[f.SP-1]
		f.Stack[f.SP-1] = f.Stack[f.SP-1-n]
		f.Stack[f.SP-1-n] = t
	case 0xfd:
		if requireStack(f, 2) != 0 {
			return f.Status
		}
		var off, sz uint64
		if u256AsU64(&f.Stack[f.SP-1], &off) < 0 {
			return haltEx(f, StatusOutOfGas)
		}
		if u256AsU64(&f.Stack[f.SP-2], &sz) < 0 {
			return haltEx(f, StatusOutOfGas)
		}
		if chargeMem(f, off, sz) < 0 {
			return haltEx(f, StatusOutOfGas)
		}
		f.ReturnDataOffset = uint32(off)
		f.ReturnDataSize = uint32(sz)
		f.SP -= 2
		f.Status = StatusRevert
	default:
		return haltEx(f, StatusInvalidOpcode)
	}
	return f.Status
}
