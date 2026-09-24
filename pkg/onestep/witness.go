// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. See LICENSE and NOTICE.

package onestep

import (
	"encoding/binary"
	"errors"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2crypto"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2evm"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/statetrie"
)

var (
	ErrNilFrame     = errors.New("onestep: nil execution frame")
	ErrNilWitness   = errors.New("onestep: nil witness")
	ErrOpcode       = errors.New("onestep: unsupported opcode")
	ErrStack        = errors.New("onestep: insufficient stack depth")
	ErrPreRoot      = errors.New("onestep: invalid pre-state root")
	ErrPostRoot     = errors.New("onestep: invalid post-state root")
	ErrStackOut     = errors.New("onestep: invalid output stack")
	ErrStep         = errors.New("onestep: step transition rejected")
	ErrCode         = errors.New("onestep: invalid replay bytecode")
	ErrStorageProof = errors.New("onestep: invalid storage merkle proof")
)

const (
	abiWitnessWords = 19
	abiStateWords   = 11
	memCap          = 65536
	maxReplayCode   = 1 << 20
)

type StepWitness struct {
	PreStateRoot  [32]byte
	PostStateRoot [32]byte
	PC            uint32
	Opcode        uint8
	Gas           uint64
	StackIn       [4]evm256.Uint256
	StackOut      [4]evm256.Uint256
	MemOffset     uint32
	MemData       [32]byte
	StorageKey    evm256.Uint256
	StorageVal    evm256.Uint256
	StorageRoot   [32]byte
	StorageProof  [][]byte
}

type slotStore struct {
	key evm256.Uint256
	val evm256.Uint256
	set bool
}

func (s *slotStore) GetStorage(_, key, val *evm256.Uint256) {
	if s.set && *key == s.key {
		*val = s.val
		return
	}
	*val = evm256.Uint256{}
}

func (s *slotStore) SetStorage(_, key, val *evm256.Uint256) {
	s.key = *key
	s.val = *val
	s.set = true
}

func opcodeSupported(op byte) bool {
	switch op {
	case 0x01, 0x02, 0x03, 0x04, 0x16, 0x17, 0x18, 0x1b, 0x1c,
		0x51, 0x52, 0x54, 0x55, 0x56, 0x57:
		return true
	}
	if op >= 0x5f && op <= 0x7f {
		return true
	}
	if op >= 0x80 && op <= 0x82 {
		return true
	}
	if op >= 0x90 && op <= 0x92 {
		return true
	}
	return false
}

func inArity(op byte) int32 {
	switch {
	case op == 0x01 || op == 0x02 || op == 0x03 || op == 0x04 ||
		op == 0x16 || op == 0x17 || op == 0x18 || op == 0x1b || op == 0x1c:
		return 2
	case op == 0x51 || op == 0x54 || op == 0x56:
		return 1
	case op == 0x52 || op == 0x55 || op == 0x57:
		return 2
	case op >= 0x5f && op <= 0x7f:
		return 0
	case op >= 0x80 && op <= 0x8f:
		return int32(op-0x80) + 1
	case op >= 0x90 && op <= 0x9f:
		return int32(op-0x90) + 2
	}
	return 0
}

func outArity(op byte) int32 {
	switch {
	case op == 0x01 || op == 0x02 || op == 0x03 || op == 0x04 ||
		op == 0x16 || op == 0x17 || op == 0x18 || op == 0x1b || op == 0x1c:
		return 1
	case op == 0x51 || op == 0x54:
		return 1
	case op == 0x52 || op == 0x55 || op == 0x56 || op == 0x57:
		return 0
	case op >= 0x5f && op <= 0x7f:
		return 1
	case op >= 0x80 && op <= 0x8f:
		return int32(op-0x80) + 2
	case op >= 0x90 && op <= 0x9f:
		return int32(op-0x90) + 2
	}
	return 0
}

func asU64(x evm256.Uint256) (uint64, bool) {
	if (x[1] | x[2] | x[3]) != 0 {
		return 0, false
	}
	return x[0], true
}

func copyStackWindow(f *c2evm.ExecutionFrame, n int32) [4]evm256.Uint256 {
	var out [4]evm256.Uint256
	if n < 0 {
		return out
	}
	if n > 4 {
		n = 4
	}
	if n > f.SP {
		n = f.SP
	}
	base := f.SP - n
	for i := int32(0); i < n; i++ {
		out[i] = f.Stack[base+i]
	}
	return out
}

func extractMem(op byte, pre, post *c2evm.ExecutionFrame) (uint32, [32]byte) {
	var data [32]byte
	switch {
	case op == 0x51:
		off, ok := asU64(pre.Stack[pre.SP-1])
		if !ok || off > uint64(memCap-32) {
			return 0, data
		}
		copy(data[:], pre.Memory[off:off+32])
		return uint32(off), data
	case op == 0x52:
		off, ok := asU64(pre.Stack[pre.SP-1])
		if !ok || off > uint64(memCap-32) {
			return 0, data
		}
		copy(data[:], post.Memory[off:off+32])
		return uint32(off), data
	case op >= 0x60 && op <= 0x7f:
		if post.SP >= 1 {
			data = evm256.BytesBE(post.Stack[post.SP-1])
		}
		return 0, data
	}
	return 0, data
}

func extractStor(op byte, pre, post *c2evm.ExecutionFrame) (evm256.Uint256, evm256.Uint256) {
	switch op {
	case 0x54:
		if pre.SP >= 1 && post.SP >= 1 {
			return pre.Stack[pre.SP-1], post.Stack[post.SP-1]
		}
	case 0x55:
		if pre.SP >= 2 {
			return pre.Stack[pre.SP-1], pre.Stack[pre.SP-2]
		}
	}
	return evm256.Uint256{}, evm256.Uint256{}
}

func abiPutU32(dst []byte, v uint32) {
	binary.BigEndian.PutUint32(dst[28:32], v)
}

func abiPutU64(dst []byte, v uint64) {
	binary.BigEndian.PutUint64(dst[24:32], v)
}

func abiPutU8(dst []byte, v uint8) {
	dst[31] = v
}

func hashState(pc uint32, gas uint64, stack [4]evm256.Uint256, memOff uint32, mem [32]byte, storageRoot [32]byte, key, val evm256.Uint256) [32]byte {
	buf := make([]byte, abiStateWords*32)
	abiPutU32(buf[0:32], pc)
	abiPutU64(buf[32:64], gas)
	for i := 0; i < 4; i++ {
		be := evm256.BytesBE(stack[i])
		copy(buf[64+i*32:96+i*32], be[:])
	}
	abiPutU32(buf[192:224], memOff)
	copy(buf[224:256], mem[:])
	copy(buf[256:288], storageRoot[:])
	k := evm256.BytesBE(key)
	copy(buf[288:320], k[:])
	v := evm256.BytesBE(val)
	copy(buf[320:352], v[:])
	var out [32]byte
	c2crypto.Keccak256(buf, &out)
	return out
}

func CaptureWitness(preFrame, postFrame *c2evm.ExecutionFrame, op byte) (*StepWitness, error) {
	if preFrame == nil || postFrame == nil {
		return nil, ErrNilFrame
	}
	if !opcodeSupported(op) {
		return nil, ErrOpcode
	}
	need := inArity(op)
	if preFrame.SP < need {
		return nil, ErrStack
	}
	memOff, memData := extractMem(op, preFrame, postFrame)
	skey, sval := extractStor(op, preFrame, postFrame)
	w := &StepWitness{
		PC:         preFrame.PC,
		Opcode:     op,
		Gas:        preFrame.Gas,
		StackIn:    copyStackWindow(preFrame, need),
		StackOut:   copyStackWindow(postFrame, outArity(op)),
		MemOffset:  memOff,
		MemData:    memData,
		StorageKey: skey,
		StorageVal: sval,
	}
	w.PreStateRoot = hashState(preFrame.PC, preFrame.Gas, w.StackIn, w.MemOffset, w.MemData, w.StorageRoot, w.StorageKey, w.StorageVal)
	w.PostStateRoot = hashState(postFrame.PC, postFrame.Gas, w.StackOut, w.MemOffset, w.MemData, w.StorageRoot, w.StorageKey, w.StorageVal)
	return w, nil
}

// CaptureWitnessWithStorage capture le même pas que CaptureWitness et, pour un
// SLOAD (0x54) ou un SSTORE (0x55), y joint la racine de stockage du compte et
// la preuve Merkle Patricia Trie du slot engagé. Un trie nil laisse le témoin
// sans preuve, ce qui préserve le chemin de vérification local.
func CaptureWitnessWithStorage(preFrame, postFrame *c2evm.ExecutionFrame, op byte, trie *statetrie.StateTrie, addr evm256.Uint256) (*StepWitness, error) {
	w, err := CaptureWitness(preFrame, postFrame, op)
	if err != nil {
		return nil, err
	}
	if trie == nil || (op != 0x54 && op != 0x55) {
		return w, nil
	}
	root, proof, err := trie.GenerateStorageProof(addr, w.StorageKey)
	if err != nil {
		return nil, err
	}
	w.StorageRoot = root
	w.StorageProof = proof
	w.PreStateRoot = hashState(preFrame.PC, preFrame.Gas, w.StackIn, w.MemOffset, w.MemData, w.StorageRoot, w.StorageKey, w.StorageVal)
	w.PostStateRoot = hashState(postFrame.PC, postFrame.Gas, w.StackOut, w.MemOffset, w.MemData, w.StorageRoot, w.StorageKey, w.StorageVal)
	return w, nil
}

func reconstructCode(w *StepWitness) ([]byte, error) {
	op := w.Opcode
	pc := w.PC
	npush := 0
	if op >= 0x60 && op <= 0x7f {
		npush = int(op - 0x5f)
	}
	end := int(pc) + 1 + npush
	var dest uint32
	hasJump := op == 0x56 || op == 0x57
	taken := false
	if hasJump {
		var top evm256.Uint256
		if op == 0x56 {
			top = w.StackIn[0]
			taken = true
		} else {
			top = w.StackIn[1]
			taken = !evm256.IsZero(&w.StackIn[0])
		}
		d, ok := asU64(top)
		if !ok || d > 0xffffffff {
			return nil, ErrCode
		}
		dest = uint32(d)
		if taken && int(dest)+1 > end {
			end = int(dest) + 1
		}
	}
	if end <= 0 || end > maxReplayCode {
		return nil, ErrCode
	}
	code := make([]byte, end)
	code[pc] = op
	if npush > 0 {
		copy(code[int(pc)+1:], w.MemData[32-npush:])
	}
	if hasJump && taken && dest != pc {
		code[dest] = 0x5b
	}
	return code, nil
}

func reconstructFrame(w *StepWitness) (*c2evm.ExecutionFrame, error) {
	f := new(c2evm.ExecutionFrame)
	f.Reset(w.Gas)
	f.PC = w.PC
	n := inArity(w.Opcode)
	if n > 4 {
		return nil, ErrStack
	}
	f.SP = n
	for i := int32(0); i < n; i++ {
		f.Stack[i] = w.StackIn[i]
	}
	switch w.Opcode {
	case 0x51:
		off := w.MemOffset
		if off > memCap-32 {
			return nil, ErrCode
		}
		copy(f.Memory[off:off+32], w.MemData[:])
		words := (uint64(off) + 32 + 31) / 32
		f.MemorySize = uint32(words * 32)
	case 0x54:
		f.StateDB = &slotStore{key: w.StorageKey, val: w.StorageVal, set: true}
	case 0x55:
		f.StateDB = &slotStore{}
	}
	return f, nil
}

func VerifyWitness(w *StepWitness) (bool, error) {
	if w == nil {
		return false, ErrNilWitness
	}
	if !opcodeSupported(w.Opcode) {
		return false, ErrOpcode
	}
	pre := hashState(w.PC, w.Gas, w.StackIn, w.MemOffset, w.MemData, w.StorageRoot, w.StorageKey, w.StorageVal)
	if pre != w.PreStateRoot {
		return false, ErrPreRoot
	}
	code, err := reconstructCode(w)
	if err != nil {
		return false, err
	}
	f, err := reconstructFrame(w)
	if err != nil {
		return false, err
	}
	st := c2evm.StepOne(f, code)
	if st != c2evm.StatusRunning && st != c2evm.StatusSuccess {
		return false, ErrStep
	}
	got := copyStackWindow(f, outArity(w.Opcode))
	if got != w.StackOut {
		return false, ErrStackOut
	}
	if w.Opcode == 0x55 {
		db, ok := f.StateDB.(*slotStore)
		if !ok || !db.set || db.key != w.StorageKey || db.val != w.StorageVal {
			return false, ErrStep
		}
	}
	post := hashState(f.PC, f.Gas, w.StackOut, w.MemOffset, w.MemData, w.StorageRoot, w.StorageKey, w.StorageVal)
	if post != w.PostStateRoot {
		return false, ErrPostRoot
	}
	if w.Opcode == 0x54 || w.Opcode == 0x55 {
		if len(w.StorageProof) == 0 {
			if w.StorageRoot != ([32]byte{}) {
				return false, ErrStorageProof
			}
		} else {
			if w.StorageRoot == ([32]byte{}) {
				return false, ErrStorageProof
			}
			var keyHash [32]byte
			be := evm256.BytesBE(w.StorageKey)
			c2crypto.Keccak256(be[:], &keyHash)
			expected := statetrie.EncodeStorageValue(w.StorageVal)
			if !statetrie.VerifyStorageProof(w.StorageRoot, keyHash, expected, w.StorageProof) {
				return false, ErrStorageProof
			}
		}
	}
	return true, nil
}

func EncodeWitnessABI(w *StepWitness) []byte {
	if w == nil {
		return nil
	}
	tupleOffset := 32
	head := abiWitnessWords * 32
	tail := 32
	n := len(w.StorageProof)
	tail += n * 32
	elems := make([]int, n)
	for i, p := range w.StorageProof {
		elems[i] = ((len(p) + 31) / 32) * 32
		tail += 32 + elems[i]
	}
	buf := make([]byte, tupleOffset+head+tail)
	binary.BigEndian.PutUint64(buf[24:32], uint64(tupleOffset))
	base := tupleOffset
	copy(buf[base:base+32], w.PreStateRoot[:])
	copy(buf[base+32:base+64], w.PostStateRoot[:])
	abiPutU32(buf[base+64:base+96], w.PC)
	abiPutU8(buf[base+96:base+128], w.Opcode)
	abiPutU64(buf[base+128:base+160], w.Gas)
	for i := 0; i < 4; i++ {
		be := evm256.BytesBE(w.StackIn[i])
		copy(buf[base+160+i*32:base+192+i*32], be[:])
	}
	for i := 0; i < 4; i++ {
		be := evm256.BytesBE(w.StackOut[i])
		copy(buf[base+288+i*32:base+320+i*32], be[:])
	}
	abiPutU32(buf[base+416:base+448], w.MemOffset)
	copy(buf[base+448:base+480], w.MemData[:])
	k := evm256.BytesBE(w.StorageKey)
	copy(buf[base+480:base+512], k[:])
	v := evm256.BytesBE(w.StorageVal)
	copy(buf[base+512:base+544], v[:])
	copy(buf[base+544:base+576], w.StorageRoot[:])
	binary.BigEndian.PutUint64(buf[base+576+24:base+608], uint64(head))
	dataBase := base + head
	binary.BigEndian.PutUint64(buf[dataBase+24:dataBase+32], uint64(n))
	off := dataBase + 32
	dataOff := dataBase + 32 + n*32
	for i := 0; i < n; i++ {
		binary.BigEndian.PutUint64(buf[off+24:off+32], uint64(dataOff-(dataBase+32)))
		off += 32
		binary.BigEndian.PutUint64(buf[dataOff+24:dataOff+32], uint64(len(w.StorageProof[i])))
		dataOff += 32
		copy(buf[dataOff:], w.StorageProof[i])
		dataOff += elems[i]
	}
	return buf
}
