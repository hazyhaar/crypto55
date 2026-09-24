// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. See LICENSE and NOTICE.

package c2block

import (
	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2crypto"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2evm"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/statetrie"
)

const (
	maxCallDepth   = 1024
	maxCodeSize    = 24576
	maxInitSize    = 49152
	gasCallStipend = 2300
	gasCallValue   = 9000
	gasNewAccount  = 25000
	gasCreate      = 32000
	gasCodeDeposit = 200
	gasLog         = 375
	gasLogTopic    = 375
	gasLogData     = 8
	gasCallWarm    = 100
	gasCopyWord    = 3
)

type boundState struct {
	trie     *statetrie.StateTrie
	addr     evm256.Uint256
	readOnly bool
	wrote    bool
}

func (b *boundState) GetStorage(addr, key, val *evm256.Uint256) {
	b.trie.GetStorage(&b.addr, key, val)
}

func (b *boundState) SetStorage(addr, key, val *evm256.Uint256) {
	if b.readOnly {
		b.wrote = true
		return
	}
	b.trie.SetStorage(&b.addr, key, val)
}

type vmEnv struct {
	state         *statetrie.StateTrie
	header        *BlockHeader
	origin        Address
	gasPrice      evm256.Uint256
	logs          []*Log
	retData       []byte
	depth         int
	refund        uint64
	touched        map[Address]bool
	touchJournal   []Address
	createdInTx    map[Address]bool
	createJournal  []Address
	suicided       map[Address]bool
	suicideJournal []Address
}

type callParams struct {
	caller   Address
	addr     Address
	codeAddr Address
	origin   Address
	value    evm256.Uint256
	callVal  evm256.Uint256
	data     []byte
	code     []byte
	gas      uint64
	readOnly bool
	kind     byte
}

func eip150(available uint64) uint64 {
	return available - available/64
}

func callGas(available, requested uint64) uint64 {
	max := eip150(available)
	if requested > max {
		return max
	}
	return requested
}

func addrToU256(a Address) evm256.Uint256 {
	var b [32]byte
	copy(b[12:], a[:])
	return evm256.FromBytesBE(b[:])
}

func u256ToAddr(z evm256.Uint256) Address {
	be := evm256.BytesBE(z)
	var a Address
	copy(a[:], be[12:])
	return a
}

func isPrecompile(a Address) (uint64, bool) {
	for i := 0; i < 19; i++ {
		if a[i] != 0 {
			return 0, false
		}
	}
	if a[19] >= 1 && a[19] <= 10 {
		return uint64(a[19]), true
	}
	return 0, false
}

func (e *vmEnv) account(addr Address) *statetrie.Account {
	a := addrToU256(addr)
	acc, ok := e.state.GetAccount(&a)
	if !ok {
		return &statetrie.Account{}
	}
	return acc
}

func (e *vmEnv) codeOf(addr Address) []byte {
	if _, ok := isPrecompile(addr); ok {
		return nil
	}
	return e.account(addr).Code
}

func (e *vmEnv) setCode(addr Address, code []byte) {
	a := addrToU256(addr)
	acc, ok := e.state.GetAccount(&a)
	if !ok {
		acc = &statetrie.Account{}
	}
	acc.Code = append([]byte(nil), code...)
	var h [32]byte
	c2crypto.Keccak256(code, &h)
	acc.CodeHash = h
	e.state.SetAccount(&a, acc)
}

func (e *vmEnv) setNonce(addr Address, n uint64) {
	a := addrToU256(addr)
	acc, ok := e.state.GetAccount(&a)
	if !ok {
		acc = &statetrie.Account{}
	}
	acc.Nonce = n
	e.state.SetAccount(&a, acc)
}

func (e *vmEnv) getNonce(addr Address) uint64 {
	return e.account(addr).Nonce
}

func (e *vmEnv) transfer(from, to Address, val evm256.Uint256) error {
	e.touch(from)
	e.touch(to)
	if evm256.IsZero(&val) {
		return nil
	}
	fa := addrToU256(from)
	ta := addrToU256(to)
	if err := e.state.SubBalance(&fa, &val); err != nil {
		return err
	}
	e.state.AddBalance(&ta, &val)
	return nil
}

func (e *vmEnv) emptyAccount(addr Address) bool {
	acc := e.account(addr)
	return acc.Nonce == 0 && evm256.IsZero(&acc.Balance) && len(acc.Code) == 0
}

func (e *vmEnv) touch(a Address) {
	if e.touched == nil {
		e.touched = make(map[Address]bool)
	}
	if !e.touched[a] {
		e.touched[a] = true
		e.touchJournal = append(e.touchJournal, a)
	}
}

func (e *vmEnv) markCreated(a Address) {
	if e.createdInTx == nil {
		e.createdInTx = make(map[Address]bool)
	}
	if !e.createdInTx[a] {
		e.createdInTx[a] = true
		e.createJournal = append(e.createJournal, a)
	}
}

func (e *vmEnv) revertTouched(mark int) {
	for i := len(e.touchJournal) - 1; i >= mark; i-- {
		a := e.touchJournal[i]
		delete(e.touched, a)
	}
	e.touchJournal = e.touchJournal[:mark]
}

func (e *vmEnv) revertCreated(mark int) {
	for i := len(e.createJournal) - 1; i >= mark; i-- {
		a := e.createJournal[i]
		delete(e.createdInTx, a)
	}
	e.createJournal = e.createJournal[:mark]
}

func (e *vmEnv) markSuicided(a Address) {
	if e.suicided == nil {
		e.suicided = make(map[Address]bool)
	}
	if !e.suicided[a] {
		e.suicided[a] = true
		e.suicideJournal = append(e.suicideJournal, a)
	}
}

func (e *vmEnv) revertSuicided(mark int) {
	for i := len(e.suicideJournal) - 1; i >= mark; i-- {
		a := e.suicideJournal[i]
		delete(e.suicided, a)
	}
	e.suicideJournal = e.suicideJournal[:mark]
}

func (e *vmEnv) cleanTouchedEmptyAccounts() {
	for a := range e.touched {
		if e.emptyAccount(a) {
			ua := addrToU256(a)
			e.state.SetAccount(&ua, nil)
		}
	}
	for a := range e.suicided {
		if e.createdInTx != nil && e.createdInTx[a] {
			ua := addrToU256(a)
			e.state.SetAccount(&ua, nil)
		}
	}
}

func createAddress(sender Address, nonce uint64) Address {
	enc := rlpListEnc(rlpBytesEnc(sender[:]), rlpU64Enc(nonce))
	h := keccak32(enc)
	var a Address
	copy(a[:], h[12:])
	return a
}

func create2Address(sender Address, salt Hash, initHash Hash) Address {
	buf := make([]byte, 1+20+32+32)
	buf[0] = 0xff
	copy(buf[1:21], sender[:])
	copy(buf[21:53], salt[:])
	copy(buf[53:], initHash[:])
	h := keccak32(buf)
	var a Address
	copy(a[:], h[12:])
	return a
}

func (e *vmEnv) run(p callParams) (ret []byte, left uint64, ok bool) {
	if e.depth >= maxCallDepth {
		return nil, p.gas, false
	}
	e.depth++
	defer func() { e.depth-- }()

	logMark := len(e.logs)
	touchMark := len(e.touchJournal)
	createMark := len(e.createJournal)
	suicideMark := len(e.suicideJournal)
	rev := e.state.Snapshot()

	if p.kind == 0xf0 || p.kind == 0xf5 {
		e.markCreated(p.addr)
	}

	e.touch(p.caller)
	e.touch(p.addr)

	if p.kind != 0xf4 {
		if err := e.transfer(p.caller, p.addr, p.callVal); err != nil {
			e.state.RevertToSnapshot(rev)
			e.logs = e.logs[:logMark]
			e.revertTouched(touchMark)
			e.revertCreated(createMark)
			e.revertSuicided(suicideMark)
			return nil, p.gas, false
		}
	}

	pcAddr := p.addr
	if p.codeAddr != (Address{}) {
		pcAddr = p.codeAddr
	}
	if id, isPC := isPrecompile(pcAddr); isPC && p.kind != 0xf0 && p.kind != 0xf5 {
		out, g, err := RunPrecompile(id, p.data, p.gas)
		if err != nil {
			e.state.RevertToSnapshot(rev)
			e.logs = e.logs[:logMark]
			e.revertTouched(touchMark)
			e.revertCreated(createMark)
			e.revertSuicided(suicideMark)
			return nil, 0, false
		}
		e.retData = out
		return out, g, true
	}

	code := p.code
	if p.kind != 0xf0 && p.kind != 0xf5 && p.kind != 0xf2 && p.kind != 0xf4 {
		code = e.codeOf(p.addr)
	}
	if len(code) == 0 && p.kind != 0xf0 && p.kind != 0xf5 {
		e.retData = nil
		return nil, p.gas, true
	}

	f := new(c2evm.ExecutionFrame)
	bs := &boundState{trie: e.state, addr: addrToU256(p.addr), readOnly: p.readOnly}
	f.StateDB = bs
	f.Reset(p.gas)
	ret, status := e.execFrame(f, p, code, bs)
	if bs.wrote {
		status = c2evm.StatusInvalidOpcode
		f.Gas = 0
	}
	if status != c2evm.StatusSuccess {
		e.state.RevertToSnapshot(rev)
		e.logs = e.logs[:logMark]
		e.revertTouched(touchMark)
		e.revertCreated(createMark)
		e.revertSuicided(suicideMark)
		e.retData = ret
		if status == c2evm.StatusRevert {
			return ret, f.Gas, false
		}
		return ret, 0, false
	}
	e.refund += f.Refund
	if p.kind == 0xf0 || p.kind == 0xf5 {
		if e.suicided != nil && e.suicided[p.addr] {
			e.retData = nil
			return nil, f.Gas, true
		}
		if len(ret) > maxCodeSize {
			e.state.RevertToSnapshot(rev)
			e.logs = e.logs[:logMark]
			e.revertTouched(touchMark)
			e.revertCreated(createMark)
			e.revertSuicided(suicideMark)
			return nil, 0, false
		}
		deposit := uint64(len(ret)) * gasCodeDeposit
		if f.Gas < deposit {
			e.state.RevertToSnapshot(rev)
			e.logs = e.logs[:logMark]
			e.revertTouched(touchMark)
			e.revertCreated(createMark)
			e.revertSuicided(suicideMark)
			return nil, 0, false
		}
		f.Gas -= deposit
		e.setCode(p.addr, ret)
		e.setNonce(p.addr, 1)
		e.markCreated(p.addr)
	}
	e.retData = ret
	return ret, f.Gas, true
}

func (e *vmEnv) execFrame(f *c2evm.ExecutionFrame, p callParams, code []byte, bs *boundState) ([]byte, int) {
	for f.Status == c2evm.StatusRunning {
		if int(f.PC) >= len(code) {
			f.Status = c2evm.StatusSuccess
			break
		}
		op := code[f.PC]
		if p.readOnly && (op == 0x55 || op == 0xf0 || op == 0xf5 || op == 0xff || (op >= 0xa0 && op <= 0xa4)) {
			f.Status = c2evm.StatusInvalidOpcode
			f.Gas = 0
			break
		}
		if isHostOp(op) {
			e.execHost(f, p, code, op)
			continue
		}
		c2evm.StepOne(f, code)
	}
	if f.Status == c2evm.StatusSuccess || f.Status == c2evm.StatusRevert {
		off := f.ReturnDataOffset
		sz := f.ReturnDataSize
		if sz == 0 {
			return nil, f.Status
		}
		end := uint64(off) + uint64(sz)
		if end > uint64(len(f.Memory)) {
			return nil, c2evm.StatusOutOfGas
		}
		return append([]byte(nil), f.Memory[off:end]...), f.Status
	}
	return nil, f.Status
}

func isHostOp(op byte) bool {
	switch {
	case op >= 0x30 && op <= 0x48:
		return true
	case op >= 0xa0 && op <= 0xa4:
		return true
	case op == 0xf0, op == 0xf1, op == 0xf2, op == 0xf3, op == 0xf4, op == 0xf5, op == 0xfa, op == 0xff:
		return true
	default:
		return false
	}
}

func hostGas(op byte) uint64 {
	switch op {
	case 0x30, 0x32, 0x33, 0x34, 0x36, 0x38, 0x3a, 0x3d, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x48:
		return 2
	case 0x35:
		return 3
	case 0x37, 0x39, 0x3e:
		return 3
	case 0x31, 0x3b, 0x3c, 0x3f:
		return 2600
	case 0x40:
		return 20
	case 0x47:
		return 5
	case 0xf0, 0xf5:
		return gasCreate
	case 0xf1, 0xf2, 0xf4, 0xfa:
		return gasCallWarm
	case 0xf3:
		return 0
	case 0xff:
		// SELFDESTRUCT : tarification statique forfaitaire L2 fixée à 5000 gaz (coût de base EIP-150).
		// Contrairement à Ethereum L1 (EIP-161 / EIP-2929) qui applique des surcoûts dynamiques
		// (25000 gaz si le bénéficiaire est vide, 2600 gaz d'accès froid), le micro-noyau L2 c2evm
		// applique un barème prévisible et déterministe, analogue aux 5000 gaz statiques de SSTORE.
		return 5000
	default:
		if op >= 0xa0 && op <= 0xa4 {
			return gasLog
		}
		return 0
	}
}

func requireStack(f *c2evm.ExecutionFrame, n int32) bool {
	if f.SP < n {
		f.Status = c2evm.StatusStackUnderflow
		f.Gas = 0
		return false
	}
	return true
}

func requireRoom(f *c2evm.ExecutionFrame) bool {
	if f.SP >= 1024 {
		f.Status = c2evm.StatusStackOverflow
		f.Gas = 0
		return false
	}
	return true
}

func asU64(x *evm256.Uint256) (uint64, bool) {
	if (x[1] | x[2] | x[3]) != 0 {
		return 0, false
	}
	return x[0], true
}

func chargeMem(f *c2evm.ExecutionFrame, offset, size uint64) bool {
	if size == 0 {
		return true
	}
	const memMax = 65536
	if offset >= memMax || size > memMax-offset {
		return false
	}
	end := offset + size
	words := (end + 31) / 32
	newSize := words * 32
	if newSize > memMax {
		return false
	}
	if newSize <= uint64(f.MemorySize) {
		return true
	}
	oldWords := (uint64(f.MemorySize) + 31) / 32
	oldCost := 3*oldWords + (oldWords*oldWords)/512
	newCost := 3*words + (words*words)/512
	if newCost < oldCost || f.Gas < newCost-oldCost {
		return false
	}
	f.Gas -= newCost - oldCost
	f.MemorySize = uint32(newSize)
	return true
}

func haltOOG(f *c2evm.ExecutionFrame) {
	f.Status = c2evm.StatusOutOfGas
	f.Gas = 0
}

func (e *vmEnv) execHost(f *c2evm.ExecutionFrame, p callParams, code []byte, op byte) {
	cost := hostGas(op)
	if f.Gas < cost {
		haltOOG(f)
		return
	}
	f.Gas -= cost
	f.PC++
	switch op {
	case 0x30:
		if !requireRoom(f) {
			return
		}
		f.Stack[f.SP] = addrToU256(p.addr)
		f.SP++
	case 0x31:
		if !requireStack(f, 1) {
			return
		}
		a := u256ToAddr(f.Stack[f.SP-1])
		ua := addrToU256(a)
		e.state.GetBalance(&ua, &f.Stack[f.SP-1])
	case 0x32:
		if !requireRoom(f) {
			return
		}
		f.Stack[f.SP] = addrToU256(p.origin)
		f.SP++
	case 0x33:
		if !requireRoom(f) {
			return
		}
		f.Stack[f.SP] = addrToU256(p.caller)
		f.SP++
	case 0x34:
		if !requireRoom(f) {
			return
		}
		f.Stack[f.SP] = p.callVal
		f.SP++
	case 0x35:
		if !requireStack(f, 1) {
			return
		}
		off, ok := asU64(&f.Stack[f.SP-1])
		if !ok {
			f.Stack[f.SP-1] = evm256.Uint256{}
			return
		}
		var buf [32]byte
		for i := uint64(0); i < 32; i++ {
			idx := off + i
			if idx < uint64(len(p.data)) {
				buf[i] = p.data[idx]
			}
		}
		f.Stack[f.SP-1] = evm256.FromBytesBE(buf[:])
	case 0x36:
		if !requireRoom(f) {
			return
		}
		f.Stack[f.SP] = evm256.FromU64(uint64(len(p.data)))
		f.SP++
	case 0x37:
		e.opCopy(f, p.data)
	case 0x38:
		if !requireRoom(f) {
			return
		}
		f.Stack[f.SP] = evm256.FromU64(uint64(len(code)))
		f.SP++
	case 0x39:
		e.opCopy(f, code)
	case 0x3a:
		if !requireRoom(f) {
			return
		}
		f.Stack[f.SP] = e.gasPrice
		f.SP++
	case 0x3b:
		if !requireStack(f, 1) {
			return
		}
		a := u256ToAddr(f.Stack[f.SP-1])
		f.Stack[f.SP-1] = evm256.FromU64(uint64(len(e.codeOf(a))))
	case 0x3c:
		if !requireStack(f, 4) {
			return
		}
		a := u256ToAddr(f.Stack[f.SP-1])
		memOff, ok1 := asU64(&f.Stack[f.SP-2])
		codeOff, ok2 := asU64(&f.Stack[f.SP-3])
		sz, ok3 := asU64(&f.Stack[f.SP-4])
		f.SP -= 4
		if !ok1 || !ok2 || !ok3 {
			haltOOG(f)
			return
		}
		src := e.codeOf(a)
		e.copyBytes(f, memOff, sz, src, codeOff)
	case 0x3d:
		if !requireRoom(f) {
			return
		}
		f.Stack[f.SP] = evm256.FromU64(uint64(len(e.retData)))
		f.SP++
	case 0x3e:
		e.opCopy(f, e.retData)
	case 0x3f:
		if !requireStack(f, 1) {
			return
		}
		a := u256ToAddr(f.Stack[f.SP-1])
		acc := e.account(a)
		if e.emptyAccount(a) {
			f.Stack[f.SP-1] = evm256.Uint256{}
		} else {
			f.Stack[f.SP-1] = evm256.FromBytesBE(acc.CodeHash[:])
		}
	case 0x40:
		if !requireStack(f, 1) {
			return
		}
		f.Stack[f.SP-1] = evm256.Uint256{}
	case 0x41:
		if !requireRoom(f) {
			return
		}
		f.Stack[f.SP] = addrToU256(e.header.Coinbase)
		f.SP++
	case 0x42:
		if !requireRoom(f) {
			return
		}
		f.Stack[f.SP] = evm256.FromU64(e.header.Timestamp)
		f.SP++
	case 0x43:
		if !requireRoom(f) {
			return
		}
		f.Stack[f.SP] = evm256.FromU64(e.header.Number)
		f.SP++
	case 0x44:
		if !requireRoom(f) {
			return
		}
		f.Stack[f.SP] = e.header.Difficulty
		f.SP++
	case 0x45:
		if !requireRoom(f) {
			return
		}
		f.Stack[f.SP] = evm256.FromU64(e.header.GasLimit)
		f.SP++
	case 0x46:
		if !requireRoom(f) {
			return
		}
		f.Stack[f.SP] = e.header.ChainID
		f.SP++
	case 0x47:
		if !requireRoom(f) {
			return
		}
		ua := addrToU256(p.addr)
		e.state.GetBalance(&ua, &f.Stack[f.SP])
		f.SP++
	case 0x48:
		if !requireRoom(f) {
			return
		}
		f.Stack[f.SP] = e.header.BaseFee
		f.SP++
	case 0xa0, 0xa1, 0xa2, 0xa3, 0xa4:
		e.opLog(f, p.addr, int(op-0xa0))
	case 0xf3:
		e.opReturn(f, false)
	case 0xf0:
		e.opCreate(f, p, false)
	case 0xf5:
		e.opCreate(f, p, true)
	case 0xf1:
		e.opCall(f, p, 0xf1)
	case 0xf2:
		e.opCall(f, p, 0xf2)
	case 0xf4:
		e.opCall(f, p, 0xf4)
	case 0xfa:
		e.opCall(f, p, 0xfa)
	case 0xff:
		if !requireStack(f, 1) {
			return
		}
		beneficiary := u256ToAddr(f.Stack[f.SP-1])
		f.SP--
		bal := e.account(p.addr).Balance
		e.transfer(p.addr, beneficiary, bal)
		e.touch(p.addr)
		e.touch(beneficiary)
		e.markSuicided(p.addr)
		// EIP-6780 (Cancun) : le compte n'est supprimé du StateTrie que s'il
		// a été créé dans la même transaction. S'il s'agit d'un compte préexistant,
		// seul son solde est transféré vers le bénéficiaire.
		if e.createdInTx != nil && e.createdInTx[p.addr] {
			ua := addrToU256(p.addr)
			e.state.SetAccount(&ua, nil)
		}
		f.Status = c2evm.StatusSuccess
	default:
		f.Status = c2evm.StatusInvalidOpcode
		f.Gas = 0
	}
}

func (e *vmEnv) opCopy(f *c2evm.ExecutionFrame, src []byte) {
	if !requireStack(f, 3) {
		return
	}
	memOff, ok1 := asU64(&f.Stack[f.SP-1])
	dataOff, ok2 := asU64(&f.Stack[f.SP-2])
	sz, ok3 := asU64(&f.Stack[f.SP-3])
	f.SP -= 3
	if !ok1 || !ok2 || !ok3 {
		haltOOG(f)
		return
	}
	e.copyBytes(f, memOff, sz, src, dataOff)
}

func (e *vmEnv) copyBytes(f *c2evm.ExecutionFrame, memOff, sz uint64, src []byte, srcOff uint64) {
	if !chargeMem(f, memOff, sz) {
		haltOOG(f)
		return
	}
	words := words32(int(sz))
	cost := gasCopyWord * words
	if f.Gas < cost {
		haltOOG(f)
		return
	}
	f.Gas -= cost
	for i := uint64(0); i < sz; i++ {
		var b byte
		idx := srcOff + i
		if idx < uint64(len(src)) {
			b = src[idx]
		}
		f.Memory[memOff+i] = b
	}
}

func (e *vmEnv) opReturn(f *c2evm.ExecutionFrame, revert bool) {
	if !requireStack(f, 2) {
		return
	}
	off, ok1 := asU64(&f.Stack[f.SP-1])
	sz, ok2 := asU64(&f.Stack[f.SP-2])
	if !ok1 || !ok2 {
		haltOOG(f)
		return
	}
	if !chargeMem(f, off, sz) {
		haltOOG(f)
		return
	}
	f.ReturnDataOffset = uint32(off)
	f.ReturnDataSize = uint32(sz)
	f.SP -= 2
	if revert {
		f.Status = c2evm.StatusRevert
	} else {
		f.Status = c2evm.StatusSuccess
	}
}

func (e *vmEnv) opLog(f *c2evm.ExecutionFrame, addr Address, nTopics int) {
	need := int32(2 + nTopics)
	if !requireStack(f, need) {
		return
	}
	off, ok1 := asU64(&f.Stack[f.SP-1])
	sz, ok2 := asU64(&f.Stack[f.SP-2])
	if !ok1 || !ok2 {
		haltOOG(f)
		return
	}
	if !chargeMem(f, off, sz) {
		haltOOG(f)
		return
	}
	extra := uint64(nTopics)*gasLogTopic + sz*gasLogData
	if f.Gas < extra {
		haltOOG(f)
		return
	}
	f.Gas -= extra
	topics := make([]Hash, nTopics)
	for i := 0; i < nTopics; i++ {
		be := evm256.BytesBE(f.Stack[f.SP-3-int32(i)])
		copy(topics[i][:], be[:])
	}
	data := append([]byte(nil), f.Memory[off:off+sz]...)
	e.logs = append(e.logs, &Log{Address: addr, Topics: topics, Data: data})
	f.SP -= need
}

func (e *vmEnv) opCreate(f *c2evm.ExecutionFrame, p callParams, is2 bool) {
	n := int32(3)
	if is2 {
		n = 4
	}
	if !requireStack(f, n) {
		return
	}
	val := f.Stack[f.SP-1]
	off, ok1 := asU64(&f.Stack[f.SP-2])
	sz, ok2 := asU64(&f.Stack[f.SP-3])
	if !ok1 || !ok2 {
		haltOOG(f)
		return
	}
	var salt Hash
	if is2 {
		be := evm256.BytesBE(f.Stack[f.SP-4])
		copy(salt[:], be[:])
	}
	f.SP -= n
	if !chargeMem(f, off, sz) {
		haltOOG(f)
		return
	}
	if sz > maxInitSize {
		haltOOG(f)
		return
	}
	words := words32(int(sz))
	if f.Gas < words*2 {
		haltOOG(f)
		return
	}
	f.Gas -= words * 2
	init := append([]byte(nil), f.Memory[off:off+sz]...)
	nonce := e.getNonce(p.addr)
	e.setNonce(p.addr, nonce+1)
	var dest Address
	if is2 {
		h := keccak32(init)
		dest = create2Address(p.addr, salt, h)
	} else {
		dest = createAddress(p.addr, nonce)
	}
	if !e.emptyAccount(dest) && len(e.codeOf(dest)) != 0 {
		if !requireRoom(f) {
			return
		}
		f.Stack[f.SP] = evm256.Uint256{}
		f.SP++
		return
	}
	fwd := eip150(f.Gas)
	f.Gas -= fwd
	kind := byte(0xf0)
	if is2 {
		kind = 0xf5
	}
	_, left, ok := e.run(callParams{
		caller:  p.addr,
		addr:    dest,
		origin:  p.origin,
		value:   val,
		callVal: val,
		data:    nil,
		code:    init,
		gas:     fwd,
		kind:    kind,
	})
	f.Gas += left
	if !requireRoom(f) {
		return
	}
	if ok {
		f.Stack[f.SP] = addrToU256(dest)
	} else {
		f.Stack[f.SP] = evm256.Uint256{}
	}
	f.SP++
}

func (e *vmEnv) opCall(f *c2evm.ExecutionFrame, p callParams, kind byte) {
	n := int32(7)
	if kind == 0xf4 || kind == 0xfa {
		n = 6
	}
	if !requireStack(f, n) {
		return
	}
	reqGas, ok0 := asU64(&f.Stack[f.SP-1])
	to := u256ToAddr(f.Stack[f.SP-2])
	var val evm256.Uint256
	idx := int32(3)
	if kind == 0xf1 || kind == 0xf2 {
		val = f.Stack[f.SP-3]
		idx = 4
	}
	inOff, ok1 := asU64(&f.Stack[f.SP-idx])
	inSz, ok2 := asU64(&f.Stack[f.SP-idx-1])
	outOff, ok3 := asU64(&f.Stack[f.SP-idx-2])
	outSz, ok4 := asU64(&f.Stack[f.SP-idx-3])
	f.SP -= n
	if !ok0 || !ok1 || !ok2 || !ok3 || !ok4 {
		haltOOG(f)
		return
	}
	if !chargeMem(f, inOff, inSz) || !chargeMem(f, outOff, outSz) {
		haltOOG(f)
		return
	}
	if kind == 0xfa && !evm256.IsZero(&val) {
		haltOOG(f)
		return
	}
	if p.readOnly && !evm256.IsZero(&val) {
		f.Status = c2evm.StatusInvalidOpcode
		f.Gas = 0
		return
	}
	extra := uint64(0)
	if !evm256.IsZero(&val) {
		extra += gasCallValue
		if e.emptyAccount(to) {
			extra += gasNewAccount
		}
	}
	if f.Gas < extra {
		haltOOG(f)
		return
	}
	f.Gas -= extra
	fwd := callGas(f.Gas, reqGas)
	f.Gas -= fwd
	if !evm256.IsZero(&val) {
		fwd += gasCallStipend
	}
	input := append([]byte(nil), f.Memory[inOff:inOff+inSz]...)
	callee := to
	caller := p.addr
	cval := val
	ro := p.readOnly || kind == 0xfa
	codeAddr := to
	if kind == 0xf4 {
		caller = p.caller
		cval = p.callVal
		callee = p.addr
	}
	if kind == 0xf2 {
		callee = p.addr
	}
	cp := callParams{
		caller:   caller,
		addr:     callee,
		codeAddr: codeAddr,
		origin:   p.origin,
		value:    cval,
		callVal:  cval,
		data:     input,
		code:     e.codeOf(codeAddr),
		gas:      fwd,
		readOnly: ro,
		kind:     kind,
	}
	ret, left, ok := e.run(cp)
	f.Gas += left
	ncopy := uint64(len(ret))
	if ncopy > outSz {
		ncopy = outSz
	}
	if ncopy > 0 {
		copy(f.Memory[outOff:outOff+ncopy], ret[:ncopy])
	}
	if !requireRoom(f) {
		return
	}
	if ok {
		f.Stack[f.SP] = evm256.FromU64(1)
	} else {
		f.Stack[f.SP] = evm256.Uint256{}
	}
	f.SP++
}
