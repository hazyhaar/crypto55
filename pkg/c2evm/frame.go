package c2evm

import "code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"

const (
	StatusRunning         = 0
	StatusSuccess         = 1
	StatusRevert          = 2
	StatusStackUnderflow  = 3
	StatusStackOverflow   = 4
	StatusOutOfGas        = 5
	StatusInvalidOpcode   = 6
	StatusJumpDestInvalid = 7
)

const (
	stackMax = 1024
	memMax   = 65536
)

type StateAccessor interface {
	GetStorage(addr, key *evm256.Uint256, val *evm256.Uint256)
	SetStorage(addr, key, val *evm256.Uint256)
}

type ExecutionFrame struct {
	Stack            [stackMax]evm256.Uint256
	SP               int32
	PC               uint32
	Gas              uint64
	Refund           uint64
	Status           int
	Memory           [memMax]byte
	MemorySize       uint32
	ReturnDataOffset uint32
	ReturnDataSize   uint32
	StateDB          StateAccessor
}

func (f *ExecutionFrame) Reset(gas uint64) {
	db := f.StateDB
	clear(f.Stack[:])
	clear(f.Memory[:])
	f.SP = 0
	f.PC = 0
	f.Gas = gas
	f.Refund = 0
	f.Status = StatusRunning
	f.MemorySize = 0
	f.ReturnDataOffset = 0
	f.ReturnDataSize = 0
	f.StateDB = db
}
