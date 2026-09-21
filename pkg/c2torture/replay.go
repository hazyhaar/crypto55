package c2torture

import (
	"bytes"
	"fmt"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2block"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/statetrie"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2evm"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/onestep"
)

const (
	maxWitnessSteps = 4096
	witnessGas      = 8_000_000
)

type BlockReplaySpec struct {
	Header         *c2block.BlockHeader
	Transactions   []*c2block.Transaction
	Expected       ExpectedTransitionResult
	CaptureWitness bool
	WitnessTxIndex int
	WitnessCode    []byte
}

type ExpectedTransitionResult struct {
	StateRoot    [32]byte
	ReceiptsRoot [32]byte
	GasUsed      uint64
	Bloom        [256]byte
}

type ReplayReport struct {
	OK           bool
	StateRoot    [32]byte
	ReceiptsRoot [32]byte
	GasUsed      uint64
	Bloom        [256]byte
	Mismatches   []string
	Witnesses    []*onestep.StepWitness
	Receipts     []*c2block.Receipt
}

type BlockReplayer struct {
	State     *statetrie.StateTrie
	Processor *c2block.BlockProcessor
}

func NewBlockReplayer(st *statetrie.StateTrie) *BlockReplayer {
	if st == nil {
		st = statetrie.NewStateTrie()
	}
	return &BlockReplayer{
		State:     st,
		Processor: c2block.NewBlockProcessor(st),
	}
}

func cloneHeader(h *c2block.BlockHeader) *c2block.BlockHeader {
	if h == nil {
		return &c2block.BlockHeader{}
	}
	cp := *h
	if h.Extra != nil {
		cp.Extra = append([]byte(nil), h.Extra...)
	}
	return &cp
}

func addrToU256(a c2block.Address) evm256.Uint256 {
	var b [32]byte
	copy(b[12:], a[:])
	return evm256.FromBytesBE(b[:])
}

func cloneFrame(f *c2evm.ExecutionFrame) *c2evm.ExecutionFrame {
	c := *f
	return &c
}

func CaptureStepWitnesses(code []byte, gas uint64, db c2evm.StateAccessor) []*onestep.StepWitness {
	if gas == 0 {
		gas = witnessGas
	}
	f := new(c2evm.ExecutionFrame)
	f.StateDB = db
	f.Reset(gas)
	out := make([]*onestep.StepWitness, 0, 16)
	for steps := 0; f.Status == c2evm.StatusRunning && steps < maxWitnessSteps; steps++ {
		if int(f.PC) >= len(code) {
			break
		}
		op := code[f.PC]
		pre := cloneFrame(f)
		c2evm.StepOne(f, code)
		post := cloneFrame(f)
		w, err := onestep.CaptureWitness(pre, post, op)
		if err != nil {
			continue
		}
		out = append(out, w)
	}
	return out
}

func (r *BlockReplayer) codeOf(addr c2block.Address) []byte {
	a := addrToU256(addr)
	acc, ok := r.State.GetAccount(&a)
	if !ok {
		return nil
	}
	return acc.Code
}

func (r *BlockReplayer) witnessCode(spec BlockReplaySpec) []byte {
	if len(spec.WitnessCode) > 0 {
		return spec.WitnessCode
	}
	if spec.WitnessTxIndex < 0 || spec.WitnessTxIndex >= len(spec.Transactions) {
		return []byte{0x60, 0x01, 0x60, 0x02, 0x01, 0x00}
	}
	tx := spec.Transactions[spec.WitnessTxIndex]
	if tx == nil {
		return nil
	}
	if tx.To == nil {
		return append([]byte(nil), tx.Data...)
	}
	return r.codeOf(*tx.To)
}

func (r *BlockReplayer) Replay(spec BlockReplaySpec) (*ReplayReport, error) {
	if r == nil || r.Processor == nil {
		r = NewBlockReplayer(nil)
	}
	header := cloneHeader(spec.Header)
	res, err := r.Processor.ProcessBlock(header, spec.Transactions)
	if err != nil {
		return nil, err
	}
	rep := &ReplayReport{
		OK:           true,
		StateRoot:    res.StateRoot,
		ReceiptsRoot: res.ReceiptsRoot,
		GasUsed:      res.GasUsed,
		Bloom:        res.Bloom,
		Receipts:     res.Receipts,
	}
	exp := spec.Expected
	if exp.StateRoot != rep.StateRoot {
		rep.OK = false
		rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("StateRoot obtenu=%x attendu=%x", rep.StateRoot, exp.StateRoot))
	}
	if exp.ReceiptsRoot != rep.ReceiptsRoot {
		rep.OK = false
		rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("ReceiptsRoot obtenu=%x attendu=%x", rep.ReceiptsRoot, exp.ReceiptsRoot))
	}
	if exp.GasUsed != rep.GasUsed {
		rep.OK = false
		rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("GasUsed obtenu=%d attendu=%d", rep.GasUsed, exp.GasUsed))
	}
	if !bytes.Equal(exp.Bloom[:], rep.Bloom[:]) {
		rep.OK = false
		rep.Mismatches = append(rep.Mismatches, "Bloom 2048 bits non bit-exact")
	}
	if spec.CaptureWitness {
		code := r.witnessCode(spec)
		rep.Witnesses = CaptureStepWitnesses(code, witnessGas, statetrie.NewStateTrie())
	}
	return rep, nil
}
