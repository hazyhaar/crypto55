package c2block

import (
	"errors"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2crypto"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/statetrie"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
)

var (
	ErrNonce             = errors.New("c2block: invalid nonce")
	ErrInsufficientFunds = errors.New("c2block: insufficient funds")
	ErrIntrinsicGas      = errors.New("c2block: intrinsic gas too low")
	ErrFeeCap            = errors.New("c2block: fee cap below base fee")
	ErrGasLimit          = errors.New("c2block: gas exceeds block limit")
)

type BlockProcessor struct {
	State *statetrie.StateTrie
}

func NewBlockProcessor(st *statetrie.StateTrie) *BlockProcessor {
	if st == nil {
		st = statetrie.NewStateTrie()
	}
	return &BlockProcessor{State: st}
}

func (p *BlockProcessor) nonceOf(addr Address) uint64 {
	a := addrToU256(addr)
	acc, ok := p.State.GetAccount(&a)
	if !ok {
		return 0
	}
	return acc.Nonce
}

func (p *BlockProcessor) setNonce(addr Address, n uint64) {
	a := addrToU256(addr)
	acc, ok := p.State.GetAccount(&a)
	if !ok {
		acc = &statetrie.Account{}
	}
	acc.Nonce = n
	p.State.SetAccount(&a, acc)
}

func intrinsicGas(tx *Transaction) uint64 {
	var gas uint64 = 21000
	if tx.To == nil {
		gas = 53000
		words := words32(len(tx.Data))
		gas += words * 2
	}
	for _, b := range tx.Data {
		if b == 0 {
			gas += 4
		} else {
			gas += 16
		}
	}
	for _, t := range tx.AccessList {
		gas += 2400 + uint64(len(t.StorageKeys))*1900
	}
	return gas
}

func minU256(a, b evm256.Uint256) evm256.Uint256 {
	if evm256.Cmp(&a, &b) <= 0 {
		return a
	}
	return b
}

func effectiveFees(header *BlockHeader, tx *Transaction) (effective, tip evm256.Uint256, err error) {
	base := header.BaseFee
	switch tx.Type {
	case TxDynamicFee, TxBlob:
		if evm256.Cmp(&tx.GasFeeCap, &base) < 0 {
			return evm256.Uint256{}, evm256.Uint256{}, ErrFeeCap
		}
		var room evm256.Uint256
		evm256.Sub256(&tx.GasFeeCap, &base, &room)
		tip = minU256(tx.GasTipCap, room)
		evm256.Add256(&base, &tip, &effective)
		return effective, tip, nil
	default:
		if !evm256.IsZero(&base) && evm256.Cmp(&tx.GasPrice, &base) < 0 {
			return evm256.Uint256{}, evm256.Uint256{}, ErrFeeCap
		}
		effective = tx.GasPrice
		if evm256.IsZero(&base) {
			tip = tx.GasPrice
		} else {
			evm256.Sub256(&tx.GasPrice, &base, &tip)
		}
		return effective, tip, nil
	}
}

func u256MulU64(a evm256.Uint256, n uint64) evm256.Uint256 {
	b := evm256.FromU64(n)
	var out evm256.Uint256
	evm256.Mul256(&a, &b, &out)
	return out
}

func (p *BlockProcessor) ProcessTransaction(header *BlockHeader, tx *Transaction) (*Receipt, error) {
	if tx.Gas > header.GasLimit {
		return nil, ErrGasLimit
	}
	ig := intrinsicGas(tx)
	if tx.Gas < ig {
		return nil, ErrIntrinsicGas
	}
	eff, tip, err := effectiveFees(header, tx)
	if err != nil {
		return nil, err
	}
	if p.nonceOf(tx.From) != tx.Nonce {
		return nil, ErrNonce
	}
	cost := u256MulU64(eff, tx.Gas)
	evm256.Add256(&cost, &tx.Value, &cost)
	fromU := addrToU256(tx.From)
	var bal evm256.Uint256
	p.State.GetBalance(&fromU, &bal)
	if evm256.Cmp(&bal, &cost) < 0 {
		return nil, ErrInsufficientFunds
	}
	gasCost := u256MulU64(eff, tx.Gas)
	if err := p.State.SubBalance(&fromU, &gasCost); err != nil {
		return nil, err
	}
	p.setNonce(tx.From, tx.Nonce+1)

	env := &vmEnv{
		state:    p.State,
		header:   header,
		origin:   tx.From,
		gasPrice: eff,
	}
	gasLeft := tx.Gas - ig
	rev := p.State.Snapshot()
	var (
		ret      []byte
		ok       bool
		contract Address
	)
	if tx.To == nil {
		dest := createAddress(tx.From, tx.Nonce)
		contract = dest
		ret, gasLeft, ok = env.run(callParams{
			caller:  tx.From,
			addr:    dest,
			origin:  tx.From,
			value:   tx.Value,
			callVal: tx.Value,
			data:    nil,
			code:    append([]byte(nil), tx.Data...),
			gas:     gasLeft,
			kind:    0xf0,
		})
	} else {
		ret, gasLeft, ok = env.run(callParams{
			caller:  tx.From,
			addr:    *tx.To,
			origin:  tx.From,
			value:   tx.Value,
			callVal: tx.Value,
			data:    append([]byte(nil), tx.Data...),
			gas:     gasLeft,
			kind:    0xf1,
		})
	}
	if !ok {
		p.State.RevertToSnapshot(rev)
	}

	used := tx.Gas - gasLeft
	if used > tx.Gas {
		used = tx.Gas
		gasLeft = 0
	}
	refundCap := used / 5
	if refundCap > 0 {
		if gasLeft+refundCap < gasLeft {
			gasLeft = tx.Gas
		} else {
			gasLeft += refundCap
			if gasLeft > tx.Gas-ig {
				gasLeft = tx.Gas - ig
			}
		}
		used = tx.Gas - gasLeft
	}
	refund := u256MulU64(eff, gasLeft)
	p.State.AddBalance(&fromU, &refund)
	coin := addrToU256(header.Coinbase)
	miner := u256MulU64(tip, used)
	p.State.AddBalance(&coin, &miner)

	rec := &Receipt{
		GasUsed:         used,
		Logs:            env.logs,
		TxHash:          tx.Hash,
		ContractAddress: contract,
		ReturnData:      append([]byte(nil), ret...),
	}
	if ok {
		rec.Status = 1
	}
	rec.Bloom = logsBloom(rec.Logs)
	return rec, nil
}

func (p *BlockProcessor) ProcessBlock(header *BlockHeader, txs []*Transaction) (*BlockResult, error) {
	res := &BlockResult{}
	var cum uint64
	var all []*Log
	for _, tx := range txs {
		rec, err := p.ProcessTransaction(header, tx)
		if err != nil {
			return nil, err
		}
		if header.GasLimit != 0 && cum+rec.GasUsed > header.GasLimit {
			return nil, ErrGasLimit
		}
		cum += rec.GasUsed
		rec.CumulativeGasUsed = cum
		res.Receipts = append(res.Receipts, rec)
		all = append(all, rec.Logs...)
	}
	res.GasUsed = cum
	res.Bloom = logsBloom(all)
	res.ReceiptsRoot = receiptsRoot(res.Receipts)
	res.StateRoot = p.State.ComputeRoot()
	header.GasUsed = cum
	header.Bloom = res.Bloom
	header.ReceiptsRoot = res.ReceiptsRoot
	header.StateRoot = res.StateRoot
	return res, nil
}

func logsBloom(logs []*Log) [256]byte {
	var b [256]byte
	for _, l := range logs {
		addBloom(&b, l.Address[:])
		for i := range l.Topics {
			addBloom(&b, l.Topics[i][:])
		}
	}
	return b
}

func addBloom(b *[256]byte, data []byte) {
	var h [32]byte
	c2crypto.Keccak256(data, &h)
	for i := 0; i < 3; i++ {
		bit := (uint(h[i*2])<<8 | uint(h[i*2+1])) & 2047
		b[255-bit/8] |= 1 << (bit % 8)
	}
}

type mptNode struct {
	kind     byte
	nibbles  []byte
	value    []byte
	children [16]*mptNode
}

const (
	mptEmpty byte = iota
	mptLeaf
	mptExt
	mptBranch
)

func receiptsRoot(recs []*Receipt) Hash {
	if len(recs) == 0 {
		var h [32]byte
		c2crypto.Keccak256([]byte{0x80}, &h)
		return Hash(h)
	}
	var n *mptNode
	for i, r := range recs {
		key := rlpU64Enc(uint64(i))
		val := encodeReceipt(r)
		n = mptInsert(n, bytesToNibbles(key), val)
	}
	return mptHashRoot(n)
}

func encodeReceipt(r *Receipt) []byte {
	return rlpListEnc(
		rlpU64Enc(r.Status),
		rlpU64Enc(r.CumulativeGasUsed),
		rlpBytesEnc(r.Bloom[:]),
		encodeLogs(r.Logs),
	)
}

func encodeLogs(logs []*Log) []byte {
	items := make([][]byte, len(logs))
	for i, l := range logs {
		topics := make([][]byte, len(l.Topics))
		for j, t := range l.Topics {
			topics[j] = rlpBytesEnc(t[:])
		}
		items[i] = rlpListEnc(rlpBytesEnc(l.Address[:]), rlpListEnc(topics...), rlpBytesEnc(l.Data))
	}
	return rlpListEnc(items...)
}

func bytesToNibbles(b []byte) []byte {
	n := make([]byte, len(b)*2)
	for i, x := range b {
		n[i*2] = x >> 4
		n[i*2+1] = x & 0x0f
	}
	return n
}

func cloneB(b []byte) []byte {
	return append([]byte(nil), b...)
}

func mptInsert(n *mptNode, key, value []byte) *mptNode {
	if n == nil || n.kind == mptEmpty {
		return &mptNode{kind: mptLeaf, nibbles: cloneB(key), value: cloneB(value)}
	}
	switch n.kind {
	case mptLeaf:
		return mptInsertLeaf(n, key, value)
	case mptExt:
		return mptInsertExt(n, key, value)
	default:
		return mptInsertBranch(n, key, value)
	}
}

func commonPref(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	i := 0
	for i < n && a[i] == b[i] {
		i++
	}
	return i
}

func mptInsertLeaf(n *mptNode, key, value []byte) *mptNode {
	if len(n.nibbles) == len(key) {
		eq := true
		for i := range key {
			if n.nibbles[i] != key[i] {
				eq = false
				break
			}
		}
		if eq {
			n.value = cloneB(value)
			return n
		}
	}
	cp := commonPref(n.nibbles, key)
	br := mptSplit(n.nibbles[cp:], n.value, nil, key[cp:], value)
	if cp > 0 {
		return &mptNode{kind: mptExt, nibbles: cloneB(n.nibbles[:cp]), children: [16]*mptNode{0: br}}
	}
	return br
}

func mptInsertExt(n *mptNode, key, value []byte) *mptNode {
	cp := commonPref(n.nibbles, key)
	if cp == len(n.nibbles) {
		n.children[0] = mptInsert(n.children[0], key[cp:], value)
		return n
	}
	oldRest := n.nibbles[cp:]
	oldChild := n.children[0]
	var oldNode *mptNode
	if len(oldRest) == 1 {
		oldNode = oldChild
	} else {
		oldNode = &mptNode{kind: mptExt, nibbles: cloneB(oldRest[1:]), children: [16]*mptNode{0: oldChild}}
	}
	br := mptSplit(oldRest, nil, oldNode, key[cp:], value)
	if cp > 0 {
		return &mptNode{kind: mptExt, nibbles: cloneB(n.nibbles[:cp]), children: [16]*mptNode{0: br}}
	}
	return br
}

func mptInsertBranch(n *mptNode, key, value []byte) *mptNode {
	if len(key) == 0 {
		n.value = cloneB(value)
		return n
	}
	n.children[key[0]] = mptInsert(n.children[key[0]], key[1:], value)
	return n
}

func mptSplit(oldRest, oldVal []byte, oldNode *mptNode, newRest, newVal []byte) *mptNode {
	br := &mptNode{kind: mptBranch}
	if len(oldRest) == 0 {
		br.value = cloneB(oldVal)
	} else {
		if oldNode == nil {
			oldNode = &mptNode{kind: mptLeaf, nibbles: cloneB(oldRest[1:]), value: cloneB(oldVal)}
		}
		br.children[oldRest[0]] = oldNode
	}
	if len(newRest) == 0 {
		br.value = cloneB(newVal)
	} else {
		br.children[newRest[0]] = &mptNode{kind: mptLeaf, nibbles: cloneB(newRest[1:]), value: cloneB(newVal)}
	}
	return br
}

func mptEncode(n *mptNode, out []byte) int {
	switch n.kind {
	case mptLeaf:
		return c2crypto.MptEncodeLeaf(n.nibbles, n.value, out)
	case mptExt:
		h := mptHashChild(n.children[0])
		return c2crypto.MptEncodeExtension(n.nibbles, &h, out)
	case mptBranch:
		var children [16][32]byte
		var has [16]int
		for i := 0; i < 16; i++ {
			if n.children[i] != nil {
				children[i] = mptHashChild(n.children[i])
				has[i] = 1
			}
		}
		return c2crypto.MptEncodeBranch(&children, &has, n.value, out)
	default:
		out[0] = 0x80
		return 1
	}
}

func mptHashChild(n *mptNode) [32]byte {
	var buf [2048]byte
	k := mptEncode(n, buf[:])
	var h [32]byte
	c2crypto.MptHashNode(buf[:k], &h)
	return h
}

func mptHashRoot(n *mptNode) Hash {
	if n == nil {
		var h [32]byte
		c2crypto.Keccak256([]byte{0x80}, &h)
		return Hash(h)
	}
	var buf [2048]byte
	k := mptEncode(n, buf[:])
	var h [32]byte
	c2crypto.Keccak256(buf[:k], &h)
	return Hash(h)
}
