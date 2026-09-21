package c2seq

import (
	"bytes"
	"errors"
	"sync"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2block"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
)

var (
	ErrNilTx       = errors.New("c2seq: nil transaction")
	ErrDuplicate   = errors.New("c2seq: duplicate transaction")
	ErrUnderpriced = errors.New("c2seq: underpriced replacement")
)

type Mempool struct {
	mu       sync.Mutex
	byHash   map[c2block.Hash]*c2block.Transaction
	bySender map[c2block.Address][]*c2block.Transaction
}

func NewMempool() *Mempool {
	return &Mempool{
		byHash:   make(map[c2block.Hash]*c2block.Transaction),
		bySender: make(map[c2block.Address][]*c2block.Transaction),
	}
}

func txTip(tx *c2block.Transaction) evm256.Uint256 {
	if !evm256.IsZero(&tx.GasTipCap) {
		return tx.GasTipCap
	}
	return tx.GasPrice
}

func tipCmp(a, b *c2block.Transaction) int {
	ta, tb := txTip(a), txTip(b)
	if c := evm256.Cmp(&ta, &tb); c != 0 {
		return c
	}
	return bytes.Compare(a.Hash[:], b.Hash[:])
}

func popPrefer(a, b *c2block.Transaction) bool {
	if a.Nonce < b.Nonce {
		return true
	}
	if a.Nonce > b.Nonce {
		return false
	}
	return tipCmp(a, b) > 0
}

func (m *Mempool) AddTx(tx *c2block.Transaction) error {
	if tx == nil {
		return ErrNilTx
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byHash[tx.Hash]; ok {
		return ErrDuplicate
	}
	list := m.bySender[tx.From]
	for i, ex := range list {
		if ex.Nonce != tx.Nonce {
			continue
		}
		nt, ot := txTip(tx), txTip(ex)
		if evm256.Cmp(&nt, &ot) <= 0 {
			return ErrUnderpriced
		}
		delete(m.byHash, ex.Hash)
		list[i] = tx
		m.bySender[tx.From] = list
		m.byHash[tx.Hash] = tx
		return nil
	}
	ins := len(list)
	for i, ex := range list {
		if ex.Nonce > tx.Nonce {
			ins = i
			break
		}
	}
	list = append(list, nil)
	copy(list[ins+1:], list[ins:])
	list[ins] = tx
	m.bySender[tx.From] = list
	m.byHash[tx.Hash] = tx
	return nil
}

func (m *Mempool) PopBatch(maxGas uint64, maxCount int) []*c2block.Transaction {
	m.mu.Lock()
	defer m.mu.Unlock()
	if maxCount == 0 || maxGas == 0 {
		return nil
	}
	heads := make(map[c2block.Address]int, len(m.bySender))
	for addr := range m.bySender {
		heads[addr] = 0
	}
	var out []*c2block.Transaction
	var used uint64
	for {
		if maxCount > 0 && len(out) >= maxCount {
			break
		}
		var best *c2block.Transaction
		var bestAddr c2block.Address
		for addr, idx := range heads {
			list := m.bySender[addr]
			if idx < 0 || idx >= len(list) {
				continue
			}
			tx := list[idx]
			if maxGas < tx.Gas {
				continue
			}
			remain, err := SafeSubGas(maxGas, used)
			if err != nil || tx.Gas > remain {
				continue
			}
			if best == nil || popPrefer(tx, best) {
				best = tx
				bestAddr = addr
			}
		}
		if best == nil {
			break
		}
		next, err := SafeAddGas(used, best.Gas)
		if err != nil {
			heads[bestAddr] = -1
			continue
		}
		used = next
		out = append(out, best)
		m.removeLocked(best.Hash)
		if _, still := m.bySender[bestAddr]; still {
			heads[bestAddr] = 0
		} else {
			delete(heads, bestAddr)
		}
	}
	return out
}

func (m *Mempool) RemoveTx(hash [32]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeLocked(hash)
}

func (m *Mempool) removeLocked(hash [32]byte) {
	tx, ok := m.byHash[hash]
	if !ok {
		return
	}
	delete(m.byHash, hash)
	list := m.bySender[tx.From]
	for i, ex := range list {
		if ex.Hash != hash {
			continue
		}
		list = append(list[:i], list[i+1:]...)
		break
	}
	if len(list) == 0 {
		delete(m.bySender, tx.From)
		return
	}
	m.bySender[tx.From] = list
}

func (m *Mempool) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.byHash)
}
