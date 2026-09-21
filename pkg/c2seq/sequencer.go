package c2seq

import (
	"sync"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2block"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/statetrie"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
)

const (
	MsgEthDeposit uint8 = 0
	MsgRetryable  uint8 = 1
	defaultTxs          = 128
)

type DelayedMessage struct {
	Kind             uint8
	From             c2block.Address
	To               *c2block.Address
	Value            evm256.Uint256
	Data             []byte
	GasLimit         uint64
	MaxFeePerGas     evm256.Uint256
	Deposit          evm256.Uint256
	MaxSubmissionFee evm256.Uint256
	L1BaseFee        evm256.Uint256
	GasProvided      uint64
	PostedAt         uint64
}

type DelayedInbox struct {
	mu    sync.Mutex
	delay uint64
	q     []DelayedMessage
}

func NewDelayedInbox(delay uint64) *DelayedInbox {
	return &DelayedInbox{delay: delay}
}

func (d *DelayedInbox) Enqueue(msg DelayedMessage) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.q = append(d.q, msg)
}

func (d *DelayedInbox) PopReady(now uint64) []DelayedMessage {
	d.mu.Lock()
	defer d.mu.Unlock()
	var ready []DelayedMessage
	keep := d.q[:0]
	for _, m := range d.q {
		if now < m.PostedAt {
			keep = append(keep, m)
			continue
		}
		elapsed, err := SafeSubGas(now, m.PostedAt)
		if err != nil {
			keep = append(keep, m)
			continue
		}
		if elapsed < d.delay {
			keep = append(keep, m)
			continue
		}
		ready = append(ready, m)
	}
	d.q = keep
	return ready
}

func (d *DelayedInbox) Count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.q)
}

type Sequencer struct {
	mu           sync.Mutex
	Mempool      *Mempool
	Timeboost    *Timeboost
	DelayedInbox *DelayedInbox
	Retryables   *RetryableEngine
	Processor    *c2block.BlockProcessor
	State        *statetrie.StateTrie
	Poster       *BatchPoster
	Header       c2block.BlockHeader
	LastBatch    []byte
	LastTxs      []*c2block.Transaction
	maxTxs       int
}

func NewSequencer(st *statetrie.StateTrie) *Sequencer {
	if st == nil {
		st = statetrie.NewStateTrie()
	}
	return &Sequencer{
		Mempool:      NewMempool(),
		Timeboost:    NewTimeboost(DefaultExpressWindow),
		DelayedInbox: NewDelayedInbox(1),
		Retryables:   NewRetryableEngine(),
		Processor:    c2block.NewBlockProcessor(st),
		State:        st,
		Poster:       NewBatchPoster(),
		Header: c2block.BlockHeader{
			GasLimit: 30_000_000,
		},
		maxTxs: defaultTxs,
	}
}

func addrToU256(a c2block.Address) evm256.Uint256 {
	var b [32]byte
	copy(b[12:], a[:])
	return evm256.FromBytesBE(b[:])
}

func (s *Sequencer) nonceOf(addr c2block.Address) uint64 {
	a := addrToU256(addr)
	acc, ok := s.State.GetAccount(&a)
	if !ok {
		return 0
	}
	return acc.Nonce
}

func (s *Sequencer) collect(now uint64) []*c2block.Transaction {
	var out []*c2block.Transaction
	if s.DelayedInbox != nil {
		for _, msg := range s.DelayedInbox.PopReady(now) {
			switch msg.Kind {
			case MsgRetryable:
				if s.Retryables == nil {
					continue
				}
				p := RetryableParams{
					From:              msg.From,
					To:                msg.To,
					CallValue:         msg.Value,
					Deposit:           msg.Deposit,
					MaxSubmissionFee:  msg.MaxSubmissionFee,
					ExcessFeeRefundTo: msg.From,
					CallValueRefundTo: msg.From,
					GasLimit:          msg.GasLimit,
					MaxFeePerGas:      msg.MaxFeePerGas,
					Data:              msg.Data,
					L1BaseFee:         msg.L1BaseFee,
					GasProvided:       msg.GasProvided,
				}
				_, tx, err := s.Retryables.Create(p)
				if err != nil || tx == nil {
					continue
				}
				tx.Nonce = s.nonceOf(tx.From)
				out = append(out, tx)
			default:
				if msg.To == nil {
					continue
				}
				to := addrToU256(*msg.To)
				s.State.AddBalance(&to, &msg.Value)
			}
		}
	}
	if s.Timeboost != nil {
		out = append(out, s.Timeboost.Drain(now)...)
	}
	used := uint64(0)
	for _, tx := range out {
		next, err := SafeAddGas(used, tx.Gas)
		if err != nil {
			break
		}
		used = next
	}
	remainGas := uint64(^uint64(0))
	if s.Header.GasLimit != 0 {
		if used >= s.Header.GasLimit {
			remainGas = 0
		} else {
			remainGas = s.Header.GasLimit - used
		}
	}
	remainCount := s.maxTxs - len(out)
	if remainCount < 0 {
		remainCount = 0
	}
	if s.Mempool != nil && remainCount > 0 && remainGas > 0 {
		out = append(out, s.Mempool.PopBatch(remainGas, remainCount)...)
	}
	return out
}

func (s *Sequencer) ProduceBlock(timestamp uint64) (*c2block.BlockResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Header.ParentHash = s.Header.StateRoot
	s.Header.Timestamp = timestamp
	next, err := SafeAddGas(s.Header.Number, 1)
	if err != nil {
		return nil, err
	}
	s.Header.Number = next
	s.Header.GasUsed = 0
	cands := s.collect(timestamp)
	var batch []*c2block.Transaction
	var reserved uint64
	seen := make(map[c2block.Address]uint64)
	for _, tx := range cands {
		if s.maxTxs > 0 && len(batch) >= s.maxTxs {
			break
		}
		if s.Header.GasLimit != 0 {
			if reserved >= s.Header.GasLimit {
				break
			}
			room := s.Header.GasLimit - reserved
			if tx.Gas > room {
				continue
			}
		}
		want, ok := seen[tx.From]
		if !ok {
			want = s.nonceOf(tx.From)
			seen[tx.From] = want
		}
		if tx.Nonce != want {
			continue
		}
		nextRes, err := SafeAddGas(reserved, tx.Gas)
		if err != nil {
			continue
		}
		reserved = nextRes
		seen[tx.From] = want + 1
		batch = append(batch, tx)
	}
	res, err := s.Processor.ProcessBlock(&s.Header, batch)
	if err != nil {
		return nil, err
	}
	packed, err := s.Poster.Pack(batch)
	if err != nil {
		return nil, err
	}
	s.LastBatch = packed
	s.LastTxs = batch
	return res, nil
}
