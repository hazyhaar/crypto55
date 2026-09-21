package c2seq

import (
	"errors"
	"math/bits"
	"sync"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2block"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2crypto"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
)

const (
	retryableOverheadGas uint64 = 1400
	retryablePerByteGas  uint64 = 6
)

type RetryableStatus uint8

const (
	RetryableCreated RetryableStatus = iota
	RetryableAutoRedeemed
	RetryableManualRedeemed
)

var (
	ErrGasOverflow   = errors.New("c2seq: gas overflow")
	ErrGasUnderflow  = errors.New("c2seq: gas underflow")
	ErrSubmissionFee = errors.New("c2seq: submission fee exceeds cap")
	ErrDeposit       = errors.New("c2seq: insufficient deposit")
	ErrTicketMissing = errors.New("c2seq: retryable ticket not found")
	ErrTicketState   = errors.New("c2seq: retryable ticket not redeemable")
)

func SafeAddGas(a, b uint64) (uint64, error) {
	sum, c := bits.Add64(a, b, 0)
	if c != 0 {
		return 0, ErrGasOverflow
	}
	return sum, nil
}

func SafeSubGas(a, b uint64) (uint64, error) {
	d, br := bits.Sub64(a, b, 0)
	if br != 0 {
		return 0, ErrGasUnderflow
	}
	return d, nil
}

func SafeMulGas(a, b uint64) (uint64, error) {
	hi, lo := bits.Mul64(a, b)
	if hi != 0 {
		return 0, ErrGasOverflow
	}
	return lo, nil
}

func addU256Checked(a, b evm256.Uint256) (evm256.Uint256, error) {
	var out evm256.Uint256
	evm256.Add256(&a, &b, &out)
	if !evm256.IsZero(&b) && evm256.Cmp(&out, &a) < 0 {
		return evm256.Uint256{}, ErrGasOverflow
	}
	return out, nil
}

func mulU256U64Checked(a evm256.Uint256, n uint64) (evm256.Uint256, error) {
	var out evm256.Uint256
	var carry uint64
	for i := 0; i < 4; i++ {
		hi, lo := bits.Mul64(a[i], n)
		sum, c1 := bits.Add64(lo, carry, 0)
		out[i] = sum
		next, c2 := bits.Add64(hi, 0, c1)
		if c2 != 0 {
			return evm256.Uint256{}, ErrGasOverflow
		}
		carry = next
	}
	if carry != 0 {
		return evm256.Uint256{}, ErrGasOverflow
	}
	return out, nil
}

type RetryableParams struct {
	From              c2block.Address
	To                *c2block.Address
	CallValue         evm256.Uint256
	Deposit           evm256.Uint256
	MaxSubmissionFee  evm256.Uint256
	ExcessFeeRefundTo c2block.Address
	CallValueRefundTo c2block.Address
	GasLimit          uint64
	MaxFeePerGas      evm256.Uint256
	Data              []byte
	L1BaseFee         evm256.Uint256
	GasProvided       uint64
}

type RetryableTicket struct {
	ID                [32]byte
	From              c2block.Address
	To                *c2block.Address
	CallValue         evm256.Uint256
	Deposit           evm256.Uint256
	MaxSubmissionFee  evm256.Uint256
	ExcessFeeRefundTo c2block.Address
	CallValueRefundTo c2block.Address
	GasLimit          uint64
	MaxFeePerGas      evm256.Uint256
	Data              []byte
	Status            RetryableStatus
	SubmissionGas     uint64
	SubmissionFee     evm256.Uint256
}

type RetryableEngine struct {
	mu      sync.Mutex
	tickets map[[32]byte]*RetryableTicket
}

func NewRetryableEngine() *RetryableEngine {
	return &RetryableEngine{tickets: make(map[[32]byte]*RetryableTicket)}
}

func submissionGas(dataLen int) (uint64, error) {
	if dataLen < 0 {
		return 0, ErrGasUnderflow
	}
	n, err := SafeMulGas(retryablePerByteGas, uint64(dataLen))
	if err != nil {
		return 0, err
	}
	return SafeAddGas(retryableOverheadGas, n)
}

func quoteRetryable(p RetryableParams) (subGas uint64, subFee evm256.Uint256, exec evm256.Uint256, total evm256.Uint256, err error) {
	subGas, err = submissionGas(len(p.Data))
	if err != nil {
		return 0, evm256.Uint256{}, evm256.Uint256{}, evm256.Uint256{}, err
	}
	subFee, err = mulU256U64Checked(p.L1BaseFee, subGas)
	if err != nil {
		return 0, evm256.Uint256{}, evm256.Uint256{}, evm256.Uint256{}, err
	}
	if evm256.Cmp(&subFee, &p.MaxSubmissionFee) > 0 {
		return 0, evm256.Uint256{}, evm256.Uint256{}, evm256.Uint256{}, ErrSubmissionFee
	}
	exec, err = mulU256U64Checked(p.MaxFeePerGas, p.GasLimit)
	if err != nil {
		return 0, evm256.Uint256{}, evm256.Uint256{}, evm256.Uint256{}, err
	}
	total, err = addU256Checked(subFee, exec)
	if err != nil {
		return 0, evm256.Uint256{}, evm256.Uint256{}, evm256.Uint256{}, err
	}
	total, err = addU256Checked(total, p.CallValue)
	if err != nil {
		return 0, evm256.Uint256{}, evm256.Uint256{}, evm256.Uint256{}, err
	}
	if evm256.Cmp(&p.Deposit, &total) < 0 {
		return 0, evm256.Uint256{}, evm256.Uint256{}, evm256.Uint256{}, ErrDeposit
	}
	if _, err = SafeSubGas(p.GasProvided, subGas); err != nil {
		return 0, evm256.Uint256{}, evm256.Uint256{}, evm256.Uint256{}, err
	}
	return subGas, subFee, exec, total, nil
}

func ticketID(p RetryableParams) [32]byte {
	var buf []byte
	buf = append(buf, p.From[:]...)
	if p.To != nil {
		buf = append(buf, 0x01)
		buf = append(buf, p.To[:]...)
	} else {
		buf = append(buf, 0x00)
	}
	vb := evm256.BytesBE(p.CallValue)
	buf = append(buf, vb[:]...)
	buf = append(buf, p.Data...)
	gb := evm256.BytesBE(evm256.FromU64(p.GasLimit))
	buf = append(buf, gb[:]...)
	var h [32]byte
	c2crypto.Keccak256(buf, &h)
	return h
}

func cloneAddr(a *c2block.Address) *c2block.Address {
	if a == nil {
		return nil
	}
	cp := *a
	return &cp
}

func ticketToTx(t *RetryableTicket, nonce uint64) *c2block.Transaction {
	h := t.ID
	h[0] ^= 0xa5
	return &c2block.Transaction{
		Type:      c2block.TxDynamicFee,
		Nonce:     nonce,
		GasTipCap: t.MaxFeePerGas,
		GasFeeCap: t.MaxFeePerGas,
		GasPrice:  t.MaxFeePerGas,
		Gas:       t.GasLimit,
		To:        cloneAddr(t.To),
		Value:     t.CallValue,
		Data:      append([]byte(nil), t.Data...),
		From:      t.From,
		Hash:      h,
	}
}

func (e *RetryableEngine) Create(p RetryableParams) (*RetryableTicket, *c2block.Transaction, error) {
	subGas, subFee, _, _, err := quoteRetryable(p)
	if err != nil {
		return nil, nil, err
	}
	left, err := SafeSubGas(p.GasProvided, subGas)
	if err != nil {
		return nil, nil, err
	}
	t := &RetryableTicket{
		ID:                ticketID(p),
		From:              p.From,
		To:                cloneAddr(p.To),
		CallValue:         p.CallValue,
		Deposit:           p.Deposit,
		MaxSubmissionFee:  p.MaxSubmissionFee,
		ExcessFeeRefundTo: p.ExcessFeeRefundTo,
		CallValueRefundTo: p.CallValueRefundTo,
		GasLimit:          p.GasLimit,
		MaxFeePerGas:      p.MaxFeePerGas,
		Data:              append([]byte(nil), p.Data...),
		Status:            RetryableCreated,
		SubmissionGas:     subGas,
		SubmissionFee:     subFee,
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.tickets == nil {
		e.tickets = make(map[[32]byte]*RetryableTicket)
	}
	e.tickets[t.ID] = t
	if p.GasLimit == 0 {
		return t, nil, nil
	}
	if left < p.GasLimit {
		return t, nil, nil
	}
	t.Status = RetryableAutoRedeemed
	return t, ticketToTx(t, 0), nil
}

func (e *RetryableEngine) AutoRedeem(id [32]byte) (*c2block.Transaction, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	t, ok := e.tickets[id]
	if !ok {
		return nil, ErrTicketMissing
	}
	if t.Status != RetryableCreated {
		return nil, ErrTicketState
	}
	if t.GasLimit == 0 {
		return nil, ErrTicketState
	}
	t.Status = RetryableAutoRedeemed
	return ticketToTx(t, 0), nil
}

func (e *RetryableEngine) ManualRedeem(id [32]byte, gasLimit uint64, maxFee evm256.Uint256) (*c2block.Transaction, error) {
	if _, err := mulU256U64Checked(maxFee, gasLimit); err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	t, ok := e.tickets[id]
	if !ok {
		return nil, ErrTicketMissing
	}
	if t.Status != RetryableCreated {
		return nil, ErrTicketState
	}
	if gasLimit == 0 {
		return nil, ErrTicketState
	}
	t.GasLimit = gasLimit
	t.MaxFeePerGas = maxFee
	t.Status = RetryableManualRedeemed
	return ticketToTx(t, 0), nil
}

func (e *RetryableEngine) Get(id [32]byte) (*RetryableTicket, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	t, ok := e.tickets[id]
	if !ok {
		return nil, false
	}
	cp := *t
	cp.To = cloneAddr(t.To)
	cp.Data = append([]byte(nil), t.Data...)
	return &cp, true
}
