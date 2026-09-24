// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. See LICENSE and NOTICE.

package c2rpc

import (
	"encoding/json"
	"strconv"
	"sync"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2block"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2crypto"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2seq"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
)

const defaultChainID = 1

type EthAPI struct {
	mu      sync.Mutex
	Seq     *c2seq.Sequencer
	chainID uint64
	blocks  []*SealedBlock
	byHash  map[c2block.Hash]*SealedBlock
	txByH   map[c2block.Hash]*txIndex
}

func NewEthAPI(seq *c2seq.Sequencer) *EthAPI {
	if seq == nil {
		seq = c2seq.NewSequencer(nil)
	}
	a := &EthAPI{
		Seq:     seq,
		chainID: defaultChainID,
		byHash:  make(map[c2block.Hash]*SealedBlock),
		txByH:   make(map[c2block.Hash]*txIndex),
	}
	if evm256.IsZero(&seq.Header.ChainID) {
		seq.Header.ChainID = evm256.FromU64(a.chainID)
	} else {
		if n, ok := u256u64(seq.Header.ChainID); ok && n != 0 {
			a.chainID = n
		}
	}
	seq.Header.StateRoot = seq.State.ComputeRoot()
	gen := &SealedBlock{
		Header: cloneHeader(seq.Header),
	}
	gen.Hash = hashHeader(&gen.Header)
	a.blocks = []*SealedBlock{gen}
	a.byHash[gen.Hash] = gen
	return a
}

func u256u64(z evm256.Uint256) (uint64, bool) {
	if z[1] != 0 || z[2] != 0 || z[3] != 0 {
		return 0, false
	}
	return z[0], true
}

func addrToU256(a c2block.Address) evm256.Uint256 {
	var b [32]byte
	copy(b[12:], a[:])
	return evm256.FromBytesBE(b[:])
}

func cloneHeader(h c2block.BlockHeader) c2block.BlockHeader {
	if h.Extra != nil {
		h.Extra = append([]byte(nil), h.Extra...)
	}
	return h
}

func rlpBytes(b []byte) []byte {
	out := make([]byte, 1+len(b)+8)
	n := c2crypto.RlpEncodeBytes(b, out)
	return out[:n]
}

func rlpList(items ...[]byte) []byte {
	payload := 0
	for _, it := range items {
		payload += len(it)
	}
	hdr := make([]byte, 9)
	hn := c2crypto.RlpEncodeListHeader(payload, hdr)
	out := make([]byte, hn+payload)
	copy(out, hdr[:hn])
	off := hn
	for _, it := range items {
		copy(out[off:], it)
		off += len(it)
	}
	return out
}

func rlpU64(n uint64) []byte {
	if n == 0 {
		return []byte{0x80}
	}
	var tmp [8]byte
	i := 8
	x := n
	for x != 0 {
		i--
		tmp[i] = byte(x)
		x >>= 8
	}
	return rlpBytes(tmp[i:])
}

func rlpU256(z evm256.Uint256) []byte {
	if evm256.IsZero(&z) {
		return []byte{0x80}
	}
	be := evm256.BytesBE(z)
	i := 0
	for i < 32 && be[i] == 0 {
		i++
	}
	return rlpBytes(be[i:])
}

func hashHeader(h *c2block.BlockHeader) c2block.Hash {
	enc := rlpList(
		rlpBytes(h.ParentHash[:]),
		rlpBytes(h.Coinbase[:]),
		rlpBytes(h.StateRoot[:]),
		rlpBytes(h.ReceiptsRoot[:]),
		rlpBytes(h.Bloom[:]),
		rlpU64(h.Number),
		rlpU64(h.GasLimit),
		rlpU64(h.GasUsed),
		rlpU64(h.Timestamp),
		rlpBytes(h.Extra),
		rlpBytes(h.MixDigest[:]),
		rlpU64(h.Nonce),
		rlpU256(h.BaseFee),
		rlpU256(h.ChainID),
	)
	var out [32]byte
	c2crypto.Keccak256(enc, &out)
	return c2block.Hash(out)
}

func (a *EthAPI) Height() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.blocks[len(a.blocks)-1].Header.Number
}

func (a *EthAPI) GenesisHash() c2block.Hash {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.blocks[0].Hash
}

func (a *EthAPI) Latest() *SealedBlock {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.blocks[len(a.blocks)-1]
}

func (a *EthAPI) ProduceBlock(ts uint64) (*SealedBlock, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.produceLocked(ts)
}

func (a *EthAPI) produceLocked(ts uint64) (*SealedBlock, error) {
	parent := a.blocks[len(a.blocks)-1]
	res, err := a.Seq.ProduceBlock(ts)
	if err != nil {
		return nil, err
	}
	h := cloneHeader(a.Seq.Header)
	h.ParentHash = parent.Hash
	sb := &SealedBlock{
		Header:   h,
		Txs:      append([]*c2block.Transaction(nil), a.Seq.LastTxs...),
		Receipts: res.Receipts,
	}
	sb.Hash = hashHeader(&sb.Header)
	a.indexSealed(sb)
	return sb, nil
}

func (a *EthAPI) indexSealed(sb *SealedBlock) {
	a.blocks = append(a.blocks, sb)
	a.byHash[sb.Hash] = sb
	for i, tx := range sb.Txs {
		var rec *c2block.Receipt
		if i < len(sb.Receipts) {
			rec = sb.Receipts[i]
		}
		a.txByH[tx.Hash] = &txIndex{
			block:  sb.Hash,
			number: sb.Header.Number,
			index:  i,
			tx:     tx,
			rec:    rec,
		}
	}
}

func (a *EthAPI) ImportBlock(sb *SealedBlock) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.importLocked(sb)
}

func (a *EthAPI) importLocked(sb *SealedBlock) error {
	if sb == nil {
		return rpcErr(CodeInvParams, "nil block")
	}
	cur := a.blocks[len(a.blocks)-1]
	if sb.Header.Number != cur.Header.Number+1 {
		if _, ok := a.byHash[sb.Hash]; ok {
			return nil
		}
		return rpcErr(CodeServer, "non-sequential block")
	}
	hdr := cloneHeader(sb.Header)
	res, err := a.Seq.Processor.ProcessBlock(&hdr, sb.Txs)
	if err != nil {
		return err
	}
	a.Seq.Header = hdr
	a.Seq.LastTxs = append([]*c2block.Transaction(nil), sb.Txs...)
	out := &SealedBlock{
		Header:   hdr,
		Txs:      append([]*c2block.Transaction(nil), sb.Txs...),
		Receipts: res.Receipts,
	}
	out.Header.ParentHash = cur.Hash
	out.Hash = hashHeader(&out.Header)
	a.indexSealed(out)
	return nil
}

func (a *EthAPI) BlockByNumber(n uint64) *SealedBlock {
	a.mu.Lock()
	defer a.mu.Unlock()
	if n >= uint64(len(a.blocks)) {
		return nil
	}
	return a.blocks[n]
}

func (a *EthAPI) Handle(method string, params json.RawMessage) (any, *Error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch method {
	case "eth_blockNumber":
		return EncodeQuantity(a.blocks[len(a.blocks)-1].Header.Number), nil
	case "eth_chainId":
		return EncodeQuantity(a.chainID), nil
	case "net_version":
		return strconv.FormatUint(a.chainID, 10), nil
	case "web3_clientVersion":
		return "crypto55/v1.0.0/linux-amd64/go1.27", nil
	case "eth_gasPrice":
		base := a.Seq.Header.BaseFee
		if evm256.IsZero(&base) {
			base = evm256.FromU64(100_000_000)
		}
		return EncodeUint256(base), nil
	case "arb_getBatchConfirmations":
		return EncodeQuantity(1), nil
	case "arb_getSequencerAddress":
		return EncodeAddress(a.Seq.Header.Coinbase), nil
	case "eth_getBalance":
		return a.getBalance(params)
	case "eth_getTransactionCount":
		return a.getTxCount(params)
	case "eth_getCode":
		return a.getCode(params)
	case "eth_getStorageAt":
		return a.getStorageAt(params)
	case "eth_call":
		return a.ethCall(params)
	case "eth_estimateGas":
		return a.estimateGas(params)
	case "eth_sendRawTransaction":
		return a.sendRaw(params)
	case "eth_getBlockByNumber":
		return a.getBlockByNumber(params)
	case "eth_getBlockByHash":
		return a.getBlockByHash(params)
	case "eth_getTransactionReceipt":
		return a.getReceipt(params)
	case "eth_getLogs":
		return a.getLogs(params)
	default:
		return nil, rpcErr(CodeNoMethod, "method not found")
	}
}

func paramList(raw json.RawMessage) ([]json.RawMessage, *Error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, rpcErr(CodeInvParams, "params must be an array")
	}
	return arr, nil
}

func need(arr []json.RawMessage, n int) *Error {
	if len(arr) < n {
		return rpcErr(CodeInvParams, "missing params")
	}
	return nil
}

func unmarshalStr(raw json.RawMessage) (string, *Error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", rpcErr(CodeInvParams, "string param required")
	}
	return s, nil
}

func (a *EthAPI) resolveBlock(tag string) (*SealedBlock, *Error) {
	switch tag {
	case "", "latest", "pending":
		return a.blocks[len(a.blocks)-1], nil
	case "earliest":
		return a.blocks[0], nil
	}
	n, err := DecodeQuantity(tag)
	if err != nil {
		return nil, rpcErr(CodeInvParams, "invalid block tag")
	}
	if n >= uint64(len(a.blocks)) {
		return nil, rpcErr(CodeServer, "block not found")
	}
	return a.blocks[n], nil
}

func (a *EthAPI) blockParam(arr []json.RawMessage, idx int) (*SealedBlock, *Error) {
	if idx >= len(arr) {
		return a.blocks[len(a.blocks)-1], nil
	}
	s, e := unmarshalStr(arr[idx])
	if e != nil {
		return nil, e
	}
	return a.resolveBlock(s)
}

func (a *EthAPI) getBalance(params json.RawMessage) (any, *Error) {
	arr, e := paramList(params)
	if e != nil {
		return nil, e
	}
	if e = need(arr, 1); e != nil {
		return nil, e
	}
	s, e := unmarshalStr(arr[0])
	if e != nil {
		return nil, e
	}
	addr, err := DecodeAddress(s)
	if err != nil {
		return nil, rpcErr(CodeInvParams, "invalid address")
	}
	if _, e = a.blockParam(arr, 1); e != nil {
		return nil, e
	}
	u := addrToU256(addr)
	var bal evm256.Uint256
	a.Seq.State.GetBalance(&u, &bal)
	return EncodeUint256(bal), nil
}

func (a *EthAPI) getTxCount(params json.RawMessage) (any, *Error) {
	arr, e := paramList(params)
	if e != nil {
		return nil, e
	}
	if e = need(arr, 1); e != nil {
		return nil, e
	}
	s, e := unmarshalStr(arr[0])
	if e != nil {
		return nil, e
	}
	addr, err := DecodeAddress(s)
	if err != nil {
		return nil, rpcErr(CodeInvParams, "invalid address")
	}
	if _, e = a.blockParam(arr, 1); e != nil {
		return nil, e
	}
	u := addrToU256(addr)
	acc, ok := a.Seq.State.GetAccount(&u)
	if !ok {
		return EncodeQuantity(0), nil
	}
	return EncodeQuantity(acc.Nonce), nil
}

func (a *EthAPI) getCode(params json.RawMessage) (any, *Error) {
	arr, e := paramList(params)
	if e != nil {
		return nil, e
	}
	if e = need(arr, 1); e != nil {
		return nil, e
	}
	s, e := unmarshalStr(arr[0])
	if e != nil {
		return nil, e
	}
	addr, err := DecodeAddress(s)
	if err != nil {
		return nil, rpcErr(CodeInvParams, "invalid address")
	}
	if _, e = a.blockParam(arr, 1); e != nil {
		return nil, e
	}
	u := addrToU256(addr)
	acc, ok := a.Seq.State.GetAccount(&u)
	if !ok {
		return "0x", nil
	}
	return EncodeBytes(acc.Code), nil
}

func (a *EthAPI) getStorageAt(params json.RawMessage) (any, *Error) {
	arr, e := paramList(params)
	if e != nil {
		return nil, e
	}
	if e = need(arr, 2); e != nil {
		return nil, e
	}
	as, e := unmarshalStr(arr[0])
	if e != nil {
		return nil, e
	}
	ks, e := unmarshalStr(arr[1])
	if e != nil {
		return nil, e
	}
	addr, err := DecodeAddress(as)
	if err != nil {
		return nil, rpcErr(CodeInvParams, "invalid address")
	}
	slot, err := DecodeHashPad(ks)
	if err != nil {
		return nil, rpcErr(CodeInvParams, "invalid slot")
	}
	if _, e = a.blockParam(arr, 2); e != nil {
		return nil, e
	}
	u := addrToU256(addr)
	key := evm256.FromBytesBE(slot[:])
	var val evm256.Uint256
	a.Seq.State.GetStorage(&u, &key, &val)
	be := evm256.BytesBE(val)
	return EncodeBytes(be[:]), nil
}

type callJSON struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Gas      string `json:"gas"`
	GasPrice string `json:"gasPrice"`
	Value    string `json:"value"`
	Data     string `json:"data"`
	Input    string `json:"input"`
}

func parseCall(raw json.RawMessage) (CallMsg, *Error) {
	var c callJSON
	if err := json.Unmarshal(raw, &c); err != nil {
		return CallMsg{}, rpcErr(CodeInvParams, "invalid call object")
	}
	var msg CallMsg
	if c.From != "" {
		a, err := DecodeAddress(c.From)
		if err != nil {
			return CallMsg{}, rpcErr(CodeInvParams, "invalid from")
		}
		msg.From = a
	}
	if c.To != "" {
		a, err := DecodeAddress(c.To)
		if err != nil {
			return CallMsg{}, rpcErr(CodeInvParams, "invalid to")
		}
		msg.To = &a
	}
	if c.Gas != "" {
		g, err := DecodeQuantity(c.Gas)
		if err != nil {
			return CallMsg{}, rpcErr(CodeInvParams, "invalid gas")
		}
		msg.Gas = g
	}
	if c.GasPrice != "" {
		g, err := DecodeUint256(c.GasPrice)
		if err != nil {
			return CallMsg{}, rpcErr(CodeInvParams, "invalid gasPrice")
		}
		msg.GasPrice = g
	}
	if c.Value != "" {
		v, err := DecodeUint256(c.Value)
		if err != nil {
			return CallMsg{}, rpcErr(CodeInvParams, "invalid value")
		}
		msg.Value = v
	}
	ds := c.Data
	if ds == "" {
		ds = c.Input
	}
	if ds != "" {
		b, err := DecodeBytes(ds)
		if err != nil {
			return CallMsg{}, rpcErr(CodeInvParams, "invalid data")
		}
		msg.Data = b
	}
	return msg, nil
}

func (a *EthAPI) nonceOf(addr c2block.Address) uint64 {
	u := addrToU256(addr)
	acc, ok := a.Seq.State.GetAccount(&u)
	if !ok {
		return 0
	}
	return acc.Nonce
}

func (a *EthAPI) simTx(msg CallMsg) *c2block.Transaction {
	tx := &c2block.Transaction{
		Nonce:     a.nonceOf(msg.From),
		GasPrice:  msg.GasPrice,
		GasTipCap: msg.GasPrice,
		GasFeeCap: msg.GasPrice,
		Gas:       msg.Gas,
		To:        msg.To,
		Value:     msg.Value,
		Data:      append([]byte(nil), msg.Data...),
		From:      msg.From,
		ChainID:   evm256.FromU64(a.chainID),
	}
	return tx
}

func (a *EthAPI) runSim(msg CallMsg) (*c2block.Receipt, error) {
	tx := a.simTx(msg)
	hdr := cloneHeader(a.Seq.Header)
	if hdr.GasLimit == 0 {
		hdr.GasLimit = 30_000_000
	}
	if tx.Gas > hdr.GasLimit {
		hdr.GasLimit = tx.Gas
	}
	rev := a.Seq.State.Snapshot()
	rec, err := a.Seq.Processor.ProcessTransaction(&hdr, tx)
	a.Seq.State.RevertToSnapshot(rev)
	return rec, err
}

func (a *EthAPI) ethCall(params json.RawMessage) (any, *Error) {
	arr, e := paramList(params)
	if e != nil {
		return nil, e
	}
	if e = need(arr, 1); e != nil {
		return nil, e
	}
	msg, e := parseCall(arr[0])
	if e != nil {
		return nil, e
	}
	if _, e = a.blockParam(arr, 1); e != nil {
		return nil, e
	}
	if msg.Gas == 0 {
		msg.Gas = a.Seq.Header.GasLimit
		if msg.Gas == 0 {
			msg.Gas = 30_000_000
		}
	}
	rec, err := a.runSim(msg)
	if err != nil {
		return nil, rpcErr(CodeServer, err.Error())
	}
	if rec.Status != 1 {
		return nil, rpcErrData(CodeServer, "execution reverted", EncodeBytes(rec.ReturnData))
	}
	return EncodeBytes(rec.ReturnData), nil
}

func (a *EthAPI) estimateGas(params json.RawMessage) (any, *Error) {
	arr, e := paramList(params)
	if e != nil {
		return nil, e
	}
	if e = need(arr, 1); e != nil {
		return nil, e
	}
	msg, e := parseCall(arr[0])
	if e != nil {
		return nil, e
	}
	hi := msg.Gas
	if hi == 0 {
		hi = a.Seq.Header.GasLimit
		if hi == 0 {
			hi = 30_000_000
		}
	}
	okAt := func(g uint64) bool {
		m := msg
		m.Gas = g
		rec, err := a.runSim(m)
		return err == nil && rec != nil && rec.Status == 1
	}
	if !okAt(hi) {
		return nil, rpcErr(CodeServer, "gas estimation failed")
	}
	lo := uint64(0)
	for lo < hi {
		mid := lo + (hi-lo)/2
		if okAt(mid) {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	return EncodeQuantity(lo), nil
}

func (a *EthAPI) sendRaw(params json.RawMessage) (any, *Error) {
	arr, e := paramList(params)
	if e != nil {
		return nil, e
	}
	if e = need(arr, 1); e != nil {
		return nil, e
	}
	s, e := unmarshalStr(arr[0])
	if e != nil {
		return nil, e
	}
	raw, err := DecodeBytes(s)
	if err != nil {
		return nil, rpcErr(CodeInvParams, "invalid raw tx")
	}
	tx, err := c2block.DecodeTransaction(raw)
	if err != nil {
		return nil, rpcErr(CodeServer, err.Error())
	}
	if err := a.Seq.Mempool.AddTx(tx); err != nil {
		return nil, rpcErr(CodeServer, err.Error())
	}
	return EncodeHash(tx.Hash), nil
}

func (a *EthAPI) rpcBlock(sb *SealedBlock, full bool) map[string]any {
	txs := make([]any, len(sb.Txs))
	for i, tx := range sb.Txs {
		if full {
			txs[i] = a.rpcTx(tx, sb.Hash, sb.Header.Number, uint64(i))
		} else {
			txs[i] = EncodeHash(tx.Hash)
		}
	}
	return map[string]any{
		"number":           EncodeQuantity(sb.Header.Number),
		"hash":             EncodeHash(sb.Hash),
		"parentHash":       EncodeHash(sb.Header.ParentHash),
		"nonce":            EncodeQuantity(sb.Header.Nonce),
		"sha3Uncles":       EncodeHash(c2block.Hash{}),
		"logsBloom":        EncodeBytes(sb.Header.Bloom[:]),
		"transactionsRoot": EncodeHash(c2block.Hash{}),
		"stateRoot":        EncodeHash(sb.Header.StateRoot),
		"receiptsRoot":     EncodeHash(sb.Header.ReceiptsRoot),
		"miner":            EncodeAddress(sb.Header.Coinbase),
		"difficulty":       EncodeUint256(sb.Header.Difficulty),
		"extraData":        EncodeBytes(sb.Header.Extra),
		"gasLimit":         EncodeQuantity(sb.Header.GasLimit),
		"gasUsed":          EncodeQuantity(sb.Header.GasUsed),
		"timestamp":        EncodeQuantity(sb.Header.Timestamp),
		"transactions":     txs,
		"uncles":           []any{},
		"baseFeePerGas":    EncodeUint256(sb.Header.BaseFee),
	}
}

func (a *EthAPI) rpcTx(tx *c2block.Transaction, bh c2block.Hash, num, idx uint64) map[string]any {
	m := map[string]any{
		"hash":             EncodeHash(tx.Hash),
		"nonce":            EncodeQuantity(tx.Nonce),
		"blockHash":        EncodeHash(bh),
		"blockNumber":      EncodeQuantity(num),
		"transactionIndex": EncodeQuantity(idx),
		"from":             EncodeAddress(tx.From),
		"value":            EncodeUint256(tx.Value),
		"gasPrice":         EncodeUint256(tx.GasPrice),
		"gas":              EncodeQuantity(tx.Gas),
		"input":            EncodeBytes(tx.Data),
		"type":             EncodeQuantity(uint64(tx.Type)),
		"chainId":          EncodeUint256(tx.ChainID),
		"v":                EncodeUint256(tx.V),
		"r":                EncodeUint256(tx.R),
		"s":                EncodeUint256(tx.S),
	}
	if tx.To != nil {
		m["to"] = EncodeAddress(*tx.To)
	} else {
		m["to"] = nil
	}
	return m
}

func (a *EthAPI) getBlockByNumber(params json.RawMessage) (any, *Error) {
	arr, e := paramList(params)
	if e != nil {
		return nil, e
	}
	if e = need(arr, 1); e != nil {
		return nil, e
	}
	tag, e := unmarshalStr(arr[0])
	if e != nil {
		return nil, e
	}
	sb, e := a.resolveBlock(tag)
	if e != nil {
		return nil, e
	}
	full := false
	if len(arr) > 1 {
		if err := json.Unmarshal(arr[1], &full); err != nil {
			return nil, rpcErr(CodeInvParams, "invalid fullTx flag")
		}
	}
	return a.rpcBlock(sb, full), nil
}

func (a *EthAPI) getBlockByHash(params json.RawMessage) (any, *Error) {
	arr, e := paramList(params)
	if e != nil {
		return nil, e
	}
	if e = need(arr, 1); e != nil {
		return nil, e
	}
	s, e := unmarshalStr(arr[0])
	if e != nil {
		return nil, e
	}
	h, err := DecodeHash(s)
	if err != nil {
		return nil, rpcErr(CodeInvParams, "invalid hash")
	}
	sb, ok := a.byHash[h]
	if !ok {
		return nil, nil
	}
	full := false
	if len(arr) > 1 {
		if err := json.Unmarshal(arr[1], &full); err != nil {
			return nil, rpcErr(CodeInvParams, "invalid fullTx flag")
		}
	}
	return a.rpcBlock(sb, full), nil
}

func (a *EthAPI) getReceipt(params json.RawMessage) (any, *Error) {
	arr, e := paramList(params)
	if e != nil {
		return nil, e
	}
	if e = need(arr, 1); e != nil {
		return nil, e
	}
	s, e := unmarshalStr(arr[0])
	if e != nil {
		return nil, e
	}
	h, err := DecodeHash(s)
	if err != nil {
		return nil, rpcErr(CodeInvParams, "invalid hash")
	}
	loc, ok := a.txByH[h]
	if !ok || loc.rec == nil {
		return nil, nil
	}
	return a.rpcReceipt(loc), nil
}

func (a *EthAPI) rpcReceipt(loc *txIndex) map[string]any {
	r := loc.rec
	logs := make([]any, len(r.Logs))
	for i, l := range r.Logs {
		logs[i] = a.rpcLog(l, loc, uint64(i))
	}
	st := "0x0"
	if r.Status == 1 {
		st = "0x1"
	}
	m := map[string]any{
		"transactionHash":   EncodeHash(loc.tx.Hash),
		"transactionIndex":  EncodeQuantity(uint64(loc.index)),
		"blockHash":         EncodeHash(loc.block),
		"blockNumber":       EncodeQuantity(loc.number),
		"from":              EncodeAddress(loc.tx.From),
		"cumulativeGasUsed": EncodeQuantity(r.CumulativeGasUsed),
		"gasUsed":           EncodeQuantity(r.GasUsed),
		"contractAddress":   nil,
		"logs":              logs,
		"logsBloom":         EncodeBytes(r.Bloom[:]),
		"status":            st,
		"type":              EncodeQuantity(uint64(loc.tx.Type)),
	}
	if loc.tx.To != nil {
		m["to"] = EncodeAddress(*loc.tx.To)
	} else {
		m["to"] = nil
	}
	if r.ContractAddress != (c2block.Address{}) {
		m["contractAddress"] = EncodeAddress(r.ContractAddress)
	}
	return m
}

func (a *EthAPI) rpcLog(l *c2block.Log, loc *txIndex, li uint64) map[string]any {
	topics := make([]string, len(l.Topics))
	for i, t := range l.Topics {
		topics[i] = EncodeHash(t)
	}
	return map[string]any{
		"address":          EncodeAddress(l.Address),
		"topics":           topics,
		"data":             EncodeBytes(l.Data),
		"blockNumber":      EncodeQuantity(loc.number),
		"transactionHash":  EncodeHash(loc.tx.Hash),
		"transactionIndex": EncodeQuantity(uint64(loc.index)),
		"blockHash":        EncodeHash(loc.block),
		"logIndex":         EncodeQuantity(li),
		"removed":          false,
	}
}

func (a *EthAPI) getLogs(params json.RawMessage) (any, *Error) {
	arr, e := paramList(params)
	if e != nil {
		return nil, e
	}
	if e = need(arr, 1); e != nil {
		return nil, e
	}
	fq, e := parseFilter(arr[0], a.blocks[len(a.blocks)-1].Header.Number)
	if e != nil {
		return nil, e
	}
	var out []any
	for n := fq.FromBlock; n <= fq.ToBlock && n < uint64(len(a.blocks)); n++ {
		sb := a.blocks[n]
		for i, rec := range sb.Receipts {
			if rec == nil {
				continue
			}
			loc := &txIndex{
				block:  sb.Hash,
				number: sb.Header.Number,
				index:  i,
				tx:     nil,
				rec:    rec,
			}
			if i < len(sb.Txs) {
				loc.tx = sb.Txs[i]
			} else {
				loc.tx = &c2block.Transaction{Hash: rec.TxHash}
			}
			for li, l := range rec.Logs {
				if matchLog(l, fq) {
					out = append(out, a.rpcLog(l, loc, uint64(li)))
				}
			}
		}
	}
	if out == nil {
		out = []any{}
	}
	return out, nil
}

func parseFilter(raw json.RawMessage, latest uint64) (FilterQuery, *Error) {
	var obj struct {
		FromBlock *string           `json:"fromBlock"`
		ToBlock   *string           `json:"toBlock"`
		Address   json.RawMessage   `json:"address"`
		Topics    []json.RawMessage `json:"topics"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return FilterQuery{}, rpcErr(CodeInvParams, "invalid filter")
	}
	fq := FilterQuery{FromBlock: 0, ToBlock: latest}
	if obj.FromBlock != nil {
		n, err := decodeBlockTag(*obj.FromBlock, latest)
		if err != nil {
			return FilterQuery{}, rpcErr(CodeInvParams, "invalid fromBlock")
		}
		fq.FromBlock = n
	}
	if obj.ToBlock != nil {
		n, err := decodeBlockTag(*obj.ToBlock, latest)
		if err != nil {
			return FilterQuery{}, rpcErr(CodeInvParams, "invalid toBlock")
		}
		fq.ToBlock = n
	}
	if len(obj.Address) > 0 && string(obj.Address) != "null" {
		addrs, err := decodeAddrList(obj.Address)
		if err != nil {
			return FilterQuery{}, rpcErr(CodeInvParams, "invalid address filter")
		}
		fq.Addresses = addrs
	}
	for _, t := range obj.Topics {
		alts, err := decodeTopic(t)
		if err != nil {
			return FilterQuery{}, rpcErr(CodeInvParams, "invalid topics")
		}
		fq.Topics = append(fq.Topics, alts)
	}
	return fq, nil
}

func decodeBlockTag(s string, latest uint64) (uint64, error) {
	switch s {
	case "", "latest", "pending":
		return latest, nil
	case "earliest":
		return 0, nil
	}
	return DecodeQuantity(s)
}

func decodeAddrList(raw json.RawMessage) ([]c2block.Address, error) {
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, err
		}
		a, err := DecodeAddress(s)
		if err != nil {
			return nil, err
		}
		return []c2block.Address{a}, nil
	}
	var ss []string
	if err := json.Unmarshal(raw, &ss); err != nil {
		return nil, err
	}
	out := make([]c2block.Address, len(ss))
	for i, s := range ss {
		a, err := DecodeAddress(s)
		if err != nil {
			return nil, err
		}
		out[i] = a
	}
	return out, nil
}

func decodeTopic(raw json.RawMessage) ([]c2block.Hash, error) {
	if string(raw) == "null" {
		return nil, nil
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, err
		}
		h, err := DecodeHash(s)
		if err != nil {
			return nil, err
		}
		return []c2block.Hash{h}, nil
	}
	var ss []string
	if err := json.Unmarshal(raw, &ss); err != nil {
		return nil, err
	}
	out := make([]c2block.Hash, 0, len(ss))
	for _, s := range ss {
		if s == "" {
			continue
		}
		h, err := DecodeHash(s)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, nil
}

func matchLog(l *c2block.Log, fq FilterQuery) bool {
	if len(fq.Addresses) > 0 {
		ok := false
		for _, a := range fq.Addresses {
			if a == l.Address {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	for i, alts := range fq.Topics {
		if alts == nil {
			continue
		}
		if i >= len(l.Topics) {
			return false
		}
		ok := false
		for _, t := range alts {
			if t == l.Topics[i] {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}
