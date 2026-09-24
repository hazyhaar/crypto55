// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. See LICENSE and NOTICE.

package c2block

import (
	"errors"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2crypto"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
)

var (
	ErrInvalidRLP = errors.New("c2block: invalid RLP")
	ErrInvalidTx  = errors.New("c2block: invalid transaction")
	ErrSender     = errors.New("c2block: sender recovery failed")
)

type rlpKind int

const (
	rlpBytes rlpKind = iota
	rlpList
)

type rlpVal struct {
	kind rlpKind
	b    []byte
	list []rlpVal
}

func rlpDecode(buf []byte) (rlpVal, []byte, error) {
	if len(buf) == 0 {
		return rlpVal{}, nil, ErrInvalidRLP
	}
	b := buf[0]
	if b < 0x80 {
		return rlpVal{kind: rlpBytes, b: buf[:1]}, buf[1:], nil
	}
	if b < 0xb8 {
		n := int(b - 0x80)
		if n == 1 && len(buf) > 1 && buf[1] < 0x80 {
			return rlpVal{}, nil, ErrInvalidRLP
		}
		if len(buf) < 1+n {
			return rlpVal{}, nil, ErrInvalidRLP
		}
		return rlpVal{kind: rlpBytes, b: buf[1 : 1+n]}, buf[1+n:], nil
	}
	if b < 0xc0 {
		llen := int(b - 0xb7)
		if llen == 0 || len(buf) < 1+llen {
			return rlpVal{}, nil, ErrInvalidRLP
		}
		n := rlpReadInt(buf[1 : 1+llen])
		if n < 56 {
			return rlpVal{}, nil, ErrInvalidRLP
		}
		if len(buf) < 1+llen+n {
			return rlpVal{}, nil, ErrInvalidRLP
		}
		return rlpVal{kind: rlpBytes, b: buf[1+llen : 1+llen+n]}, buf[1+llen+n:], nil
	}
	var payload []byte
	var rest []byte
	if b < 0xf8 {
		n := int(b - 0xc0)
		if len(buf) < 1+n {
			return rlpVal{}, nil, ErrInvalidRLP
		}
		payload = buf[1 : 1+n]
		rest = buf[1+n:]
	} else {
		llen := int(b - 0xf7)
		if llen == 0 || len(buf) < 1+llen {
			return rlpVal{}, nil, ErrInvalidRLP
		}
		n := rlpReadInt(buf[1 : 1+llen])
		if n < 56 {
			return rlpVal{}, nil, ErrInvalidRLP
		}
		if len(buf) < 1+llen+n {
			return rlpVal{}, nil, ErrInvalidRLP
		}
		payload = buf[1+llen : 1+llen+n]
		rest = buf[1+llen+n:]
	}
	var items []rlpVal
	for len(payload) > 0 {
		v, next, err := rlpDecode(payload)
		if err != nil {
			return rlpVal{}, nil, err
		}
		items = append(items, v)
		payload = next
	}
	return rlpVal{kind: rlpList, list: items}, rest, nil
}

func rlpReadInt(b []byte) int {
	n := 0
	for _, c := range b {
		n = (n << 8) | int(c)
	}
	return n
}

func rlpBytesEnc(b []byte) []byte {
	n := 1 + len(b) + 8
	out := make([]byte, n)
	k := c2crypto.RlpEncodeBytes(b, out)
	return out[:k]
}

func rlpListEnc(items ...[]byte) []byte {
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

func rlpU64Enc(n uint64) []byte {
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
	return rlpBytesEnc(tmp[i:])
}

func rlpU256Enc(z evm256.Uint256) []byte {
	if evm256.IsZero(&z) {
		return []byte{0x80}
	}
	be := evm256.BytesBE(z)
	i := 0
	for i < 32 && be[i] == 0 {
		i++
	}
	return rlpBytesEnc(be[i:])
}

func rlpAddrEnc(a *Address) []byte {
	if a == nil {
		return []byte{0x80}
	}
	return rlpBytesEnc(a[:])
}

func rlpUint64(v rlpVal) (uint64, error) {
	if v.kind != rlpBytes {
		return 0, ErrInvalidRLP
	}
	if len(v.b) == 0 {
		return 0, nil
	}
	if v.b[0] == 0 || len(v.b) > 8 {
		return 0, ErrInvalidRLP
	}
	var n uint64
	for _, c := range v.b {
		n = (n << 8) | uint64(c)
	}
	return n, nil
}

func rlpU256(v rlpVal) (evm256.Uint256, error) {
	if v.kind != rlpBytes || len(v.b) > 32 {
		return evm256.Uint256{}, ErrInvalidRLP
	}
	if len(v.b) > 1 && v.b[0] == 0 {
		return evm256.Uint256{}, ErrInvalidRLP
	}
	return evm256.FromBytesBE(v.b), nil
}

func rlpAddr(v rlpVal) (*Address, error) {
	if v.kind != rlpBytes {
		return nil, ErrInvalidRLP
	}
	if len(v.b) == 0 {
		return nil, nil
	}
	if len(v.b) != 20 {
		return nil, ErrInvalidRLP
	}
	var a Address
	copy(a[:], v.b)
	return &a, nil
}

func keccak32(in []byte) Hash {
	var h [32]byte
	c2crypto.Keccak256(in, &h)
	return Hash(h)
}

func DecodeTransaction(raw []byte) (*Transaction, error) {
	if len(raw) == 0 {
		return nil, ErrInvalidTx
	}
	tx := new(Transaction)
	var payload []byte
	if raw[0] > 0x7f {
		tx.Type = TxLegacy
		payload = raw
	} else {
		tx.Type = raw[0]
		if tx.Type != TxAccessList && tx.Type != TxDynamicFee && tx.Type != TxBlob {
			return nil, ErrInvalidTx
		}
		payload = raw[1:]
	}
	v, rest, err := rlpDecode(payload)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 || v.kind != rlpList {
		return nil, ErrInvalidTx
	}
	if err := parseTxList(tx, v.list); err != nil {
		return nil, err
	}
	sigHash := tx.signingHash()
	from, err := recoverSender(sigHash, tx.Type != TxLegacy, tx.V, tx.R, tx.S)
	if err != nil {
		return nil, err
	}
	tx.From = from
	tx.Hash = keccak32(raw)
	return tx, nil
}

func parseTxList(tx *Transaction, items []rlpVal) error {
	switch tx.Type {
	case TxLegacy:
		if len(items) != 9 {
			return ErrInvalidTx
		}
		return parseLegacy(tx, items)
	case TxAccessList:
		if len(items) != 11 {
			return ErrInvalidTx
		}
		return parseAccessListTx(tx, items)
	case TxDynamicFee:
		if len(items) != 12 {
			return ErrInvalidTx
		}
		return parseDynamicFeeTx(tx, items)
	case TxBlob:
		if len(items) != 14 {
			return ErrInvalidTx
		}
		return parseBlobTx(tx, items)
	default:
		return ErrInvalidTx
	}
}

func parseLegacy(tx *Transaction, items []rlpVal) error {
	var err error
	if tx.Nonce, err = rlpUint64(items[0]); err != nil {
		return err
	}
	if tx.GasPrice, err = rlpU256(items[1]); err != nil {
		return err
	}
	tx.GasFeeCap = tx.GasPrice
	tx.GasTipCap = tx.GasPrice
	if tx.Gas, err = rlpUint64(items[2]); err != nil {
		return err
	}
	if tx.To, err = rlpAddr(items[3]); err != nil {
		return err
	}
	if tx.Value, err = rlpU256(items[4]); err != nil {
		return err
	}
	if items[5].kind != rlpBytes {
		return ErrInvalidTx
	}
	tx.Data = append([]byte(nil), items[5].b...)
	if tx.V, err = rlpU256(items[6]); err != nil {
		return err
	}
	if tx.R, err = rlpU256(items[7]); err != nil {
		return err
	}
	if tx.S, err = rlpU256(items[8]); err != nil {
		return err
	}
	if n, ok := u256ToU64(tx.V); ok && n >= 35 {
		tx.ChainID = evm256.FromU64((n - 35) / 2)
	}
	return nil
}

func parseAccessListTx(tx *Transaction, items []rlpVal) error {
	var err error
	if tx.ChainID, err = rlpU256(items[0]); err != nil {
		return err
	}
	if tx.Nonce, err = rlpUint64(items[1]); err != nil {
		return err
	}
	if tx.GasPrice, err = rlpU256(items[2]); err != nil {
		return err
	}
	tx.GasFeeCap = tx.GasPrice
	tx.GasTipCap = tx.GasPrice
	if tx.Gas, err = rlpUint64(items[3]); err != nil {
		return err
	}
	if tx.To, err = rlpAddr(items[4]); err != nil {
		return err
	}
	if tx.Value, err = rlpU256(items[5]); err != nil {
		return err
	}
	if items[6].kind != rlpBytes {
		return ErrInvalidTx
	}
	tx.Data = append([]byte(nil), items[6].b...)
	if tx.AccessList, err = parseAccessList(items[7]); err != nil {
		return err
	}
	if tx.V, err = rlpU256(items[8]); err != nil {
		return err
	}
	if tx.R, err = rlpU256(items[9]); err != nil {
		return err
	}
	if tx.S, err = rlpU256(items[10]); err != nil {
		return err
	}
	return nil
}

func parseDynamicFeeTx(tx *Transaction, items []rlpVal) error {
	var err error
	if tx.ChainID, err = rlpU256(items[0]); err != nil {
		return err
	}
	if tx.Nonce, err = rlpUint64(items[1]); err != nil {
		return err
	}
	if tx.GasTipCap, err = rlpU256(items[2]); err != nil {
		return err
	}
	if tx.GasFeeCap, err = rlpU256(items[3]); err != nil {
		return err
	}
	tx.GasPrice = tx.GasFeeCap
	if tx.Gas, err = rlpUint64(items[4]); err != nil {
		return err
	}
	if tx.To, err = rlpAddr(items[5]); err != nil {
		return err
	}
	if tx.Value, err = rlpU256(items[6]); err != nil {
		return err
	}
	if items[7].kind != rlpBytes {
		return ErrInvalidTx
	}
	tx.Data = append([]byte(nil), items[7].b...)
	if tx.AccessList, err = parseAccessList(items[8]); err != nil {
		return err
	}
	if tx.V, err = rlpU256(items[9]); err != nil {
		return err
	}
	if tx.R, err = rlpU256(items[10]); err != nil {
		return err
	}
	if tx.S, err = rlpU256(items[11]); err != nil {
		return err
	}
	return nil
}

func parseBlobTx(tx *Transaction, items []rlpVal) error {
	var err error
	if tx.ChainID, err = rlpU256(items[0]); err != nil {
		return err
	}
	if tx.Nonce, err = rlpUint64(items[1]); err != nil {
		return err
	}
	if tx.GasTipCap, err = rlpU256(items[2]); err != nil {
		return err
	}
	if tx.GasFeeCap, err = rlpU256(items[3]); err != nil {
		return err
	}
	tx.GasPrice = tx.GasFeeCap
	if tx.Gas, err = rlpUint64(items[4]); err != nil {
		return err
	}
	if tx.To, err = rlpAddr(items[5]); err != nil {
		return err
	}
	if tx.Value, err = rlpU256(items[6]); err != nil {
		return err
	}
	if items[7].kind != rlpBytes {
		return ErrInvalidTx
	}
	tx.Data = append([]byte(nil), items[7].b...)
	if tx.AccessList, err = parseAccessList(items[8]); err != nil {
		return err
	}
	if tx.BlobFeeCap, err = rlpU256(items[9]); err != nil {
		return err
	}
	if items[10].kind != rlpList {
		return ErrInvalidTx
	}
	for _, h := range items[10].list {
		if h.kind != rlpBytes || len(h.b) != 32 {
			return ErrInvalidTx
		}
		var hh Hash
		copy(hh[:], h.b)
		tx.BlobHashes = append(tx.BlobHashes, hh)
	}
	if tx.V, err = rlpU256(items[11]); err != nil {
		return err
	}
	if tx.R, err = rlpU256(items[12]); err != nil {
		return err
	}
	if tx.S, err = rlpU256(items[13]); err != nil {
		return err
	}
	return nil
}

func parseAccessList(v rlpVal) ([]AccessTuple, error) {
	if v.kind != rlpList {
		return nil, ErrInvalidTx
	}
	out := make([]AccessTuple, 0, len(v.list))
	for _, it := range v.list {
		if it.kind != rlpList || len(it.list) != 2 {
			return nil, ErrInvalidTx
		}
		addr, err := rlpAddr(it.list[0])
		if err != nil || addr == nil {
			return nil, ErrInvalidTx
		}
		if it.list[1].kind != rlpList {
			return nil, ErrInvalidTx
		}
		var keys []Hash
		for _, k := range it.list[1].list {
			if k.kind != rlpBytes || len(k.b) != 32 {
				return nil, ErrInvalidTx
			}
			var h Hash
			copy(h[:], k.b)
			keys = append(keys, h)
		}
		out = append(out, AccessTuple{Address: *addr, StorageKeys: keys})
	}
	return out, nil
}

func accessListEnc(al []AccessTuple) []byte {
	items := make([][]byte, len(al))
	for i, t := range al {
		keys := make([][]byte, len(t.StorageKeys))
		for j, k := range t.StorageKeys {
			keys[j] = rlpBytesEnc(k[:])
		}
		items[i] = rlpListEnc(rlpBytesEnc(t.Address[:]), rlpListEnc(keys...))
	}
	return rlpListEnc(items...)
}

func blobHashesEnc(hs []Hash) []byte {
	items := make([][]byte, len(hs))
	for i, h := range hs {
		items[i] = rlpBytesEnc(h[:])
	}
	return rlpListEnc(items...)
}

func (tx *Transaction) signingHash() Hash {
	switch tx.Type {
	case TxLegacy:
		items := [][]byte{
			rlpU64Enc(tx.Nonce),
			rlpU256Enc(tx.GasPrice),
			rlpU64Enc(tx.Gas),
			rlpAddrEnc(tx.To),
			rlpU256Enc(tx.Value),
			rlpBytesEnc(tx.Data),
		}
		if n, ok := u256ToU64(tx.V); ok && n >= 35 {
			cid := evm256.FromU64((n - 35) / 2)
			items = append(items, rlpU256Enc(cid), []byte{0x80}, []byte{0x80})
		}
		return keccak32(rlpListEnc(items...))
	case TxAccessList:
		body := rlpListEnc(
			rlpU256Enc(tx.ChainID),
			rlpU64Enc(tx.Nonce),
			rlpU256Enc(tx.GasPrice),
			rlpU64Enc(tx.Gas),
			rlpAddrEnc(tx.To),
			rlpU256Enc(tx.Value),
			rlpBytesEnc(tx.Data),
			accessListEnc(tx.AccessList),
		)
		return keccak32(append([]byte{TxAccessList}, body...))
	case TxDynamicFee:
		body := rlpListEnc(
			rlpU256Enc(tx.ChainID),
			rlpU64Enc(tx.Nonce),
			rlpU256Enc(tx.GasTipCap),
			rlpU256Enc(tx.GasFeeCap),
			rlpU64Enc(tx.Gas),
			rlpAddrEnc(tx.To),
			rlpU256Enc(tx.Value),
			rlpBytesEnc(tx.Data),
			accessListEnc(tx.AccessList),
		)
		return keccak32(append([]byte{TxDynamicFee}, body...))
	case TxBlob:
		body := rlpListEnc(
			rlpU256Enc(tx.ChainID),
			rlpU64Enc(tx.Nonce),
			rlpU256Enc(tx.GasTipCap),
			rlpU256Enc(tx.GasFeeCap),
			rlpU64Enc(tx.Gas),
			rlpAddrEnc(tx.To),
			rlpU256Enc(tx.Value),
			rlpBytesEnc(tx.Data),
			accessListEnc(tx.AccessList),
			rlpU256Enc(tx.BlobFeeCap),
			blobHashesEnc(tx.BlobHashes),
		)
		return keccak32(append([]byte{TxBlob}, body...))
	default:
		return Hash{}
	}
}

func u256ToU64(z evm256.Uint256) (uint64, bool) {
	if (z[1] | z[2] | z[3]) != 0 {
		return 0, false
	}
	return z[0], true
}

func yParity(v evm256.Uint256, typed bool) (uint8, error) {
	n, ok := u256ToU64(v)
	if !ok {
		return 0, ErrSender
	}
	if typed {
		if n > 1 {
			return 0, ErrSender
		}
		return uint8(n), nil
	}
	switch {
	case n == 27 || n == 28:
		return uint8(n - 27), nil
	case n == 0 || n == 1:
		return uint8(n), nil
	case n >= 35:
		return uint8((n - 35) & 1), nil
	default:
		return 0, ErrSender
	}
}

func recoverSender(sighash Hash, typed bool, v, r, s evm256.Uint256) (Address, error) {
	yp, err := yParity(v, typed)
	if err != nil {
		return Address{}, err
	}
	rb := evm256.BytesBE(r)
	sb := evm256.BytesBE(s)
	var pub [64]byte
	if err := c2crypto.EcRecover(sighash[:], yp, rb[:], sb[:], &pub); err != nil {
		return Address{}, ErrSender
	}
	h := keccak32(pub[:])
	var addr Address
	copy(addr[:], h[12:])
	return addr, nil
}
