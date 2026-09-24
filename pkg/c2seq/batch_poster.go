// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. See LICENSE and NOTICE.

package c2seq

import (
	"errors"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2block"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2crypto"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
)

const maxBatchPlain = 512 * 1024

var (
	ErrBatchFormat   = errors.New("c2seq: invalid batch")
	ErrBatchTooLarge = errors.New("c2seq: batch too large")
)

type BatchPoster struct{}

func NewBatchPoster() *BatchPoster {
	return &BatchPoster{}
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

func encodeTx(tx *c2block.Transaction) []byte {
	var to []byte
	if tx.To != nil {
		to = tx.To[:]
	}
	return rlpList(
		rlpU64(uint64(tx.Type)),
		rlpU64(tx.Nonce),
		rlpU64(tx.Gas),
		rlpU256(tx.GasTipCap),
		rlpU256(tx.GasFeeCap),
		rlpU256(tx.GasPrice),
		rlpBytes(to),
		rlpU256(tx.Value),
		rlpBytes(tx.Data),
		rlpBytes(tx.From[:]),
		rlpBytes(tx.Hash[:]),
	)
}

func brotliUncompressed(payload []byte) ([]byte, error) {
	mlen := len(payload)
	if mlen == 0 {
		return []byte{0x06}, nil
	}
	if mlen > maxBatchPlain {
		return nil, ErrBatchTooLarge
	}
	m1 := uint64(mlen - 1)
	nib := 0
	nbits := 16
	switch {
	case m1 < 1<<16:
		nib, nbits = 0, 16
	case m1 < 1<<20:
		nib, nbits = 1, 20
	case m1 < 1<<24:
		nib, nbits = 2, 24
	default:
		return nil, ErrBatchTooLarge
	}
	var acc uint64
	var nb int
	put := func(v uint64, n int) {
		acc |= v << nb
		nb += n
	}
	put(0, 1)
	put(0, 1)
	put(uint64(nib), 2)
	put(m1, nbits)
	put(1, 1)
	for nb%8 != 0 {
		put(0, 1)
	}
	out := make([]byte, 0, nb/8+len(payload)+1)
	for i := 0; i < nb; i += 8 {
		out = append(out, byte(acc>>i))
	}
	out = append(out, payload...)
	out = append(out, 0x03)
	return out, nil
}

func (p *BatchPoster) Pack(txs []*c2block.Transaction) ([]byte, error) {
	items := make([][]byte, len(txs))
	total := 0
	for i, tx := range txs {
		if tx == nil {
			return nil, ErrNilTx
		}
		enc := encodeTx(tx)
		total += len(enc)
		if total > maxBatchPlain {
			return nil, ErrBatchTooLarge
		}
		items[i] = enc
	}
	plain := rlpList(items...)
	if len(plain) > maxBatchPlain {
		return nil, ErrBatchTooLarge
	}
	return brotliUncompressed(plain)
}

type rlpVal struct {
	list bool
	b    []byte
	elts []rlpVal
}

func rlpReadInt(b []byte) (int, error) {
	if len(b) == 0 || len(b) > 8 {
		return 0, ErrBatchFormat
	}
	if len(b) > 1 && b[0] == 0 {
		return 0, ErrBatchFormat
	}
	n := 0
	for _, c := range b {
		if n > (int(^uint(0)>>1) >> 8) {
			return 0, ErrBatchTooLarge
		}
		n = (n << 8) | int(c)
	}
	return n, nil
}

func rlpDecode(buf []byte) (rlpVal, []byte, error) {
	if len(buf) == 0 {
		return rlpVal{}, nil, ErrBatchFormat
	}
	b := buf[0]
	if b < 0x80 {
		return rlpVal{b: buf[:1]}, buf[1:], nil
	}
	if b < 0xb8 {
		n := int(b - 0x80)
		if n == 1 && len(buf) > 1 && buf[1] < 0x80 {
			return rlpVal{}, nil, ErrBatchFormat
		}
		if n > len(buf)-1 {
			return rlpVal{}, nil, ErrBatchFormat
		}
		return rlpVal{b: buf[1 : 1+n]}, buf[1+n:], nil
	}
	if b < 0xc0 {
		llen := int(b - 0xb7)
		if llen == 0 || llen > len(buf)-1 {
			return rlpVal{}, nil, ErrBatchFormat
		}
		n, err := rlpReadInt(buf[1 : 1+llen])
		if err != nil || n < 56 {
			return rlpVal{}, nil, ErrBatchFormat
		}
		if 1+llen > len(buf) || n > len(buf)-(1+llen) {
			return rlpVal{}, nil, ErrBatchFormat
		}
		return rlpVal{b: buf[1+llen : 1+llen+n]}, buf[1+llen+n:], nil
	}
	var payload []byte
	var rest []byte
	if b < 0xf8 {
		n := int(b - 0xc0)
		if n > len(buf)-1 {
			return rlpVal{}, nil, ErrBatchFormat
		}
		payload = buf[1 : 1+n]
		rest = buf[1+n:]
	} else {
		llen := int(b - 0xf7)
		if llen == 0 || llen > len(buf)-1 {
			return rlpVal{}, nil, ErrBatchFormat
		}
		n, err := rlpReadInt(buf[1 : 1+llen])
		if err != nil || n < 56 {
			return rlpVal{}, nil, ErrBatchFormat
		}
		if 1+llen > len(buf) || n > len(buf)-(1+llen) {
			return rlpVal{}, nil, ErrBatchFormat
		}
		payload = buf[1+llen : 1+llen+n]
		rest = buf[1+llen+n:]
	}
	var items []rlpVal
	for len(payload) > 0 {
		if len(items) >= 4096 {
			return rlpVal{}, nil, ErrBatchTooLarge
		}
		v, next, err := rlpDecode(payload)
		if err != nil {
			return rlpVal{}, nil, err
		}
		items = append(items, v)
		payload = next
	}
	return rlpVal{list: true, elts: items}, rest, nil
}

func rlpToU64(v rlpVal) (uint64, error) {
	if v.list {
		return 0, ErrBatchFormat
	}
	if len(v.b) == 0 {
		return 0, nil
	}
	if len(v.b) > 8 || v.b[0] == 0 {
		return 0, ErrBatchFormat
	}
	var n uint64
	for _, c := range v.b {
		n = (n << 8) | uint64(c)
	}
	return n, nil
}

func rlpToU256(v rlpVal) (evm256.Uint256, error) {
	if v.list || len(v.b) > 32 {
		return evm256.Uint256{}, ErrBatchFormat
	}
	if len(v.b) > 1 && v.b[0] == 0 {
		return evm256.Uint256{}, ErrBatchFormat
	}
	return evm256.FromBytesBE(v.b), nil
}

func decodeTx(v rlpVal) (*c2block.Transaction, error) {
	if !v.list || len(v.elts) != 11 {
		return nil, ErrBatchFormat
	}
	tx := new(c2block.Transaction)
	typ, err := rlpToU64(v.elts[0])
	if err != nil {
		return nil, err
	}
	tx.Type = uint8(typ)
	if tx.Nonce, err = rlpToU64(v.elts[1]); err != nil {
		return nil, err
	}
	if tx.Gas, err = rlpToU64(v.elts[2]); err != nil {
		return nil, err
	}
	if tx.GasTipCap, err = rlpToU256(v.elts[3]); err != nil {
		return nil, err
	}
	if tx.GasFeeCap, err = rlpToU256(v.elts[4]); err != nil {
		return nil, err
	}
	if tx.GasPrice, err = rlpToU256(v.elts[5]); err != nil {
		return nil, err
	}
	if v.elts[6].list {
		return nil, ErrBatchFormat
	}
	if n := len(v.elts[6].b); n == 20 {
		var a c2block.Address
		copy(a[:], v.elts[6].b)
		tx.To = &a
	} else if n != 0 {
		return nil, ErrBatchFormat
	}
	if tx.Value, err = rlpToU256(v.elts[7]); err != nil {
		return nil, err
	}
	if v.elts[8].list {
		return nil, ErrBatchFormat
	}
	tx.Data = append([]byte(nil), v.elts[8].b...)
	if v.elts[9].list || len(v.elts[9].b) != 20 {
		return nil, ErrBatchFormat
	}
	copy(tx.From[:], v.elts[9].b)
	if v.elts[10].list || len(v.elts[10].b) != 32 {
		return nil, ErrBatchFormat
	}
	copy(tx.Hash[:], v.elts[10].b)
	return tx, nil
}

func (p *BatchPoster) Unpack(calldata []byte) ([]*c2block.Transaction, error) {
	plain := make([]byte, maxBatchPlain)
	n, err := c2crypto.BrotliL2Decompress(calldata, plain)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	v, rest, err := rlpDecode(plain[:n])
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 || !v.list {
		return nil, ErrBatchFormat
	}
	out := make([]*c2block.Transaction, 0, len(v.elts))
	for _, it := range v.elts {
		tx, err := decodeTx(it)
		if err != nil {
			return nil, err
		}
		out = append(out, tx)
	}
	return out, nil
}
