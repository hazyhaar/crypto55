// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. See LICENSE and NOTICE.

package c2rpc

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2block"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
)

var (
	ErrHexPrefix = errors.New("c2rpc: hex prefix 0x required")
	ErrHexLength = errors.New("c2rpc: invalid hex length")
	ErrHexDigit  = errors.New("c2rpc: invalid hex digit")
)

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      json.RawMessage `json:"id,omitempty"`
}

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  any             `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
	ID      json.RawMessage `json:"id,omitempty"`
}

func (r Response) MarshalJSON() ([]byte, error) {
	id := r.ID
	if id == nil {
		id = json.RawMessage("null")
	}
	if r.Error != nil {
		return json.Marshal(struct {
			JSONRPC string          `json:"jsonrpc"`
			Error   *Error          `json:"error"`
			ID      json.RawMessage `json:"id"`
		}{"2.0", r.Error, id})
	}
	return json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		Result  any             `json:"result"`
		ID      json.RawMessage `json:"id"`
	}{"2.0", r.Result, id})
}

const (
	CodeParse      = -32700
	CodeInvalidReq = -32600
	CodeNoMethod   = -32601
	CodeInvParams  = -32602
	CodeInternal   = -32603
	CodeServer     = -32000
)

func rpcErr(code int, msg string) *Error {
	return &Error{Code: code, Message: msg}
}

func rpcErrData(code int, msg string, data any) *Error {
	return &Error{Code: code, Message: msg, Data: data}
}

func strip0x(s string) (string, error) {
	if len(s) < 2 || s[0] != '0' || (s[1] != 'x' && s[1] != 'X') {
		return "", ErrHexPrefix
	}
	return s[2:], nil
}

func EncodeBytes(b []byte) string {
	if len(b) == 0 {
		return "0x"
	}
	return "0x" + hex.EncodeToString(b)
}

func EncodeAddress(a c2block.Address) string {
	return "0x" + hex.EncodeToString(a[:])
}

func EncodeHash(h c2block.Hash) string {
	return "0x" + hex.EncodeToString(h[:])
}

func EncodeQuantity(n uint64) string {
	if n == 0 {
		return "0x0"
	}
	return "0x" + trimHexInt(n)
}

func trimHexInt(n uint64) string {
	s := hex.EncodeToString([]byte{
		byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32),
		byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n),
	})
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0"
	}
	return s
}

func EncodeUint256(z evm256.Uint256) string {
	if evm256.IsZero(&z) {
		return "0x0"
	}
	be := evm256.BytesBE(z)
	i := 0
	for i < 32 && be[i] == 0 {
		i++
	}
	s := hex.EncodeToString(be[i:])
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0x0"
	}
	return "0x" + s
}

func DecodeBytes(s string) ([]byte, error) {
	h, err := strip0x(s)
	if err != nil {
		return nil, err
	}
	if len(h)%2 != 0 {
		return nil, ErrHexLength
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, ErrHexDigit
	}
	return b, nil
}

func DecodeQuantity(s string) (uint64, error) {
	z, err := DecodeUint256(s)
	if err != nil {
		return 0, err
	}
	if z[1] != 0 || z[2] != 0 || z[3] != 0 {
		return 0, ErrHexLength
	}
	return z[0], nil
}

func DecodeUint256(s string) (evm256.Uint256, error) {
	h, err := strip0x(s)
	if err != nil {
		return evm256.Uint256{}, err
	}
	if h == "" {
		return evm256.Uint256{}, nil
	}
	if len(h)%2 != 0 {
		h = "0" + h
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return evm256.Uint256{}, ErrHexDigit
	}
	if len(b) > 32 {
		return evm256.Uint256{}, ErrHexLength
	}
	return evm256.FromBytesBE(b), nil
}

func DecodeAddress(s string) (c2block.Address, error) {
	b, err := DecodeBytes(s)
	if err != nil {
		return c2block.Address{}, err
	}
	if len(b) != 20 {
		return c2block.Address{}, ErrHexLength
	}
	var a c2block.Address
	copy(a[:], b)
	return a, nil
}

func DecodeHash(s string) (c2block.Hash, error) {
	b, err := DecodeBytes(s)
	if err != nil {
		return c2block.Hash{}, err
	}
	if len(b) != 32 {
		return c2block.Hash{}, ErrHexLength
	}
	var h c2block.Hash
	copy(h[:], b)
	return h, nil
}

func DecodeHashPad(s string) (c2block.Hash, error) {
	z, err := DecodeUint256(s)
	if err != nil {
		return c2block.Hash{}, err
	}
	return evm256.BytesBE(z), nil
}

type CallMsg struct {
	From     c2block.Address
	To       *c2block.Address
	Gas      uint64
	GasPrice evm256.Uint256
	Value    evm256.Uint256
	Data     []byte
}

type FilterQuery struct {
	FromBlock uint64
	ToBlock   uint64
	Addresses []c2block.Address
	Topics    [][]c2block.Hash
}

type SealedBlock struct {
	Hash     c2block.Hash
	Header   c2block.BlockHeader
	Txs      []*c2block.Transaction
	Receipts []*c2block.Receipt
}

type txIndex struct {
	block  c2block.Hash
	number uint64
	index  int
	tx     *c2block.Transaction
	rec    *c2block.Receipt
}
