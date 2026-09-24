// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. See LICENSE and NOTICE.

package c2block

import "code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"

const (
	TxLegacy     uint8 = 0
	TxAccessList uint8 = 1
	TxDynamicFee uint8 = 2
	TxBlob       uint8 = 3
)

type Address [20]byte
type Hash [32]byte

type AccessTuple struct {
	Address     Address
	StorageKeys []Hash
}

type Transaction struct {
	Type       uint8
	ChainID    evm256.Uint256
	Nonce      uint64
	GasPrice   evm256.Uint256
	GasTipCap  evm256.Uint256
	GasFeeCap  evm256.Uint256
	Gas        uint64
	To         *Address
	Value      evm256.Uint256
	Data       []byte
	AccessList []AccessTuple
	BlobFeeCap evm256.Uint256
	BlobHashes []Hash
	V          evm256.Uint256
	R          evm256.Uint256
	S          evm256.Uint256
	From       Address
	Hash       Hash
}

type BlockHeader struct {
	ParentHash    Hash
	Coinbase      Address
	StateRoot     Hash
	ReceiptsRoot  Hash
	Bloom         [256]byte
	Number        uint64
	GasLimit      uint64
	GasUsed       uint64
	Timestamp     uint64
	Extra         []byte
	MixDigest     Hash
	Nonce         uint64
	BaseFee       evm256.Uint256
	BlobGasUsed   uint64
	ExcessBlobGas uint64
	Difficulty    evm256.Uint256
	ChainID       evm256.Uint256
}

type Log struct {
	Address Address
	Topics  []Hash
	Data    []byte
}

type Receipt struct {
	Status            uint64
	CumulativeGasUsed uint64
	Bloom             [256]byte
	Logs              []*Log
	TxHash            Hash
	ContractAddress   Address
	GasUsed           uint64
	ReturnData        []byte
}

type BlockResult struct {
	Receipts     []*Receipt
	GasUsed      uint64
	ReceiptsRoot Hash
	Bloom        [256]byte
	StateRoot    Hash
}
