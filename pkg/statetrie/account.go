// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. See LICENSE and NOTICE.

package statetrie

import "code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"

type Account struct {
	Nonce       uint64
	Balance     evm256.Uint256
	StorageRoot [32]byte
	CodeHash    [32]byte
	Code        []byte
}
