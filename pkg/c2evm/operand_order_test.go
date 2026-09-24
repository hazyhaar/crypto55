// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. See LICENSE and NOTICE.

package c2evm

import (
	"encoding/hex"
	"testing"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
)

func runHex(t *testing.T, gas uint64, hexCode string) *ExecutionFrame {
	t.Helper()
	code, err := hex.DecodeString(hexCode)
	if err != nil {
		t.Fatal(err)
	}
	f := new(ExecutionFrame)
	f.Reset(gas)
	steps := 0
	for f.Status == StatusRunning {
		StepOne(f, code)
		steps++
		if steps > 100000 {
			t.Fatal("boucle de pas non bornée")
		}
	}
	return f
}

func TestEVMOperandOrder(t *testing.T) {
	allOnes := ^uint64(0)
	cases := []struct {
		name string
		hex  string
		want evm256.Uint256
	}{
		{"sub 3-5", "600560030300", evm256.Uint256{0xfffffffffffffffe, allOnes, allOnes, allOnes}},
		{"div 3/10", "600a60030400", evm256.FromU64(0)},
		{"sdiv 3/6", "600660030500", evm256.FromU64(0)},
		{"mod 3%10", "600a60030600", evm256.FromU64(3)},
		{"lt 3<5", "600560031000", evm256.FromU64(1)},
		{"gt 3>5", "600560031100", evm256.FromU64(0)},
		{"slt 3<5", "600560031200", evm256.FromU64(1)},
		{"sgt 3>5", "600560031300", evm256.FromU64(0)},
		{"addmod (3+4)%5", "6005600460030800", evm256.FromU64(2)},
		{"mulmod (3*4)%7", "6007600460030900", evm256.FromU64(5)},
		{"exp 8**2", "600260080a00", evm256.FromU64(64)},
		{"byte i=31 x=ff", "60ff601f1a00", evm256.FromU64(0xff)},
		{"shl val=1 shift=8", "600160081b00", evm256.FromU64(0x100)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := runHex(t, 10_000_000, tc.hex)
			if f.Status != StatusSuccess {
				t.Fatalf("status=%d", f.Status)
			}
			if f.SP != 1 {
				t.Fatalf("sp=%d", f.SP)
			}
			if !evm256.Eq(&f.Stack[0], &tc.want) {
				t.Fatalf("resultat=%v attendu=%v", f.Stack[0], tc.want)
			}
		})
	}
}

func TestExpGasUsesExponent(t *testing.T) {
	f := runHex(t, 10_000_000, "600260080a00")

	var gas uint64 = 10_000_000
	gas -= opGas[0x60]
	gas -= opGas[0x60]
	gas -= opGas[0x0a]
	gas -= 50 * 1
	gas -= opGas[0x00]
	if f.Gas != gas {
		t.Fatalf("gas restant=%d attendu=%d", f.Gas, gas)
	}
}
