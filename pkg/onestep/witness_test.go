// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. See LICENSE and NOTICE.

package onestep

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2crypto"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2evm"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/statetrie"
)

func cloneFrame(f *c2evm.ExecutionFrame) *c2evm.ExecutionFrame {
	c := *f
	return &c
}

type memState struct {
	key evm256.Uint256
	val evm256.Uint256
	set bool
}

func (m *memState) GetStorage(_, key, val *evm256.Uint256) {
	if m.set && *key == m.key {
		*val = m.val
		return
	}
	*val = evm256.Uint256{}
}

func (m *memState) SetStorage(_, key, val *evm256.Uint256) {
	m.key = *key
	m.val = *val
	m.set = true
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func runAndVerify(t *testing.T, name string, code []byte, db c2evm.StateAccessor) int {
	t.Helper()
	f := new(c2evm.ExecutionFrame)
	f.StateDB = db
	f.Reset(1_000_000)
	n := 0
	for f.Status == c2evm.StatusRunning {
		if int(f.PC) >= len(code) {
			break
		}
		op := code[f.PC]
		pre := cloneFrame(f)
		c2evm.StepOne(f, code)
		post := cloneFrame(f)
		if !opcodeSupported(op) {
			continue
		}
		w, err := CaptureWitness(pre, post, op)
		if err != nil {
			t.Fatalf("%s capture op=%02x: %v", name, op, err)
		}
		ok, err := VerifyWitness(w)
		if !ok || err != nil {
			t.Fatalf("%s verify op=%02x pc=%d: ok=%v err=%v", name, op, pre.PC, ok, err)
		}
		n++
	}
	if n == 0 {
		t.Fatalf("%s: aucun pas capturé", name)
	}
	return n
}

func TestCaptureAndVerifyWitness(t *testing.T) {
	cases := []struct {
		name string
		hex  string
		db   c2evm.StateAccessor
	}{
		{"add", "6005600301", nil},
		{"sub", "6005600303", nil},
		{"mul", "6005600302", nil},
		{"div", "600a600304", nil},
		{"and", "600f600316", nil},
		{"or", "6005600317", nil},
		{"xor", "600f600318", nil},
		{"shl", "600160011b", nil},
		{"shr", "600860011c", nil},
		{"push_dup_swap", "60016002800190", nil},
		{"mstore_mload", "602a5f52600051", nil},
		{"jump", "600456005b602a00", nil},
		{"jumpi_taken", "6001600657005b00", nil},
		{"jumpi_skip", "5f600757602a5b00", nil},
		{"sstore_sload", "602a600155600154", &memState{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runAndVerify(t, tc.name, mustHex(t, tc.hex), tc.db)
		})
	}
}

func captureOne(t *testing.T, code []byte, wantOp byte) *StepWitness {
	t.Helper()
	f := new(c2evm.ExecutionFrame)
	f.Reset(1_000_000)
	for f.Status == c2evm.StatusRunning {
		if int(f.PC) >= len(code) {
			t.Fatal("opcode cible absent")
		}
		op := code[f.PC]
		pre := cloneFrame(f)
		c2evm.StepOne(f, code)
		if op != wantOp {
			continue
		}
		w, err := CaptureWitness(pre, cloneFrame(f), op)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	t.Fatal("opcode cible absent")
	return nil
}

func TestWitnessRejectionOnTampering(t *testing.T) {
	w := captureOne(t, mustHex(t, "6005600301"), 0x01)
	ok, err := VerifyWitness(w)
	if !ok || err != nil {
		t.Fatalf("témoin intact rejeté: ok=%v err=%v", ok, err)
	}

	t.Run("stackIn", func(t *testing.T) {
		c := *w
		c.StackIn[0][0] ^= 1
		ok, _ := VerifyWitness(&c)
		if ok {
			t.Fatal("stackIn altéré doit être rejeté")
		}
	})
	t.Run("stackOut", func(t *testing.T) {
		c := *w
		c.StackOut[0][0] ^= 1
		ok, _ := VerifyWitness(&c)
		if ok {
			t.Fatal("stackOut altéré doit être rejeté")
		}
	})
	t.Run("postStateRoot", func(t *testing.T) {
		c := *w
		c.PostStateRoot[0] ^= 1
		ok, _ := VerifyWitness(&c)
		if ok {
			t.Fatal("postStateRoot altéré doit être rejeté")
		}
	})
}

func TestABIEncoding(t *testing.T) {
	var pre, post [32]byte
	for i := range pre {
		pre[i] = 0x11
		post[i] = 0x22
	}
	var mem [32]byte
	for i := range mem {
		mem[i] = byte(i)
	}
	w := &StepWitness{
		PreStateRoot:  pre,
		PostStateRoot: post,
		PC:            0xaabbccdd,
		Opcode:        0x01,
		Gas:           0x0123456789abcdef,
		StackIn: [4]evm256.Uint256{
			evm256.FromU64(1),
			evm256.FromU64(2),
			evm256.FromU64(3),
			evm256.FromU64(4),
		},
		StackOut: [4]evm256.Uint256{
			evm256.FromU64(5),
			evm256.FromU64(6),
			evm256.FromU64(7),
			evm256.FromU64(8),
		},
		MemOffset:  0x100,
		MemData:    mem,
		StorageKey: evm256.FromU64(9),
		StorageVal: evm256.FromU64(10),
	}
	enc := EncodeWitnessABI(w)
	const base = 32
	if len(enc) != base+abiWitnessWords*32+32 {
		t.Fatalf("longueur ABI=%d, attendu %d", len(enc), base+abiWitnessWords*32+32)
	}
	if binary.BigEndian.Uint64(enc[24:32]) != base {
		t.Fatalf("offset tuple=%x", enc[24:32])
	}
	if binary.BigEndian.Uint64(enc[base+576+24:base+608]) != uint64(abiWitnessWords*32) {
		t.Fatalf("offset preuve=%x", enc[base+576+24:base+608])
	}
	if binary.BigEndian.Uint64(enc[base+abiWitnessWords*32+24:base+abiWitnessWords*32+32]) != 0 {
		t.Fatal("preuve de stockage non vide attendue vide")
	}
	if string(enc[base:base+32]) != string(pre[:]) {
		t.Fatal("preStateRoot")
	}
	if string(enc[base+32:base+64]) != string(post[:]) {
		t.Fatal("postStateRoot")
	}
	if binary.BigEndian.Uint32(enc[base+92:base+96]) != 0xaabbccdd {
		t.Fatalf("pc=%x", enc[base+92:base+96])
	}
	if enc[base+127] != 0x01 {
		t.Fatalf("opcode=%x", enc[base+127])
	}
	if binary.BigEndian.Uint64(enc[base+152:base+160]) != 0x0123456789abcdef {
		t.Fatalf("gas=%x", enc[base+152:base+160])
	}
	for i, want := range []uint64{1, 2, 3, 4} {
		got := evm256.FromBytesBE(enc[base+160+i*32 : base+192+i*32])
		if got != evm256.FromU64(want) {
			t.Fatalf("stackIn[%d]=%v", i, got)
		}
	}
	for i, want := range []uint64{5, 6, 7, 8} {
		got := evm256.FromBytesBE(enc[base+288+i*32 : base+320+i*32])
		if got != evm256.FromU64(want) {
			t.Fatalf("stackOut[%d]=%v", i, got)
		}
	}
	if binary.BigEndian.Uint32(enc[base+444:base+448]) != 0x100 {
		t.Fatalf("memOffset=%x", enc[base+444:base+448])
	}
	if string(enc[base+448:base+480]) != string(mem[:]) {
		t.Fatal("memData")
	}
	if evm256.FromBytesBE(enc[base+480:base+512]) != evm256.FromU64(9) {
		t.Fatal("storageKey")
	}
	if evm256.FromBytesBE(enc[base+512:base+544]) != evm256.FromU64(10) {
		t.Fatal("storageVal")
	}
}

func TestStorageProofGenerationAndVerification(t *testing.T) {
	tr := statetrie.NewStateTrie()
	addr := evm256.FromU64(0x42)
	slot := evm256.FromU64(7)
	val := evm256.FromU64(0x123456)
	tr.SetAccount(&addr, &statetrie.Account{})
	tr.SetStorage(&addr, &slot, &val)

	root, proof, err := tr.GenerateStorageProof(addr, slot)
	if err != nil {
		t.Fatalf("génération preuve: %v", err)
	}
	if len(proof) == 0 {
		t.Fatal("preuve vide")
	}
	var keyHash [32]byte
	be := evm256.BytesBE(slot)
	c2crypto.Keccak256(be[:], &keyHash)
	if !statetrie.VerifyStorageProof(root, keyHash, statetrie.EncodeStorageValue(val), proof) {
		t.Fatal("preuve valide rejetée")
	}
	if statetrie.VerifyStorageProof(root, keyHash, statetrie.EncodeStorageValue(evm256.FromU64(999)), proof) {
		t.Fatal("valeur erronée acceptée")
	}
	if statetrie.VerifyStorageProof([32]byte{0x01}, keyHash, statetrie.EncodeStorageValue(val), proof) {
		t.Fatal("racine erronée acceptée")
	}
}

func TestCaptureWitnessWithStorageProof(t *testing.T) {
	tr := statetrie.NewStateTrie()
	addr := evm256.FromU64(0x42)
	slot := evm256.FromU64(7)
	val := evm256.FromU64(0x123456)
	tr.SetAccount(&addr, &statetrie.Account{})
	tr.SetStorage(&addr, &slot, &val)

	code := mustHex(t, "62123456600755600754")
	f := new(c2evm.ExecutionFrame)
	f.StateDB = tr
	f.Reset(1_000_000)
	var sload *StepWitness
	for f.Status == c2evm.StatusRunning {
		if int(f.PC) >= len(code) {
			break
		}
		op := code[f.PC]
		pre := cloneFrame(f)
		c2evm.StepOne(f, code)
		post := cloneFrame(f)
		if op != 0x54 && op != 0x55 {
			continue
		}
		w, err := CaptureWitnessWithStorage(pre, post, op, tr, addr)
		if err != nil {
			t.Fatalf("capture op=%02x: %v", op, err)
		}
		if len(w.StorageProof) == 0 {
			t.Fatalf("preuve absente pour op=%02x", op)
		}
		ok, err := VerifyWitness(w)
		if !ok || err != nil {
			t.Fatalf("vérification op=%02x: ok=%v err=%v", op, ok, err)
		}
		if op == 0x54 {
			sload = w
		}
	}
	if sload == nil {
		t.Fatal("aucun SLOAD capturé")
	}

	t.Run("proofTampered", func(t *testing.T) {
		c := *sload
		c.StorageProof = make([][]byte, len(sload.StorageProof))
		for i, node := range sload.StorageProof {
			c.StorageProof[i] = append([]byte(nil), node...)
		}
		c.StorageProof[0][len(c.StorageProof[0])-1] ^= 1
		if ok, _ := VerifyWitness(&c); ok {
			t.Fatal("preuve falsifiée acceptée")
		}
	})

	t.Run("abiEncoding", func(t *testing.T) {
		enc := EncodeWitnessABI(sload)
		nodeLen := len(sload.StorageProof[0])
		want := 32 + abiWitnessWords*32 + 32 + 32 + 32 + ((nodeLen+31)/32)*32
		if len(enc) != want {
			t.Fatalf("longueur ABI=%d, attendu %d", len(enc), want)
		}
		if string(enc[32+544:32+576]) != string(sload.StorageRoot[:]) {
			t.Fatal("racine de stockage absente de l'encodage ABI")
		}
		if binary.BigEndian.Uint64(enc[32+abiWitnessWords*32+24:32+abiWitnessWords*32+32]) != 1 {
			t.Fatal("longueur de preuve ABI incorrecte")
		}
	})
}
