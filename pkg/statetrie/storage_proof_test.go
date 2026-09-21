package statetrie

import (
	"testing"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2crypto"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
)

func TestGenerateStorageProofMultiSlot(t *testing.T) {
	tr := NewStateTrie()
	addr := evm256.FromU64(0x1234)
	tr.SetAccount(&addr, &Account{})
	slots := []uint64{1, 2, 7, 19, 0xdead, 0xbeef}
	for i, s := range slots {
		slot := evm256.FromU64(s)
		val := evm256.FromU64(uint64(0x1000 + i))
		tr.SetStorage(&addr, &slot, &val)
	}

	root, _, err := tr.GenerateStorageProof(addr, evm256.FromU64(slots[0]))
	if err != nil {
		t.Fatalf("preuve initiale: %v", err)
	}
	if root != tr.storageRootOf(addr) {
		t.Fatalf("racine de preuve %x != racine de compte %x", root, tr.storageRootOf(addr))
	}

	for i, s := range slots {
		slot := evm256.FromU64(s)
		val := evm256.FromU64(uint64(0x1000 + i))
		gotRoot, proof, err := tr.GenerateStorageProof(addr, slot)
		if err != nil {
			t.Fatalf("slot %d: %v", s, err)
		}
		if gotRoot != root {
			t.Fatalf("slot %d: racine divergente", s)
		}
		var keyHash [32]byte
		be := evm256.BytesBE(slot)
		c2crypto.Keccak256(be[:], &keyHash)
		if !VerifyStorageProof(gotRoot, keyHash, EncodeStorageValue(val), proof) {
			t.Fatalf("slot %d: preuve valide rejetée", s)
		}
		if VerifyStorageProof(gotRoot, keyHash, EncodeStorageValue(evm256.FromU64(0xffff)), proof) {
			t.Fatalf("slot %d: valeur erronée acceptée", s)
		}
	}
}

func TestGenerateStorageProofAbsentSlot(t *testing.T) {
	tr := NewStateTrie()
	addr := evm256.FromU64(0x55)
	tr.SetAccount(&addr, &Account{})
	slot := evm256.FromU64(3)
	val := evm256.FromU64(42)
	tr.SetStorage(&addr, &slot, &val)

	absent := evm256.FromU64(99)
	root, proof, err := tr.GenerateStorageProof(addr, absent)
	if err != nil {
		t.Fatalf("preuve exclusion: %v", err)
	}
	var keyHash [32]byte
	be := evm256.BytesBE(absent)
	c2crypto.Keccak256(be[:], &keyHash)
	if !VerifyStorageProof(root, keyHash, EncodeStorageValue(evm256.Uint256{}), proof) {
		t.Fatal("preuve d'exclusion d'un slot nul rejetée")
	}
	if VerifyStorageProof(root, keyHash, EncodeStorageValue(evm256.FromU64(1)), proof) {
		t.Fatal("valeur non nulle acceptée pour un slot absent")
	}
}

func (t *StateTrie) storageRootOf(addr evm256.Uint256) [32]byte {
	a := normalizeAddr(&addr)
	var slots []slotPair
	for k, v := range t.storage {
		if k.addr == a {
			slots = append(slots, slotPair{slot: k.slot, val: v})
		}
	}
	return hashStorage(slots)
}
