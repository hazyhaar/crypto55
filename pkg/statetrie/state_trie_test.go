// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. See LICENSE and NOTICE.

package statetrie

import (
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2crypto"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2evm"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
)

func mustRoot(t *testing.T, s string) [32]byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 32 {
		t.Fatalf("longueur racine=%d", len(raw))
	}
	var out [32]byte
	copy(out[:], raw)
	return out
}

func TestStateTrieCanonicalRootSingleAccount(t *testing.T) {
	tr := NewStateTrie()
	addr := evm256.FromU64(1)
	tr.SetAccount(&addr, &Account{Balance: evm256.FromU64(1)})
	got := tr.ComputeRoot()
	want := mustRoot(t, "8028c28b55eab8be08883e921f20d1b6cc9f2aa02cc6cd90cfaa9b0462ff6d3e")
	if got != want {
		t.Fatalf("racine canonique=%x, attendu %x", got, want)
	}
}

func TestStateTrieGenerateProof(t *testing.T) {
	tr := NewStateTrie()
	a1 := evm256.FromU64(1)
	a2 := evm256.FromU64(2)
	tr.SetAccount(&a1, &Account{Balance: evm256.FromU64(5)})
	tr.SetAccount(&a2, &Account{Balance: evm256.FromU64(7)})

	if _, err := tr.GenerateProof(evm256.FromU64(3)); err != ErrProofNotFound {
		t.Fatalf("compte absent: err=%v, attendu %v", err, ErrProofNotFound)
	}
	proof, err := tr.GenerateProof(a1)
	if err != nil {
		t.Fatalf("preuve: %v", err)
	}
	if len(proof) == 0 {
		t.Fatal("preuve vide")
	}
	var h [32]byte
	c2crypto.Keccak256(proof[0], &h)
	if h != tr.ComputeRoot() {
		t.Fatalf("tête de preuve %x ne hache pas la racine %x", h, tr.ComputeRoot())
	}
	for i, node := range proof {
		if len(node) == 0 {
			t.Fatalf("nœud %d vide", i)
		}
	}
}

func TestStateTrieRootEmpty(t *testing.T) {
	tr := NewStateTrie()
	root := tr.ComputeRoot()
	raw, err := hex.DecodeString("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
	if err != nil {
		t.Fatal(err)
	}
	var want [32]byte
	copy(want[:], raw)
	if root != want {
		t.Fatalf("racine vide=%x, attendu %x", root, want)
	}
}

func TestStateTrieStorageAndRevert(t *testing.T) {
	tr := NewStateTrie()
	addr := evm256.FromU64(1)
	key := evm256.FromU64(2)
	v1 := evm256.FromU64(10)
	v2 := evm256.FromU64(20)

	tr.SetStorage(&addr, &key, &v1)
	var got evm256.Uint256
	tr.GetStorage(&addr, &key, &got)
	if !evm256.Eq(&got, &v1) {
		t.Fatalf("après écriture: %v", got)
	}

	rev := tr.Snapshot()
	tr.SetStorage(&addr, &key, &v2)
	tr.GetStorage(&addr, &key, &got)
	if !evm256.Eq(&got, &v2) {
		t.Fatalf("après mutation: %v", got)
	}

	delta := evm256.FromU64(100)
	tr.AddBalance(&addr, &delta)
	var bal evm256.Uint256
	tr.GetBalance(&addr, &bal)
	if !evm256.Eq(&bal, &delta) {
		t.Fatalf("solde après AddBalance: %v", bal)
	}

	tr.RevertToSnapshot(rev)
	tr.GetStorage(&addr, &key, &got)
	if !evm256.Eq(&got, &v1) {
		t.Fatalf("après revert storage=%v, attendu %v", got, v1)
	}
	tr.GetBalance(&addr, &bal)
	if !evm256.IsZero(&bal) {
		t.Fatalf("après revert solde=%v, attendu zéro", bal)
	}
	if _, ok := tr.GetAccount(&addr); ok {
		t.Fatalf("le compte créé après l'instantané doit disparaître")
	}
}

func TestStateTrieIntegrationC2EVM(t *testing.T) {
	tr := NewStateTrie()
	f := new(c2evm.ExecutionFrame)
	f.StateDB = tr
	f.Reset(1_000_000)
	code, err := hex.DecodeString("602a60015560015400")
	if err != nil {
		t.Fatal(err)
	}
	for f.Status == c2evm.StatusRunning {
		c2evm.StepOne(f, code)
	}
	if f.Status != c2evm.StatusSuccess {
		t.Fatalf("status=%d", f.Status)
	}
	want := evm256.FromU64(0x2a)
	if f.SP != 1 || !evm256.Eq(&f.Stack[0], &want) {
		t.Fatalf("stack=%v sp=%d", f.Stack[0], f.SP)
	}
	var got evm256.Uint256
	addr := evm256.Uint256{}
	key := evm256.FromU64(1)
	tr.GetStorage(&addr, &key, &got)
	if !evm256.Eq(&got, &want) {
		t.Fatalf("storage=%v, attendu %v", got, want)
	}
}

func TestStateTrieAddressNormalization(t *testing.T) {
	tr := NewStateTrie()
	// a1 est une adresse 20-octets avec des bits parasites au-delà des 160 bits
	a1 := evm256.Uint256{1, 0, 0xdeadbeef00000000, 0x123456789abcdef0}
	a2 := evm256.Uint256{1, 0, 0, 0} // même adresse canonique (1)

	bal := evm256.FromU64(1000)
	tr.SetAccount(&a1, &Account{Balance: bal})

	var got evm256.Uint256
	tr.GetBalance(&a2, &got)
	if !evm256.Eq(&got, &bal) {
		t.Fatalf("balance normalisée=%v, attendu %v", got, bal)
	}

	slot := evm256.FromU64(42)
	val := evm256.FromU64(999)
	tr.SetStorage(&a1, &slot, &val)

	var sgot evm256.Uint256
	tr.GetStorage(&a2, &slot, &sgot)
	if !evm256.Eq(&sgot, &val) {
		t.Fatalf("storage normalisé=%v, attendu %v", sgot, val)
	}
}

func TestStateTrieAccountDeletionPurgesStorage(t *testing.T) {
	tr := NewStateTrie()
	addr := evm256.FromU64(0xcafe)
	tr.SetAccount(&addr, &Account{Balance: evm256.FromU64(50)})
	slot := evm256.FromU64(1)
	val := evm256.FromU64(100)
	tr.SetStorage(&addr, &slot, &val)

	// Supprimer le compte
	tr.SetAccount(&addr, nil)

	// La racine doit redevenir la racine vide car plus aucun compte ni storage ne subsiste
	root := tr.ComputeRoot()
	raw, _ := hex.DecodeString("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
	var want [32]byte
	copy(want[:], raw)
	if root != want {
		t.Fatalf("racine après suppression du compte et vidage storage=%x, attendu racine vide %x", root, want)
	}
}

func TestStateTrieExclusionProof(t *testing.T) {
	tr := NewStateTrie()
	a1 := evm256.FromU64(1)
	a2 := evm256.FromU64(2)
	tr.SetAccount(&a1, &Account{Balance: evm256.FromU64(10)})
	tr.SetAccount(&a2, &Account{Balance: evm256.FromU64(20)})

	// Recherche d'un compte inexistant
	missing := evm256.FromU64(999)
	proof, err := tr.GenerateProof(missing)
	if err != ErrProofNotFound {
		t.Fatalf("err=%v, attendu ErrProofNotFound", err)
	}
	// La preuve d'exclusion doit contenir au moins le nœud racine
	if len(proof) == 0 {
		t.Fatalf("la preuve d'exclusion ne doit pas être vide")
	}
	var h [32]byte
	c2crypto.Keccak256(proof[0], &h)
	if h != tr.ComputeRoot() {
		t.Fatalf("racine de preuve d'exclusion %x != trie root %x", h, tr.ComputeRoot())
	}
}

func TestStateTrieCommitClearsJournal(t *testing.T) {
	tr := NewStateTrie()
	addr := evm256.FromU64(1)
	key := evm256.FromU64(2)
	v := evm256.FromU64(10)
	tr.Snapshot()
	tr.SetStorage(&addr, &key, &v)
	if len(tr.journal) == 0 {
		t.Fatal("journal vide après mutation")
	}
	tr.Commit()
	if len(tr.journal) != 0 || len(tr.reverts) != 0 {
		t.Fatalf("journal=%d reverts=%d attendus nuls", len(tr.journal), len(tr.reverts))
	}
	var got evm256.Uint256
	tr.GetStorage(&addr, &key, &got)
	if !evm256.Eq(&got, &v) {
		t.Fatalf("storage scellé=%v attendu %v", got, v)
	}
}

func TestStateTrieDiscardSnapshot(t *testing.T) {
	tr := NewStateTrie()
	addr := evm256.FromU64(1)
	key := evm256.FromU64(2)
	v1 := evm256.FromU64(10)
	v2 := evm256.FromU64(20)

	outer := tr.Snapshot()
	tr.SetStorage(&addr, &key, &v1)
	inner := tr.Snapshot()
	tr.SetStorage(&addr, &key, &v2)

	tr.DiscardSnapshot(inner)
	if len(tr.reverts) != 1 {
		t.Fatalf("reverts=%d attendu 1", len(tr.reverts))
	}
	if len(tr.journal) == 0 {
		t.Fatal("journal compacté alors qu'un point de reprise subsiste")
	}
	tr.RevertToSnapshot(outer)
	var got evm256.Uint256
	tr.GetStorage(&addr, &key, &got)
	if !evm256.IsZero(&got) {
		t.Fatalf("storage après revert=%v attendu zéro", got)
	}

	rev := tr.Snapshot()
	tr.SetStorage(&addr, &key, &v2)
	tr.DiscardSnapshot(rev)
	if len(tr.reverts) != 0 || len(tr.journal) != 0 {
		t.Fatalf("reverts=%d journal=%d attendus nuls après compactage", len(tr.reverts), len(tr.journal))
	}
	tr.GetStorage(&addr, &key, &got)
	if !evm256.Eq(&got, &v2) {
		t.Fatalf("storage conservé=%v attendu %v", got, v2)
	}
}

// TestStateTrieComputeRootZeroAlloc vérifie qu'en régime stabilisé, une fois
// l'arène dimensionnée par les mutations, les appels consécutifs à ComputeRoot
// n'allouent plus sur le tas. AllocsPerRun absorbe l'appel de préchauffage.
func TestStateTrieComputeRootZeroAlloc(t *testing.T) {
	tr := NewStateTrie()
	for i := uint64(1); i <= 100; i++ {
		addr := evm256.FromU64(i)
		tr.SetAccount(&addr, &Account{Balance: evm256.FromU64(i * 1000)})
		slot := evm256.FromU64(i)
		val := evm256.FromU64(i * 42)
		tr.SetStorage(&addr, &slot, &val)
	}
	allocs := testing.AllocsPerRun(100, func() {
		_ = tr.ComputeRoot()
	})
	if allocs != 0 {
		t.Fatalf("ComputeRoot alloue %v allocations/op, attendu 0", allocs)
	}
}

func BenchmarkStateTrieComputeRoot(b *testing.B) {
	tr := NewStateTrie()
	for i := uint64(1); i <= 100; i++ {
		addr := evm256.FromU64(i)
		tr.SetAccount(&addr, &Account{Balance: evm256.FromU64(i * 1000)})
		slot := evm256.FromU64(i)
		val := evm256.FromU64(i * 42)
		tr.SetStorage(&addr, &slot, &val)
	}
	// Préchauffage hors mesure
	_ = tr.ComputeRoot()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = tr.ComputeRoot()
	}
}

// 1. Égalité bit-exacte entre trie recyclé après churn et trie frais
func TestStateTrieArenaReuseAfterChurn(t *testing.T) {
	tr := NewStateTrie()
	for i := uint64(1); i <= 60; i++ {
		a := evm256.FromU64(i)
		tr.SetAccount(&a, &Account{Balance: evm256.FromU64(i * 10)})
		s := evm256.FromU64(i)
		v := evm256.FromU64(i * 100)
		tr.SetStorage(&a, &s, &v)
	}
	_ = tr.ComputeRoot()

	// Suppression d'un tiers des comptes et slots
	for i := uint64(1); i <= 20; i++ {
		a := evm256.FromU64(i)
		tr.SetAccount(&a, nil)
	}
	_ = tr.ComputeRoot()

	// Recroissance avec de nouveaux comptes
	for i := uint64(100); i <= 150; i++ {
		a := evm256.FromU64(i)
		tr.SetAccount(&a, &Account{Balance: evm256.FromU64(i * 5)})
		s := evm256.FromU64(i)
		v := evm256.FromU64(i * 20)
		tr.SetStorage(&a, &s, &v)
	}
	rootRecycled := tr.ComputeRoot()

	// Construction d'un trie frais avec l'état final identique
	fresh := NewStateTrie()
	for i := uint64(21); i <= 60; i++ {
		a := evm256.FromU64(i)
		fresh.SetAccount(&a, &Account{Balance: evm256.FromU64(i * 10)})
		s := evm256.FromU64(i)
		v := evm256.FromU64(i * 100)
		fresh.SetStorage(&a, &s, &v)
	}
	for i := uint64(100); i <= 150; i++ {
		a := evm256.FromU64(i)
		fresh.SetAccount(&a, &Account{Balance: evm256.FromU64(i * 5)})
		s := evm256.FromU64(i)
		v := evm256.FromU64(i * 20)
		fresh.SetStorage(&a, &s, &v)
	}
	rootFresh := fresh.ComputeRoot()

	if rootRecycled != rootFresh {
		t.Fatalf("racine après churn divergente: recyclée=%x fraîche=%x", rootRecycled, rootFresh)
	}
}

// 2. Traitement canonique des adresses de stockage orphelines (sans compte déclaré)
func TestStateTrieOrphanStorageParity(t *testing.T) {
	tr := NewStateTrie()
	// Compte normal
	a1 := evm256.FromU64(0x10)
	tr.SetAccount(&a1, &Account{Balance: evm256.FromU64(500)})
	s1 := evm256.FromU64(1)
	v1 := evm256.FromU64(99)
	tr.SetStorage(&a1, &s1, &v1)

	// Adresse orpheline (aucun SetAccount préalable)
	orphan := evm256.FromU64(0x9999)
	so := evm256.FromU64(7)
	vo := evm256.FromU64(777)
	tr.SetStorage(&orphan, &so, &vo)

	r1 := tr.ComputeRoot()

	// Même état sur trie frais
	fresh := NewStateTrie()
	fresh.SetAccount(&a1, &Account{Balance: evm256.FromU64(500)})
	fresh.SetStorage(&a1, &s1, &v1)
	fresh.SetStorage(&orphan, &so, &vo)
	r2 := fresh.ComputeRoot()

	if r1 != r2 {
		t.Fatalf("divergence sur stockage orphelin: r1=%x r2=%x", r1, r2)
	}
	if r1 == emptyRoot {
		t.Fatal("la racine d'un trie avec stockage orphelin ne doit pas être la racine vide")
	}
}

// 3. Déclenchement et intégrité de growBytes en cours de construction
func TestStateTrieGrowBytesDuringBuild(t *testing.T) {
	tr := NewStateTrie()
	// 200 comptes et 400 slots pour dépasser les allocations initiales de tampons
	for i := uint64(1); i <= 200; i++ {
		a := evm256.FromU64(i)
		tr.SetAccount(&a, &Account{Balance: evm256.FromU64(i * 1000), Nonce: i})
		for s := uint64(1); s <= 2; s++ {
			slot := evm256.FromU64(s)
			val := evm256.Uint256{i, s, i * s, 0x12345678}
			tr.SetStorage(&a, &slot, &val)
		}
	}
	r1 := tr.ComputeRoot()

	fresh := NewStateTrie()
	for i := uint64(1); i <= 200; i++ {
		a := evm256.FromU64(i)
		fresh.SetAccount(&a, &Account{Balance: evm256.FromU64(i * 1000), Nonce: i})
		for s := uint64(1); s <= 2; s++ {
			slot := evm256.FromU64(s)
			val := evm256.Uint256{i, s, i * s, 0x12345678}
			fresh.SetStorage(&a, &slot, &val)
		}
	}
	r2 := fresh.ComputeRoot()

	if r1 != r2 {
		t.Fatalf("divergence après growBytes: r1=%x r2=%x", r1, r2)
	}
}

// 4. Validation de la borne de nœuds sous haute densité (500 comptes + 500 slots)
func TestStateTrieNodeBoundHighDensity(t *testing.T) {
	tr := NewStateTrie()
	for i := uint64(1); i <= 500; i++ {
		a := evm256.FromU64(i)
		tr.SetAccount(&a, &Account{Balance: evm256.FromU64(i)})
		s := evm256.FromU64(i)
		v := evm256.FromU64(i * 3)
		tr.SetStorage(&a, &s, &v)
	}
	// Ne doit pas paniquer sur dépassement d'arène
	r := tr.ComputeRoot()
	if r == emptyRoot {
		t.Fatal("racine vide inattendue pour trie dense")
	}
}

// 5. Concurrence forcenée entre mutateurs et lecteurs (ComputeRoot et GenerateProof)
func TestStateTrieConcurrentMutationsAndComputeRoot(t *testing.T) {
	tr := NewStateTrie()
	for i := uint64(1); i <= 50; i++ {
		a := evm256.FromU64(i)
		tr.SetAccount(&a, &Account{Balance: evm256.FromU64(i * 100)})
		s := evm256.FromU64(i)
		v := evm256.FromU64(i)
		tr.SetStorage(&a, &s, &v)
	}

	stop := make(chan struct{})
	time.AfterFunc(100*time.Millisecond, func() { close(stop) })

	var wg sync.WaitGroup
	// 3 mutateurs concurrents
	for g := 0; g < 3; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			var counter uint64
			for {
				select {
				case <-stop:
					return
				default:
					counter++
					a := evm256.FromU64(uint64(gid*100) + (counter % 30))
					s := evm256.FromU64(counter % 10)
					v := evm256.FromU64(counter)
					tr.SetStorage(&a, &s, &v)
					tr.AddBalance(&a, &v)
				}
			}
		}(g)
	}

	// 3 lecteurs concurrents (ComputeRoot et GenerateProof)
	for g := 0; g < 3; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = tr.ComputeRoot()
					target := evm256.FromU64(uint64(gid*10 + 1))
					_, _ = tr.GenerateProof(target)
				}
			}
		}(g)
	}

	wg.Wait()
}

