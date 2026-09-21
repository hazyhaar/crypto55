package statetrie

import (
	"encoding/hex"
	"testing"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2evm"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
)

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
