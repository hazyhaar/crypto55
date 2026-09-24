// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. See LICENSE and NOTICE.

package onestep

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"testing"
	"time"

	"path/filepath"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2evm"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/statetrie"
)

const selectorHex = "7bce236b"

func getAnvilBinary() string {
	if p, err := exec.LookPath("anvil"); err == nil {
		return p
	}
	if home, err := os.UserHomeDir(); err == nil {
		cand := filepath.Join(home, ".foundry", "bin", "anvil")
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	return "anvil"
}

func getArtifactPath() string {
	candidates := []string{
		"../../out/OneStepEVM.sol/OneStepEVM.json",
		"out/OneStepEVM.sol/OneStepEVM.json",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return candidates[0]
}

type syncWriter struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (w *syncWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error"`
}

var rpcHTTPClient = &http.Client{Timeout: 10 * time.Second}

func rpcCall(url, method string, params []any, out any) error {
	if params == nil {
		params = []any{}
	}
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: 1, Method: method, Params: params})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := rpcHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var rr rpcResponse
	if err := json.Unmarshal(raw, &rr); err != nil {
		return fmt.Errorf("réponse JSON-RPC illisible: %w", err)
	}
	if rr.Error != nil {
		return fmt.Errorf("rpc %s: [%d] %s", method, rr.Error.Code, rr.Error.Message)
	}
	if out != nil && len(rr.Result) > 0 {
		if err := json.Unmarshal(rr.Result, out); err != nil {
			return fmt.Errorf("rpc %s: résultat illisible: %w", method, err)
		}
	}
	return nil
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("port libre introuvable: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func startAnvil(t *testing.T) string {
	t.Helper()
	anvilBin := getAnvilBinary()
	if _, err := os.Stat(anvilBin); err != nil {
		t.Skipf("anvil binary not found (%s): differential test skipped", anvilBin)
	}
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	log := &syncWriter{}
	cmd := exec.CommandContext(ctx, anvilBin,
		"--host", "127.0.0.1",
		"--port", strconv.Itoa(port),
		"--silent",
	)
	cmd.Stdout = log
	cmd.Stderr = log
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("failed to start anvil: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	url := fmt.Sprintf("http://127.0.0.1:%d", port)
	deadline := time.Now().Add(15 * time.Second)
	for {
		var version string
		if err := rpcCall(url, "net_version", nil, &version); err == nil {
			return url
		}
		if time.Now().After(deadline) {
			t.Fatalf("anvil unavailable on %s:\n%s", url, log.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func loadDeployedBytecode(t *testing.T) string {
	t.Helper()
	artPath := getArtifactPath()
	raw, err := os.ReadFile(artPath)
	if err != nil {
		t.Skipf("compiled artifact not found (%s): differential test skipped", artPath)
	}
	var art struct {
		DeployedBytecode struct {
			Object string `json:"object"`
		} `json:"deployedBytecode"`
	}
	if err := json.Unmarshal(raw, &art); err != nil {
		t.Fatalf("unreadable artifact: %v", err)
	}
	obj := art.DeployedBytecode.Object
	if len(obj) < 2 || obj[:2] != "0x" {
		t.Fatalf("invalid deployed bytecode in %s", artPath)
	}
	return obj[2:]
}

func installContract(t *testing.T, url string, codeHex string) string {
	t.Helper()
	addr := "0x1000000000000000000000000000000000000001"
	if err := rpcCall(url, "anvil_setCode", []any{addr, "0x" + codeHex}, nil); err != nil {
		t.Fatalf("anvil_setCode: %v", err)
	}
	return addr
}

func callAnvilOneStep(t *testing.T, url, addr string, w *StepWitness) (bool, [32]byte, uint64) {
	t.Helper()
	payload := append(mustHex(t, selectorHex), EncodeWitnessABI(w)...)
	var resultHex string
	call := map[string]string{
		"to":   addr,
		"data": "0x" + hex.EncodeToString(payload),
	}
	if err := rpcCall(url, "eth_call", []any{call, "latest"}, &resultHex); err != nil {
		t.Fatalf("eth_call: %v", err)
	}
	if len(resultHex) < 2 || resultHex[:2] != "0x" {
		t.Fatalf("résultat eth_call invalide: %q", resultHex)
	}
	raw, err := hex.DecodeString(resultHex[2:])
	if err != nil {
		t.Fatalf("décodage résultat eth_call: %v", err)
	}
	if len(raw) < 96 {
		t.Fatalf("résultat eth_call trop court: %d octets", len(raw))
	}
	success := raw[31] == 1
	var root [32]byte
	copy(root[:], raw[32:64])
	gas := binary.BigEndian.Uint64(raw[88:96])
	return success, root, gas
}

func captureForOp(t *testing.T, code []byte, wantOp byte, db c2evm.StateAccessor) (*StepWitness, uint64) {
	t.Helper()
	f := new(c2evm.ExecutionFrame)
	f.StateDB = db
	f.Reset(1_000_000)
	for f.Status == c2evm.StatusRunning {
		if int(f.PC) >= len(code) {
			t.Fatalf("opcode cible %02x absent du code rejoué", wantOp)
		}
		op := code[f.PC]
		pre := cloneFrame(f)
		c2evm.StepOne(f, code)
		if op != wantOp {
			continue
		}
		post := cloneFrame(f)
		w, err := CaptureWitness(pre, post, op)
		if err != nil {
			t.Fatalf("capture op=%02x pc=%d: %v", op, pre.PC, err)
		}
		return w, post.Gas
	}
	t.Fatalf("opcode cible %02x absent du code rejoué", wantOp)
	return nil, 0
}

func assertDifferentialParity(t *testing.T, url, addr string, w *StepWitness, goPostGas uint64) {
	t.Helper()
	ok, err := VerifyWitness(w)
	if !ok || err != nil {
		t.Fatalf("vérification Go rejetée: ok=%v err=%v", ok, err)
	}
	success, root, gas := callAnvilOneStep(t, url, addr, w)
	if !success {
		t.Fatalf("anvil rejette un témoin valide (op=%02x pc=%d)", w.Opcode, w.PC)
	}
	if root != w.PostStateRoot {
		t.Fatalf("racine divergente: anvil=%x go=%x", root, w.PostStateRoot)
	}
	if gas != goPostGas {
		t.Fatalf("gaz restant divergent: anvil=%d go=%d", gas, goPostGas)
	}
}

func TestAnvilDifferentialOneStep(t *testing.T) {
	url := startAnvil(t)
	addr := installContract(t, url, loadDeployedBytecode(t))

	cases := []struct {
		name string
		code string
		op   byte
		db   c2evm.StateAccessor
	}{
		{"ADD", "6005600301", 0x01, nil},
		{"SUB", "6005600303", 0x03, nil},
		{"MUL", "6005600302", 0x02, nil},
		{"DIV", "600a600304", 0x04, nil},
		{"AND", "600f600316", 0x16, nil},
		{"OR", "6005600317", 0x17, nil},
		{"XOR", "600f600318", 0x18, nil},
		{"SHL", "600160011b", 0x1b, nil},
		{"SHR", "600860011c", 0x1c, nil},
		{"SLOAD", "602a600155600154", 0x54, &memState{}},
		{"SSTORE", "602a600155", 0x55, &memState{}},
		{"MSTORE", "602a5f52", 0x52, nil},
		{"MLOAD", "602a5f52600051", 0x51, nil},
		{"PUSH", "602a5b00", 0x60, nil},
		{"DUP", "600160028001", 0x80, nil},
		{"SWAP", "6001600290", 0x90, nil},
		{"JUMP", "600456005b602a00", 0x56, nil},
		{"JUMPI", "6001600657005b00", 0x57, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, postGas := captureForOp(t, mustHex(t, tc.code), tc.op, tc.db)
			assertDifferentialParity(t, url, addr, w, postGas)
		})
	}
}

func TestAnvilDifferentialRejectsTamperedWitness(t *testing.T) {
	url := startAnvil(t)
	addr := installContract(t, url, loadDeployedBytecode(t))

	w, _ := captureForOp(t, mustHex(t, "6005600301"), 0x01, nil)
	ok, err := VerifyWitness(w)
	if !ok || err != nil {
		t.Fatalf("témoin intact rejeté: ok=%v err=%v", ok, err)
	}

	t.Run("preStateRoot", func(t *testing.T) {
		bad := *w
		bad.PreStateRoot[0] ^= 1
		if ok, _ := VerifyWitness(&bad); ok {
			t.Fatal("Go doit rejeter preStateRoot falsifié")
		}
		if success, _, _ := callAnvilOneStep(t, url, addr, &bad); success {
			t.Fatal("anvil doit rejeter preStateRoot falsifié")
		}
	})

	t.Run("postStateRoot", func(t *testing.T) {
		bad := *w
		bad.PostStateRoot[0] ^= 1
		if ok, _ := VerifyWitness(&bad); ok {
			t.Fatal("Go doit rejeter postStateRoot falsifié")
		}
		if success, _, _ := callAnvilOneStep(t, url, addr, &bad); success {
			t.Fatal("anvil doit rejeter postStateRoot falsifié")
		}
	})
}

func TestAnvilDifferentialWithStorageProof(t *testing.T) {
	url := startAnvil(t)
	addr := installContract(t, url, loadDeployedBytecode(t))

	tr := statetrie.NewStateTrie()
	acct := evm256.FromU64(0x1000)
	slot := evm256.FromU64(7)
	val := evm256.FromU64(0x123456)
	tr.SetAccount(&acct, &statetrie.Account{})
	tr.SetStorage(&acct, &slot, &val)

	code := mustHex(t, "62123456600755600754")
	f := new(c2evm.ExecutionFrame)
	f.StateDB = tr
	f.Reset(1_000_000)

	var sloadWitness *StepWitness
	var sloadPostGas uint64
	for f.Status == c2evm.StatusRunning {
		if int(f.PC) >= len(code) {
			break
		}
		op := code[f.PC]
		pre := cloneFrame(f)
		c2evm.StepOne(f, code)
		post := cloneFrame(f)
		if op == 0x54 {
			w, err := CaptureWitnessWithStorage(pre, post, op, tr, acct)
			if err != nil {
				t.Fatalf("capture SLOAD: %v", err)
			}
			sloadWitness = w
			sloadPostGas = post.Gas
			break
		}
	}
	if sloadWitness == nil {
		t.Fatal("SLOAD non exécuté")
	}

	t.Run("validProofParity", func(t *testing.T) {
		assertDifferentialParity(t, url, addr, sloadWitness, sloadPostGas)
	})

	t.Run("tamperedProofRejected", func(t *testing.T) {
		bad := *sloadWitness
		bad.StorageProof = make([][]byte, len(sloadWitness.StorageProof))
		for i, n := range sloadWitness.StorageProof {
			bad.StorageProof[i] = append([]byte(nil), n...)
		}
		bad.StorageProof[0][len(bad.StorageProof[0])-1] ^= 1
		if ok, _ := VerifyWitness(&bad); ok {
			t.Fatal("Go doit rejeter la preuve falsifiée")
		}
		if success, _, _ := callAnvilOneStep(t, url, addr, &bad); success {
			t.Fatal("Anvil doit rejeter la preuve falsifiée")
		}
	})

	t.Run("tamperedStorageRootRejected", func(t *testing.T) {
		bad := *sloadWitness
		bad.StorageRoot[0] ^= 1
		bad.PreStateRoot = hashState(bad.PC, bad.Gas, bad.StackIn, bad.MemOffset, bad.MemData, bad.StorageRoot, bad.StorageKey, bad.StorageVal)
		bad.PostStateRoot = hashState(bad.PC+1, sloadPostGas, bad.StackOut, bad.MemOffset, bad.MemData, bad.StorageRoot, bad.StorageKey, bad.StorageVal)
		if ok, _ := VerifyWitness(&bad); ok {
			t.Fatal("Go doit rejeter la racine de stockage altérée")
		}
		if success, _, _ := callAnvilOneStep(t, url, addr, &bad); success {
			t.Fatal("Anvil doit rejeter la racine de stockage altérée")
		}
	})
}

func TestAnvilDifferentialMultiSlotStorageProof(t *testing.T) {
	url := startAnvil(t)
	addr := installContract(t, url, loadDeployedBytecode(t))

	tr := statetrie.NewStateTrie()
	acct := evm256.FromU64(0x2000)
	tr.SetAccount(&acct, &statetrie.Account{})

	for i := uint64(1); i <= 6; i++ {
		slot := evm256.FromU64(i)
		val := evm256.FromU64(i * 100)
		tr.SetStorage(&acct, &slot, &val)
	}

	targetSlot := evm256.FromU64(3)
	root, proof, err := tr.GenerateStorageProof(acct, targetSlot)
	if err != nil {
		t.Fatalf("génération preuve multi-slot: %v", err)
	}
	if len(proof) < 2 {
		t.Fatalf("preuve multi-niveaux attendue, obtenu %d nœud(s)", len(proof))
	}

	w := &StepWitness{
		PC:           0,
		Opcode:       0x54,
		Gas:          1000,
		StackIn:      [4]evm256.Uint256{targetSlot},
		StackOut:     [4]evm256.Uint256{evm256.FromU64(300)},
		StorageRoot:  root,
		StorageKey:   targetSlot,
		StorageVal:   evm256.FromU64(300),
		StorageProof: proof,
	}
	w.PreStateRoot = hashState(w.PC, w.Gas, w.StackIn, w.MemOffset, w.MemData, w.StorageRoot, w.StorageKey, w.StorageVal)
	w.PostStateRoot = hashState(w.PC+1, 200, w.StackOut, w.MemOffset, w.MemData, w.StorageRoot, w.StorageKey, w.StorageVal)

	ok, err := VerifyWitness(w)
	if !ok || err != nil {
		t.Fatalf("vérification Go du témoin multi-slot rejetée: ok=%v err=%v", ok, err)
	}

	success, outRoot, gas := callAnvilOneStep(t, url, addr, w)
	if !success {
		t.Fatalf("Anvil a rejeté la preuve MPT multi-nœuds (niveaux=%d)", len(proof))
	}
	if outRoot != w.PostStateRoot {
		t.Fatalf("racine post-état divergente: anvil=%x go=%x", outRoot, w.PostStateRoot)
	}
	if gas != 200 {
		t.Fatalf("gaz restant divergent: anvil=%d go=%d", gas, 200)
	}
}


