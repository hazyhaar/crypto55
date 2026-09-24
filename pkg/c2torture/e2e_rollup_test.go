// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. See LICENSE and NOTICE.

package c2torture

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2block"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2crypto"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2evm"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2rpc"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2seq"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/onestep"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/statetrie"
)

// The interpreter delegates address binding to its caller, just as vmEnv does.
type rollupStorage struct {
	state *statetrie.StateTrie
	addr  evm256.Uint256
}

func (s *rollupStorage) GetStorage(_, key, val *evm256.Uint256) {
	s.state.GetStorage(&s.addr, key, val)
}

func (s *rollupStorage) SetStorage(_, key, val *evm256.Uint256) {
	s.state.SetStorage(&s.addr, key, val)
}

func rollupRPC(ctx context.Context, client *http.Client, url, method string, params any, result any) error {
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %s", method, resp.Status)
	}
	var envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      int             `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&envelope); err != nil {
		return err
	}
	if envelope.JSONRPC != "2.0" || envelope.ID != 1 {
		return fmt.Errorf("%s: invalid response identity", method)
	}
	if len(envelope.Error) != 0 && string(envelope.Error) != "null" {
		return fmt.Errorf("%s: %s", method, envelope.Error)
	}
	return json.Unmarshal(envelope.Result, result)
}

func TestE2ERollup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	transport := &http.Transport{Proxy: nil}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	call := func(url, method string, params, result any) {
		t.Helper()
		if err := rollupRPC(ctx, client, url, method, params, result); err != nil {
			t.Fatal(err)
		}
	}

	// Sign a legacy test transaction with private key d=1 and nonce k=1.
	// These PUBLIC test constants must never be used to sign real funds.
	contract := c2block.Address{0x51}
	const initialBalance = uint64(10_000_000)
	const gasLimit = uint64(100_000)
	const value = uint64(7)
	encodeList := func(fields ...[]byte) []byte {
		var payload []byte
		for _, field := range fields {
			buf := make([]byte, len(field)+9)
			n := c2crypto.RlpEncodeBytes(field, buf)
			payload = append(payload, buf[:n]...)
		}
		var header [9]byte
		n := c2crypto.RlpEncodeListHeader(len(payload), header[:])
		return append(header[:n:n], payload...)
	}
	fields := [][]byte{nil, {1}, {0x01, 0x86, 0xa0}, contract[:], {byte(value)}, nil}
	unsigned := encodeList(fields...)
	var digest [32]byte
	c2crypto.Keccak256(unsigned, &digest)
	order, _ := new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	r, _ := new(big.Int).SetString("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16)
	s := new(big.Int).Add(new(big.Int).SetBytes(digest[:]), r)
	s.Mod(s, order)
	v := byte(27) // The generator's Y coordinate is even.
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(order), 1)) > 0 {
		s.Sub(order, s)
		v = 28
	}
	raw := encodeList(append(fields, []byte{v}, r.Bytes(), s.Bytes())...)
	tx, err := c2block.DecodeTransaction(raw)
	if err != nil {
		t.Fatal(err)
	}
	if c2rpc.EncodeAddress(tx.From) != "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf" || tx.Gas != gasLimit || tx.To == nil || *tx.To != contract {
		t.Fatalf("unexpected decoded transaction: %+v", tx)
	}
	// PUSH1 40; PUSH1 2; ADD; PUSH1 1; SSTORE; STOP.
	code := []byte{0x60, 40, 0x60, 2, 0x01, 0x60, 1, 0x55, 0x00}
	seed := func() *statetrie.StateTrie {
		st := statetrie.NewStateTrie()
		fund(st, tx.From, initialBalance)
		putCode(st, contract, code)
		return st
	}
	state := seed()
	preRoot := state.ComputeRoot()
	seq := c2seq.NewSequencer(state)
	seq.Header.Coinbase = c2block.Address{0xc0}
	api := c2rpc.NewEthAPI(seq)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: c2rpc.NewServer(api), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second}
	served := make(chan error, 1)
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
		select {
		case err := <-served:
			if err != nil && err != http.ErrServerClosed {
				t.Errorf("HTTP server: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("HTTP server did not stop")
		}
	})
	go func() { served <- server.Serve(listener) }()
	url := "http://" + listener.Addr().String()
	var hash string
	call(url, "eth_sendRawTransaction", []any{c2rpc.EncodeBytes(raw)}, &hash)
	if hash != c2rpc.EncodeHash(tx.Hash) {
		t.Fatalf("submitted hash=%s want=%s", hash, c2rpc.EncodeHash(tx.Hash))
	}
	block, err := api.ProduceBlock(100)
	if err != nil {
		t.Fatal(err)
	}
	if len(block.Txs) != 1 || len(block.Receipts) != 1 || !reflect.DeepEqual(block.Txs[0], tx) {
		t.Fatal("sealed block did not execute the submitted transaction exactly once")
	}
	var receipt map[string]any
	call(url, "eth_getTransactionReceipt", []any{hash}, &receipt)
	for key, want := range map[string]string{
		"status": "0x1", "transactionHash": hash, "transactionIndex": "0x0",
		"blockHash": c2rpc.EncodeHash(block.Hash), "blockNumber": "0x1",
		"from": c2rpc.EncodeAddress(tx.From), "to": c2rpc.EncodeAddress(contract),
		"gasUsed": c2rpc.EncodeQuantity(block.Receipts[0].GasUsed),
	} {
		if receipt[key] != want {
			t.Fatalf("receipt %s=%v want=%s", key, receipt[key], want)
		}
	}

	// Independent account mutations, not a second BlockProcessor oracle.
	used := block.Receipts[0].GasUsed
	if used < 21000 || used >= gasLimit {
		t.Fatalf("invalid gas used: %d", used)
	}
	wantState := seed()
	from := addrToU256(tx.From)
	account, _ := wantState.GetAccount(&from)
	account.Nonce = 1
	account.Balance = evm256.FromU64(initialBalance - value - used)
	wantState.SetAccount(&from, account)
	fund(wantState, contract, value)
	fund(wantState, seq.Header.Coinbase, used)
	addr := addrToU256(contract)
	key, answer := evm256.FromU64(1), evm256.FromU64(42)
	wantState.SetStorage(&addr, &key, &answer)
	for _, address := range []c2block.Address{tx.From, contract, seq.Header.Coinbase} {
		u := addrToU256(address)
		got, ok := state.GetAccount(&u)
		want, _ := wantState.GetAccount(&u)
		if !ok || !reflect.DeepEqual(got, want) {
			t.Fatalf("account %x: got=%+v want=%+v", address, got, want)
		}
	}
	if got := storageAt(state, contract, 1); got != answer {
		t.Fatalf("storage=%v want=%v", got, answer)
	}
	wantRoot := wantState.ComputeRoot()
	if wantRoot == preRoot || state.ComputeRoot() != wantRoot || block.Header.StateRoot != c2block.Hash(wantRoot) {
		t.Fatal("state root differs from exact expected mutations")
	}
	var rpcBlock map[string]any
	call(url, "eth_getBlockByNumber", []any{"0x1", false}, &rpcBlock)
	if rpcBlock["stateRoot"] != c2rpc.EncodeBytes(wantRoot[:]) || rpcBlock["hash"] != c2rpc.EncodeHash(block.Hash) || !reflect.DeepEqual(rpcBlock["transactions"], []any{hash}) {
		t.Fatalf("HTTP block identity/root mismatch: %v", rpcBlock)
	}

	// Pack uses stored (uncompressed) Brotli blocks. No size reduction is claimed.
	packed, err := seq.Poster.Pack(block.Txs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(packed, seq.LastBatch) {
		t.Fatal("posted batch differs from the real sealed block")
	}
	unpacked, err := seq.Poster.Unpack(packed)
	if err != nil || len(unpacked) != 1 {
		t.Fatalf("unpack: count=%d err=%v", len(unpacked), err)
	}
	// The batch format preserves execution fields and identity, not V/R/S.
	wantTx := *tx
	wantTx.V, wantTx.R, wantTx.S = evm256.Uint256{}, evm256.Uint256{}, evm256.Uint256{}
	if !reflect.DeepEqual(unpacked[0], &wantTx) {
		t.Fatalf("batch execution fields changed: got=%+v want=%+v", unpacked[0], &wantTx)
	}
	repacked, err := seq.Poster.Pack(unpacked)
	if err != nil || !bytes.Equal(repacked, packed) {
		t.Fatalf("batch bytes did not roundtrip: %v", err)
	}
	replay, err := NewBlockReplayer(seed()).Replay(BlockReplaySpec{
		Header: &block.Header, Transactions: unpacked,
		Expected: ExpectedTransitionResult{StateRoot: wantRoot, ReceiptsRoot: block.Header.ReceiptsRoot, GasUsed: used, Bloom: block.Header.Bloom},
	})
	if err != nil || !replay.OK {
		t.Fatalf("batch block replay: report=%+v err=%v", replay, err)
	}

	// This is an explicit replay, not a capture hook in the sequencer. The
	// same code has no host opcodes or calldata; bind its original address,
	// pre-storage and entry gas (empty calldata: intrinsic gas is 21000).
	replayState := seed()
	entryAccount, _ := replayState.GetAccount(&from)
	entryAccount.Nonce = tx.Nonce + 1
	entryAccount.Balance = evm256.FromU64(initialBalance - gasLimit - value)
	replayState.SetAccount(&from, entryAccount)
	fund(replayState, contract, value)
	frame := new(c2evm.ExecutionFrame)
	frame.StateDB = &rollupStorage{state: replayState, addr: addr}
	frame.Reset(tx.Gas - 21000)
	var witness *onestep.StepWitness
	var postGas uint64
	for steps := 0; steps < len(code) && frame.Status == c2evm.StatusRunning; steps++ {
		if int(frame.PC) >= len(code) {
			t.Fatal("replay ran past contract code")
		}
		op := code[frame.PC]
		pre := *frame
		c2evm.StepOne(frame, code)
		if op == 0x01 {
			witness, err = onestep.CaptureWitness(&pre, frame, op)
			if err != nil {
				t.Fatal(err)
			}
			postGas = frame.Gas
		}
	}
	if frame.Status != c2evm.StatusSuccess || storageAt(replayState, contract, 1) != answer || witness == nil {
		t.Fatal("original-context replay failed or did not capture ADD")
	}
	// La transaction n'effaçant aucun slot de stockage, aucun remboursement
	// de gaz n'est appliqué au-delà du gaz brut consommé.
	gross := tx.Gas - frame.Gas
	expectedUsed := gross
	if expectedUsed < 21000 {
		expectedUsed = 21000
	}
	if used != expectedUsed || witness.PC != 4 || witness.StackOut[0] != answer {
		t.Fatalf("witness replay does not match executed transaction gas/result: used=%d expected=%d", used, expectedUsed)
	}
	if ok, err := onestep.VerifyWitness(witness); err != nil || !ok {
		t.Fatalf("Go witness verification: ok=%v err=%v", ok, err)
	}
	tampered := *witness
	tampered.PostStateRoot[0] ^= 1
	if ok, _ := onestep.VerifyWitness(&tampered); ok {
		t.Fatal("Go verifier accepted a tampered post root")
	}

	t.Run("Solidity", func(t *testing.T) {
		anvil, err := exec.LookPath("anvil")
		if err != nil {
			if home, herr := os.UserHomeDir(); herr == nil {
				cand := filepath.Join(home, ".foundry", "bin", "anvil")
				if _, serr := os.Stat(cand); serr == nil {
					anvil = cand
					err = nil
				}
			}
		}
		if err != nil {
			t.Skip("anvil is not installed; all Go/HTTP/batch checks ran")
		}
		artifact, err := os.ReadFile("../../out/OneStepEVM.sol/OneStepEVM.json")
		if err != nil {
			t.Skipf("compiled artifact not found (%v): Solidity/Anvil test skipped, run forge build to generate", err)
		}
		var compiled struct {
			Bytecode struct {
				Object string `json:"object"`
			} `json:"bytecode"`
		}
		if err := json.Unmarshal(artifact, &compiled); err != nil {
			t.Fatal(err)
		}
		deployment, err := c2rpc.DecodeBytes(compiled.Bytecode.Object)
		if err != nil || len(deployment) == 0 {
			t.Fatalf("invalid deployment bytecode: %v", err)
		}
		// Reserve an ephemeral loopback port, then release it for anvil.
		reservation, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = reservation.Close() })
		port := reservation.Addr().(*net.TCPAddr).Port
		if err := reservation.Close(); err != nil {
			t.Fatal(err)
		}
		anvilCtx, stop := context.WithTimeout(ctx, 30*time.Second)
		t.Cleanup(stop)
		cmd := exec.CommandContext(anvilCtx, anvil, "--host", "127.0.0.1", "--port", fmt.Sprint(port), "--silent")
		cmd.WaitDelay = 2 * time.Second
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		t.Cleanup(func() {
			stop()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("anvil did not stop")
			}
		})
		endpoint := fmt.Sprintf("http://127.0.0.1:%d", port)
		var accounts []string
		deadline := time.Now().Add(5 * time.Second)
		for {
			err = rollupRPC(anvilCtx, client, endpoint, "eth_accounts", []any{}, &accounts)
			if err == nil && len(accounts) > 0 {
				break
			}
			if time.Now().After(deadline) || anvilCtx.Err() != nil {
				t.Fatalf("anvil readiness: %v", err)
			}
			time.Sleep(25 * time.Millisecond)
		}
		anvilCall := func(method string, params, result any) {
			t.Helper()
			if err := rollupRPC(anvilCtx, client, endpoint, method, params, result); err != nil {
				t.Fatal(err)
			}
		}
		var deploymentHash string
		anvilCall("eth_sendTransaction", []any{map[string]string{"from": accounts[0], "data": c2rpc.EncodeBytes(deployment), "gas": "0x989680"}}, &deploymentHash)
		var deployed struct {
			Status  string `json:"status"`
			Address string `json:"contractAddress"`
			Hash    string `json:"transactionHash"`
		}
		deadline = time.Now().Add(5 * time.Second)
		for {
			anvilCall("eth_getTransactionReceipt", []any{deploymentHash}, &deployed)
			if deployed.Hash != "" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("deployment receipt timed out")
			}
			time.Sleep(25 * time.Millisecond)
		}
		if deployed.Status != "0x1" || deployed.Address == "" || deployed.Hash != deploymentHash {
			t.Fatalf("deployment failed: %+v", deployed)
		}
		var output string
		anvilCall("eth_call", []any{map[string]string{"to": deployed.Address, "data": "0x7bce236b" + hex.EncodeToString(onestep.EncodeWitnessABI(witness)), "gas": "0x989680"}, "latest"}, &output)
		result, err := c2rpc.DecodeBytes(output)
		if err != nil || len(result) != 96 {
			t.Fatalf("invalid Solidity result: %s err=%v", output, err)
		}
		if evm256.FromBytesBE(result[:32]) != evm256.FromU64(1) || !bytes.Equal(result[32:64], witness.PostStateRoot[:]) || evm256.FromBytesBE(result[64:]) != evm256.FromU64(postGas) {
			t.Fatalf("Solidity success/root/gas differs from Go: %s", output)
		}
	})
}
