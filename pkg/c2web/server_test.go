// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. See LICENSE and NOTICE.

package c2web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestC2WebServerRoutes(t *testing.T) {
	srv, err := NewServer("127.0.0.1:0", 55555)
	if err != nil {
		t.Fatalf("échec NewServer: %v", err)
	}

	handler := srv.Handler()

	t.Run("Health", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/health", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("attendu 200 OK, obtenu %d", rec.Code)
		}
	})

	t.Run("Static Index", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("attendu 200 OK sur index, obtenu %d", rec.Code)
		}
	})

	t.Run("Simulate ADD", func(t *testing.T) {
		payload := SimulateRequest{
			Opcode: "ADD",
			Stack: []string{
				"0x000000000000000000000000000000000000000000000000000000000000002a",
				"0x0000000000000000000000000000000000000000000000000000000000000018",
			},
			Gas: 100000,
		}
		raw, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/simulate", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK on simulate, got %d: %s", rec.Code, rec.Body.String())
		}

		var res SimulateResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("failed to unmarshal JSON simulate: %v", err)
		}

		if !res.Success {
			t.Fatalf("expected successful simulation, got error: %s", res.Error)
		}

		if len(res.StackOut) == 0 {
			t.Fatal("empty output stack after ADD")
		}
		// 0x2a (42) + 0x18 (24) = 0x42 (66)
		expected := "0x0000000000000000000000000000000000000000000000000000000000000042"
		if res.StackOut[0] != expected {
			t.Errorf("invalid ADD result: expected %s, got %s", expected, res.StackOut[0])
		}
		if res.WitnessABI == "" {
			t.Error("empty OneStep witness ABI")
		}
	})

	t.Run("Simulate Tamper Dispute", func(t *testing.T) {
		payload := SimulateRequest{
			Opcode: "MUL",
			Stack: []string{
				"0x02",
				"0x05",
			},
			Gas:    100000,
			Tamper: true,
		}
		raw, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/simulate", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK on simulate with tampering, got %d", rec.Code)
		}

		var res SimulateResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("failed to unmarshal JSON: %v", err)
		}

		if !res.DisputeVerified {
			t.Error("expected DisputeVerified = true upon tampering")
		}
	})

	t.Run("Simulate SHL EIP-145", func(t *testing.T) {
		payload := SimulateRequest{
			Opcode: "SHL",
			Stack: []string{
				"0x000000000000000000000000000000000000000000000000000000000000002a", // shift = 42
				"0x0000000000000000000000000000000000000000000000000000000000000018", // val = 24
			},
			Gas: 100000,
		}
		raw, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/simulate", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK on simulate SHL, got %d: %s", rec.Code, rec.Body.String())
		}

		var res SimulateResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("failed to unmarshal JSON simulate SHL: %v", err)
		}
		if !res.Success {
			t.Fatalf("expected successful simulation: %s", res.Error)
		}
		// 0x18 << 42 = 0x600000000000
		expected := "0x0000000000000000000000000000000000000000000000000000600000000000"
		if res.StackOut[0] != expected {
			t.Errorf("invalid SHL result: expected %s, got %s", expected, res.StackOut[0])
		}
	})

	t.Run("Simulate DUP1 Order", func(t *testing.T) {
		payload := SimulateRequest{
			Opcode: "DUP1",
			Stack: []string{
				"0x000000000000000000000000000000000000000000000000000000000000002a", // [0] top
				"0x0000000000000000000000000000000000000000000000000000000000000018", // [1] second
			},
			Gas: 100000,
		}
		raw, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/simulate", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK on simulate DUP1, got %d: %s", rec.Code, rec.Body.String())
		}

		var res SimulateResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("failed to unmarshal JSON simulate DUP1: %v", err)
		}
		if !res.Success {
			t.Fatalf("expected successful simulation: %s", res.Error)
		}
		if len(res.StackOut) != 3 {
			t.Fatalf("expected stack size 3, got %d", len(res.StackOut))
		}
		// [0] = 0x2a (copy), [1] = 0x2a (original), [2] = 0x18
		s2a := "0x000000000000000000000000000000000000000000000000000000000000002a"
		s18 := "0x0000000000000000000000000000000000000000000000000000000000000018"
		if res.StackOut[0] != s2a || res.StackOut[1] != s2a || res.StackOut[2] != s18 {
			t.Errorf("invalid DUP1 stack: expected [%s, %s, %s], got %v", s2a, s2a, s18, res.StackOut)
		}
	})

	t.Run("Simulate Invalid Input Returns 400", func(t *testing.T) {
		payload := SimulateRequest{
			Opcode: "ADD",
			Stack:  []string{"0x2a"}, // insufficient stack depth (2 required)
			Gas:    100000,
		}
		raw, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/simulate", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request on insufficient stack, got %d", rec.Code)
		}
	})

	t.Run("JSON-RPC c2_simulate", func(t *testing.T) {
		rpcReq := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      42,
			"method":  "c2_simulate",
			"params": []interface{}{
				map[string]interface{}{
					"opcode": "ADD",
					"stack":  []string{"0x2a", "0x18"},
					"gas":    100000,
				},
			},
		}
		raw, _ := json.Marshal(rpcReq)
		req := httptest.NewRequest("POST", "/rpc", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK on rpc c2_simulate, got %d", rec.Code)
		}

		var rpcRes map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &rpcRes); err != nil {
			t.Fatalf("failed to unmarshal rpc c2_simulate: %v", err)
		}
		if rpcRes["result"] == nil {
			t.Errorf("rpc response missing result field: %s", rec.Body.String())
		}
	})

	t.Run("JSON-RPC eth_blockNumber", func(t *testing.T) {
		rpcReq := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "eth_blockNumber",
			"params":  []interface{}{},
		}
		raw, _ := json.Marshal(rpcReq)
		req := httptest.NewRequest("POST", "/rpc", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK on rpc, got %d", rec.Code)
		}

		var rpcRes map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &rpcRes); err != nil {
			t.Fatalf("failed to unmarshal rpc: %v", err)
		}
		if rpcRes["result"] == nil {
			t.Errorf("rpc response missing result field: %s", rec.Body.String())
		}
	})
}
