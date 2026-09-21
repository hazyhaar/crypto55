package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2evm"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/onestep"
)

func TestCommands(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"version"}, &out, io.Discard); err != nil || out.String() != version+"\n" {
		t.Fatalf("version: %q, %v", out.String(), err)
	}
	for _, args := range [][]string{{"unknown"}, {"node", "--chain-id=0"}, {"--block-time=0"}, {"node", "--block-time=-1s"}, {"node", "extra"}, {"bench", "extra"}, {"version", "--unknown"}, {"prover", "/nonexistent/crypto55-witness"}} {
		if err := run(context.Background(), args, io.Discard, io.Discard); err == nil {
			t.Errorf("accepted invalid args %v", args)
		}
	}
}

func TestProver(t *testing.T) {
	var pre c2evm.ExecutionFrame
	pre.Reset(100)
	post := pre
	c2evm.StepOne(&post, []byte{0x60, 0x02})
	witness, err := onestep.CaptureWitness(&pre, &post, 0x60)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "witness.json")
	for _, valid := range []bool{true, false} {
		if !valid {
			witness.PostStateRoot[0] ^= 1
		}
		data, err := json.Marshal(witness)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if err := runProver([]string{path}, io.Discard); (err == nil) != valid {
			t.Fatalf("valid=%t: %v", valid, err)
		}
	}
}

type startupWriter chan string

func (w startupWriter) Write(data []byte) (int, error) {
	w <- string(data)
	return len(data), nil
}

func TestNode(t *testing.T) {
	for _, mine := range []bool{false, true} {
		t.Run(fmt.Sprint(mine), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			started := make(startupWriter, 1)
			done := make(chan error, 1)
			go func() { done <- runNode(ctx, "127.0.0.1:0", 55055, 5*time.Millisecond, mine, started) }()
			var addr string
			select {
			case line := <-started:
				addr = strings.TrimSuffix(strings.Fields(line)[3], ";")
			case err := <-done:
				t.Fatalf("startup failed: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("startup timed out")
			}
			client := &http.Client{Timeout: time.Second}
			defer client.CloseIdleConnections()
			call := func(method string) string {
				t.Helper()
				response, err := client.Post("http://"+addr, "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"`+method+`","params":[]}`))
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				var result struct{ Result string }
				if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
					t.Fatal(err)
				}
				return result.Result
			}
			if got := call("eth_chainId"); got != "0xd70f" {
				t.Fatalf("chain ID: %s", got)
			}
			deadline := time.Now().Add(time.Second)
			for {
				height := call("eth_blockNumber")
				if !mine {
					if height != "0x0" {
						t.Fatalf("mining disabled: %s", height)
					}
					break
				}
				if height != "0x0" && height != "" {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("no block produced")
				}
				time.Sleep(5 * time.Millisecond)
			}
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(6 * time.Second):
				t.Fatal("shutdown timed out")
			}
		})
	}
}
