package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2crypto"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/statetrie"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2evm"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2rpc"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2seq"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2web"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/onestep"
)

const version = "crypto55 v1.0.0 (Go 1.27, CGO_ENABLED=0, SIMD: AVX-512/NEON enabled, 0-allocation core)"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	if err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, "crypto55:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out, errOut io.Writer) error {
	command := "node"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("crypto55 "+command, flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.Usage = func() {
		fmt.Fprintln(errOut, "Usage: crypto55 [node|web|prover|bench|version] [options]")
		if command == "prover" {
			fmt.Fprintln(errOut, "Usage: crypto55 prover [witness.json ...]")
		}
		fs.PrintDefaults()
	}
	switch command {
	case "web":
		addr := fs.String("addr", "0.0.0.0:8555", "Web HTTP listen address")
		chainID := fs.Uint64("chain-id", 55055, "Ethereum chain ID (nonzero)")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() != 0 || *chainID == 0 || *addr == "" {
			return errors.New("web: unexpected arguments or invalid addr or chain-id")
		}
		return runWeb(ctx, *addr, *chainID, out, errOut)
	case "node":
		addr := fs.String("rpc-addr", "127.0.0.1:8545", "HTTP/WS RPC listen address")
		chainID := fs.Uint64("chain-id", 55055, "Ethereum chain ID (nonzero)")
		blockTime := fs.Duration("block-time", 500*time.Millisecond, "Block production interval (positive)")
		mine := fs.Bool("mine", true, "Enable block production")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() != 0 || *chainID == 0 || *blockTime <= 0 || *addr == "" {
			return errors.New("node: unexpected arguments or invalid rpc-addr, chain-id or block-time")
		}
		return runNode(ctx, *addr, *chainID, *blockTime, *mine, errOut)
	case "prover", "bench", "version":
		if err := fs.Parse(args); err != nil {
			return err
		}
		if command == "prover" {
			return runProver(fs.Args(), out)
		}
		if fs.NArg() != 0 {
			return fmt.Errorf("%s: unexpected positional arguments", command)
		}
		if command == "bench" {
			return runBench(ctx, out)
		}
		_, err := fmt.Fprintln(out, version)
		return err
	default:
		return fmt.Errorf("unknown command %q; expected node, prover, bench or version", command)
	}
}

func runNode(ctx context.Context, addr string, chainID uint64, blockTime time.Duration, mine bool, out io.Writer) error {
	seq := c2seq.NewSequencer(statetrie.NewStateTrie())
	seq.Header.ChainID = evm256.FromU64(chainID)
	api := c2rpc.NewEthAPI(seq)
	srv := c2rpc.NewServer(api)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()
	// Shutdown does not close hijacked WebSocket connections.
	var connMu sync.Mutex
	connections := make(map[net.Conn]struct{})
	srv.HTTP = &http.Server{
		Handler: srv, ReadHeaderTimeout: 10 * time.Second,
		BaseContext: func(net.Listener) context.Context { return ctx },
		ConnState: func(conn net.Conn, state http.ConnState) {
			connMu.Lock()
			defer connMu.Unlock()
			if state == http.StateNew {
				connections[conn] = struct{}{}
			} else if state == http.StateClosed {
				delete(connections, conn)
			}
		},
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.HTTP.Serve(listener) }()
	fmt.Fprintf(out, "RPC listening on %s; chain-id=%d; mine=%t; state=in-memory\n", listener.Addr(), chainID, mine)
	var ticks <-chan time.Time
	if mine {
		ticker := time.NewTicker(blockTime)
		defer ticker.Stop()
		ticks = ticker.C
	}
	var runErr error
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case runErr = <-serveErr:
			break loop
		case tick := <-ticks:
			if ctx.Err() != nil {
				break loop
			}
			if _, runErr = api.ProduceBlock(uint64(tick.Unix())); runErr != nil {
				break loop
			}
		}
	}
	// Production is synchronous above: no sequencer goroutine survives this loop.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	shutdownErr := srv.HTTP.Shutdown(shutdownCtx)
	connMu.Lock()
	for conn := range connections {
		_ = conn.Close()
	}
	connMu.Unlock()
	if errors.Is(runErr, http.ErrServerClosed) {
		runErr = nil
	}
	return errors.Join(runErr, shutdownErr)
}

func runProver(paths []string, out io.Writer) error {
	fmt.Fprintln(out, "Usage: crypto55 prover [witness.json ...]")
	fmt.Fprintln(out, "Generation (Go API): post := *pre; c2evm.StepOne(&post, code); w, err := onestep.CaptureWitness(pre, &post, code[pre.PC])")
	fmt.Fprintln(out, "Serialization: json.NewEncoder(file).Encode(w); contract ABI: onestep.EncodeWitnessABI(w)")
	if len(paths) == 0 {
		fmt.Fprintln(out, "No witness file supplied; no proof was verified.")
		return nil
	}
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("witness %s: %w", path, err)
		}
		decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
		decoder.DisallowUnknownFields()
		var witness onestep.StepWitness
		err = decoder.Decode(&witness)
		if err == nil {
			var extra any
			if trailing := decoder.Decode(&extra); trailing != io.EOF {
				err = errors.New("expected exactly one JSON witness")
			}
		}
		closeErr := file.Close()
		if err = errors.Join(err, closeErr); err != nil {
			return fmt.Errorf("witness %s: %w", path, err)
		}
		valid, err := onestep.VerifyWitness(&witness)
		if err != nil || !valid {
			return fmt.Errorf("witness %s: verification failed (valid=%t): %v", path, valid, err)
		}
		fmt.Fprintf(out, "Verified witness: %s\n", path)
	}
	return nil
}

func runWeb(ctx context.Context, addr string, chainID uint64, out, errOut io.Writer) error {
	srv, err := c2web.NewServer(addr, chainID)
	if err != nil {
		return fmt.Errorf("c2web: %w", err)
	}
	fmt.Fprintf(out, "crypto55: web portal and simulator running on http://%s (chain_id=%d)\n", addr, chainID)
	errCh := make(chan error, 1)
	go func() {
		if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()
	select {
	case <-ctx.Done():
		_ = srv.Close()
		return nil
	case err := <-errCh:
		return err
	}
}

func runBench(ctx context.Context, out io.Writer) error {
	const iterations = 100_000
	code := []byte{0x60, 0x02, 0x60, 0x03, 0x01, 0x00} // PUSH1 2; PUSH1 3; ADD; STOP.
	var frame c2evm.ExecutionFrame
	start := time.Now()
	for i := 0; i < iterations; i++ {
		if i%1024 == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		frame.Reset(100)
		for step := 0; step < 4; step++ {
			c2evm.StepOne(&frame, code)
		}
		if frame.Status != c2evm.StatusSuccess || frame.SP != 1 || frame.Stack[0] != evm256.FromU64(5) {
			return errors.New("EVM benchmark result mismatch")
		}
	}
	elapsed := time.Since(start)
	fmt.Fprintf(out, "EVM: %d programs, 4 opcodes/program, %.0f ops/sec (includes frame reset and result validation)\n", iterations, float64(4*iterations)/elapsed.Seconds())
	var digest [32]byte
	start = time.Now()
	for i := 0; i < iterations; i++ {
		if i%1024 == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		c2crypto.Keccak256(digest[:], &digest)
	}
	elapsed = time.Since(start)
	fmt.Fprintf(out, "Keccak-256: %d hashes of 32 bytes, %.0f ops/sec; digest=%x\n", iterations, float64(iterations)/elapsed.Seconds(), digest)
	return nil
}
