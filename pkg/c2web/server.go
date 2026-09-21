package c2web

import (
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2evm"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2rpc"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2seq"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/onestep"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/statetrie"
)

//go:embed static/*
var staticFS embed.FS

type Server struct {
	httpServer *http.Server
	seq        *c2seq.Sequencer
	ethAPI     *c2rpc.EthAPI
	rpcServer  *c2rpc.Server
	chainID    uint64
	mu         sync.RWMutex
}

type SimulateRequest struct {
	Opcode  string   `json:"opcode"`
	Stack   []string `json:"stack"`
	PC      uint32   `json:"pc"`
	Gas     uint64   `json:"gas"`
	MemData string   `json:"mem_data,omitempty"`
	Offset  uint32   `json:"mem_offset,omitempty"`
	Tamper  bool     `json:"tamper,omitempty"`
}

type SimulateResponse struct {
	Success         bool     `json:"success"`
	OpcodeHex       string   `json:"opcode_hex"`
	PCIn            uint32   `json:"pc_in"`
	PCOut           uint32   `json:"pc_out"`
	GasIn           uint64   `json:"gas_in"`
	GasOut          uint64   `json:"gas_out"`
	GasUsed         uint64   `json:"gas_used"`
	StackIn         []string `json:"stack_in"`
	StackOut        []string `json:"stack_out"`
	PreStateRoot    string   `json:"pre_state_root"`
	PostStateRoot   string   `json:"post_state_root"`
	WitnessABI      string   `json:"witness_abi"`
	DisputeVerified bool     `json:"dispute_verified"`
	Error           string   `json:"error,omitempty"`
}

func parseHexU256(s string) (evm256.Uint256, error) {
	s = strings.TrimPrefix(s, "0x")
	if s == "" {
		return evm256.Uint256{}, nil
	}
	if len(s)%2 != 0 {
		s = "0" + s
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return evm256.Uint256{}, err
	}
	if len(b) > 32 {
		return evm256.Uint256{}, errors.New("valeur dépasse 256 bits")
	}
	var be [32]byte
	copy(be[32-len(b):], b)
	return evm256.FromBytesBE(be[:]), nil
}

func formatHexU256(x evm256.Uint256) string {
	be := evm256.BytesBE(x)
	return "0x" + hex.EncodeToString(be[:])
}

func opcodeByName(name string) (byte, error) {
	name = strings.ToUpper(strings.TrimSpace(name))
	switch name {
	case "ADD":
		return 0x01, nil
	case "MUL":
		return 0x02, nil
	case "SUB":
		return 0x03, nil
	case "DIV":
		return 0x04, nil
	case "AND":
		return 0x16, nil
	case "OR":
		return 0x17, nil
	case "XOR":
		return 0x18, nil
	case "SHL":
		return 0x1b, nil
	case "SHR":
		return 0x1c, nil
	case "MLOAD":
		return 0x51, nil
	case "MSTORE":
		return 0x52, nil
	case "SLOAD":
		return 0x54, nil
	case "SSTORE":
		return 0x55, nil
	case "JUMP":
		return 0x56, nil
	case "JUMPI":
		return 0x57, nil
	case "PUSH0":
		return 0x5f, nil
	case "PUSH1":
		return 0x60, nil
	case "DUP1":
		return 0x80, nil
	case "DUP2":
		return 0x81, nil
	case "SWAP1":
		return 0x90, nil
	case "SWAP2":
		return 0x91, nil
	}
	if strings.HasPrefix(name, "0X") {
		v, err := strconv.ParseUint(name[2:], 16, 8)
		if err == nil {
			return byte(v), nil
		}
	}
	return 0, fmt.Errorf("opcode %s non reconnu", name)
}

func NewServer(addr string, chainID uint64) (*Server, error) {
	trie := statetrie.NewStateTrie()
	seq := c2seq.NewSequencer(trie)
	seq.Header.ChainID = evm256.FromU64(chainID)
	api := c2rpc.NewEthAPI(seq)
	rpcSrv := c2rpc.NewServer(api)

	s := &Server{
		seq:       seq,
		ethAPI:    api,
		rpcServer: rpcSrv,
		chainID:   chainID,
	}

	mux := http.NewServeMux()

	// 1. Static Web Frontend
	subFS, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, fmt.Errorf("sous-système statique: %w", err)
	}
	mux.Handle("/", http.FileServer(http.FS(subFS)))

	// 2. Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":   "ok",
			"version":  "crypto55 v1.0.0",
			"chain_id": chainID,
			"simd":     true,
			"cgo":      false,
			"time":     time.Now().UTC().Format(time.RFC3339),
		})
	})

	// 3. Simulation API
	mux.HandleFunc("/api/simulate", s.handleSimulate)

	// 4. Standard JSON-RPC Endpoint (supportant c2_simulate et eth_*)
	mux.HandleFunc("/rpc", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "méthode non autorisée", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "lecture du corps impossible", http.StatusBadRequest)
			return
		}

		var rpcHead struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal(body, &rpcHead); err == nil && rpcHead.Method == "c2_simulate" {
			var params []SimulateRequest
			var simReq SimulateRequest
			if err := json.Unmarshal(rpcHead.Params, &params); err == nil && len(params) > 0 {
				simReq = params[0]
			} else if err := json.Unmarshal(rpcHead.Params, &simReq); err != nil {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0",
					"id":      rpcHead.ID,
					"error": map[string]any{
						"code":    -32602,
						"message": "paramètres invalides: " + err.Error(),
					},
				})
				return
			}
			res, status := s.executeSimulate(simReq)
			w.Header().Set("Content-Type", "application/json")
			if status != http.StatusOK && !res.Success {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0",
					"id":      rpcHead.ID,
					"error": map[string]any{
						"code":    -32000,
						"message": res.Error,
					},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      rpcHead.ID,
				"result":  res,
			})
			return
		}

		resp := s.rpcServer.Dispatch(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(resp)
	})

	s.httpServer = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
	}

	return s, nil
}

func (s *Server) Start() error {
	return s.httpServer.ListenAndServe()
}

func (s *Server) Close() error {
	return s.httpServer.Close()
}

func (s *Server) Handler() http.Handler {
	return s.httpServer.Handler
}

func (s *Server) handleSimulate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(SimulateResponse{Success: false, Error: "POST requis"})
		return
	}

	var req SimulateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(SimulateResponse{Success: false, Error: "JSON invalide: " + err.Error()})
		return
	}

	res, status := s.executeSimulate(req)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(res)
}

func (s *Server) executeSimulate(req SimulateRequest) (SimulateResponse, int) {
	op, err := opcodeByName(req.Opcode)
	if err != nil {
		return SimulateResponse{Success: false, Error: err.Error()}, http.StatusBadRequest
	}

	parsedStack := make([]evm256.Uint256, len(req.Stack))
	for i, item := range req.Stack {
		val, err := parseHexU256(item)
		if err != nil {
			return SimulateResponse{Success: false, Error: "valeur de pile invalide: " + err.Error()}, http.StatusBadRequest
		}
		parsedStack[i] = val
	}

	// Contrôle d'arité minimale de pile
	switch op {
	case 0x01, 0x02, 0x03, 0x04, 0x16, 0x17, 0x18, 0x1b, 0x1c, 0x90, 0x91:
		if len(parsedStack) < 2 {
			return SimulateResponse{
				Success:   false,
				OpcodeHex: fmt.Sprintf("0x%02x", op),
				Error:     "pile insuffisante: 2 éléments requis",
			}, http.StatusBadRequest
		}
	case 0x80, 0x81:
		if len(parsedStack) < 1 {
			return SimulateResponse{
				Success:   false,
				OpcodeHex: fmt.Sprintf("0x%02x", op),
				Error:     "pile insuffisante: 1 élément requis",
			}, http.StatusBadRequest
		}
	case 0x60:
		if len(parsedStack) == 0 {
			parsedStack = []evm256.Uint256{{}}
		}
	}

	gas := req.Gas
	if gas == 0 {
		gas = 100_000
	}

	pre := new(c2evm.ExecutionFrame)
	pre.Reset(gas)
	pre.PC = req.PC

	switch op {
	case 0x1b, 0x1c: // SHL, SHR (EIP-145: req.Stack[0] = shift, req.Stack[1] = value)
		pre.Stack[0] = parsedStack[1] // value
		pre.Stack[1] = parsedStack[0] // shift
		pre.SP = 2
	case 0x80: // DUP1: dupliquer req.Stack[0] (sommet)
		if len(parsedStack) >= 2 {
			pre.Stack[0] = parsedStack[1]
			pre.Stack[1] = parsedStack[0]
			pre.SP = 2
		} else {
			pre.Stack[0] = parsedStack[0]
			pre.SP = 1
		}
	case 0x90: // SWAP1: req.Stack[0] sommet, req.Stack[1] sous-sommet
		pre.Stack[0] = parsedStack[1]
		pre.Stack[1] = parsedStack[0]
		pre.SP = 2
	case 0x60: // PUSH1: pile préexistante sous l'élément poussé
		pre.SP = 0
		if len(parsedStack) > 1 {
			for i := 1; i < len(parsedStack) && i < 1024; i++ {
				pre.Stack[len(parsedStack)-1-i] = parsedStack[i]
			}
			pre.SP = int32(len(parsedStack) - 1)
		}
	default: // ADD, MUL, SUB, DIV, AND, OR, XOR...
		for i := 0; i < len(parsedStack) && i < 1024; i++ {
			pre.Stack[i] = parsedStack[i]
		}
		pre.SP = int32(len(parsedStack))
	}

	post := new(c2evm.ExecutionFrame)
	*post = *pre

	// Construction du bytecode à exécuter
	code := make([]byte, int(req.PC)+34)
	code[req.PC] = op
	if op >= 0x60 && op <= 0x7f {
		n := int(op - 0x5f)
		if op == 0x60 && len(parsedStack) > 0 {
			code[int(req.PC)+1] = byte(parsedStack[0][0] & 0xff)
		} else {
			for j := 0; j < n; j++ {
				code[int(req.PC)+1+j] = byte(j + 1)
			}
		}
	}

	st := c2evm.StepOne(post, code)
	if st != c2evm.StatusRunning && st != c2evm.StatusSuccess {
		return SimulateResponse{
			Success:   false,
			OpcodeHex: fmt.Sprintf("0x%02x", op),
			Error:     fmt.Sprintf("exécution rejetée (statut=%v)", st),
		}, http.StatusBadRequest
	}

	witness, err := onestep.CaptureWitness(pre, post, op)
	if err != nil {
		return SimulateResponse{
			Success:   false,
			OpcodeHex: fmt.Sprintf("0x%02x", op),
			Error:     "capture du témoin impossible: " + err.Error(),
		}, http.StatusBadRequest
	}

	if req.Tamper {
		witness.PostStateRoot[0] ^= 0xff
	}

	witnessValid, _ := onestep.VerifyWitness(witness)
	disputeVerified := witnessValid
	if req.Tamper {
		disputeVerified = !witnessValid // Litige validé par rejet de la preuve falsifiée
	}
	abiBytes := onestep.EncodeWitnessABI(witness)

	stackInHex := make([]string, len(parsedStack))
	for i := 0; i < len(parsedStack); i++ {
		stackInHex[i] = formatHexU256(parsedStack[i])
	}

	stackOutHex := make([]string, post.SP)
	for i := int32(0); i < post.SP; i++ {
		// Sommet de pile post.Stack[post.SP - 1 - i] présenté en tête [0]
		stackOutHex[i] = formatHexU256(post.Stack[post.SP-1-i])
	}

	gasUsed := gas - post.Gas

	return SimulateResponse{
		Success:         true,
		OpcodeHex:       fmt.Sprintf("0x%02x", op),
		PCIn:            pre.PC,
		PCOut:           post.PC,
		GasIn:           gas,
		GasOut:          post.Gas,
		GasUsed:         gasUsed,
		StackIn:         stackInHex,
		StackOut:        stackOutHex,
		PreStateRoot:    "0x" + hex.EncodeToString(witness.PreStateRoot[:]),
		PostStateRoot:   "0x" + hex.EncodeToString(witness.PostStateRoot[:]),
		WitnessABI:      "0x7bce236b" + hex.EncodeToString(abiBytes),
		DisputeVerified: disputeVerified,
	}, http.StatusOK
}
