package c2rpc

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2block"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2crypto"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/statetrie"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2seq"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
)

const rawLegacy = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe63288898e2f910f04bc51d1dba5a8b57b8a4ba6ac7a0122dacd536abc73bba1586e5b5c72fa07d959584d2d7fec1d1f55f8ba297996c"

func fund(st *statetrie.StateTrie, addr c2block.Address, v uint64) {
	a := addrToU256(addr)
	d := evm256.FromU64(v)
	st.AddBalance(&a, &d)
}

func putCode(st *statetrie.StateTrie, addr c2block.Address, code []byte) {
	a := addrToU256(addr)
	acc, ok := st.GetAccount(&a)
	if !ok {
		acc = &statetrie.Account{}
	}
	acc.Code = append([]byte(nil), code...)
	var h [32]byte
	c2crypto.Keccak256(code, &h)
	acc.CodeHash = h
	st.SetAccount(&a, acc)
}

func setNonce(st *statetrie.StateTrie, addr c2block.Address, n uint64) {
	a := addrToU256(addr)
	acc, ok := st.GetAccount(&a)
	if !ok {
		acc = &statetrie.Account{}
	}
	acc.Nonce = n
	st.SetAccount(&a, acc)
}

func mkTx(from c2block.Address, nonce, tip uint64, hash byte) *c2block.Transaction {
	to := c2block.Address{0xB2}
	price := evm256.FromU64(tip)
	var h c2block.Hash
	h[31] = hash
	h[0] = from[0]
	h[1] = byte(nonce)
	return &c2block.Transaction{
		Nonce:     nonce,
		GasPrice:  price,
		GasTipCap: price,
		GasFeeCap: price,
		Gas:       21000,
		To:        &to,
		From:      from,
		Hash:      h,
	}
}

func newAPI(st *statetrie.StateTrie) *EthAPI {
	return NewEthAPI(c2seq.NewSequencer(st))
}

func post(t *testing.T, url, body string) map[string]any {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("json %s: %v", b, err)
	}
	return m
}

func mustResult(t *testing.T, m map[string]any) any {
	t.Helper()
	if e, ok := m["error"]; ok && e != nil {
		t.Fatalf("erreur rpc: %v", e)
	}
	return m["result"]
}

func rpcJSON(method string, params any, id int) string {
	b, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      id,
	})
	return string(b)
}

func TestHexEthereum(t *testing.T) {
	if EncodeQuantity(0) != "0x0" {
		t.Fatalf("zéro=%s", EncodeQuantity(0))
	}
	if EncodeQuantity(255) != "0xff" {
		t.Fatalf("255=%s", EncodeQuantity(255))
	}
	if EncodeBytes(nil) != "0x" {
		t.Fatalf("data vide=%s", EncodeBytes(nil))
	}
	z := evm256.FromU64(0x0f)
	if EncodeUint256(z) != "0xf" {
		t.Fatalf("uint256=%s", EncodeUint256(z))
	}
	a := c2block.Address{0x11}
	s := EncodeAddress(a)
	got, err := DecodeAddress(s)
	if err != nil || got != a {
		t.Fatalf("adresse roundtrip %s %v", s, err)
	}
	n, err := DecodeQuantity("0xff")
	if err != nil || n != 255 {
		t.Fatalf("quantity %d %v", n, err)
	}
}

func TestHTTPEthQueries(t *testing.T) {
	st := statetrie.NewStateTrie()
	from := c2block.Address{0xA1}
	fund(st, from, 1_000_000)
	code := []byte{0x60, 0x00, 0x60, 0x00, 0xfd}
	caddr := c2block.Address{0xC0}
	putCode(st, caddr, code)
	api := newAPI(st)
	hs := httptest.NewServer(NewServer(api))
	defer hs.Close()

	m := post(t, hs.URL, rpcJSON("eth_chainId", []any{}, 1))
	if mustResult(t, m) != "0x1" {
		t.Fatalf("chainId=%v", m["result"])
	}
	m = post(t, hs.URL, rpcJSON("eth_blockNumber", []any{}, 2))
	if mustResult(t, m) != "0x0" {
		t.Fatalf("blockNumber=%v", m["result"])
	}
	m = post(t, hs.URL, rpcJSON("eth_getBalance", []any{EncodeAddress(from), "latest"}, 3))
	if mustResult(t, m) != EncodeQuantity(1_000_000) {
		t.Fatalf("balance=%v", m["result"])
	}
	m = post(t, hs.URL, rpcJSON("eth_getTransactionCount", []any{EncodeAddress(from), "latest"}, 4))
	if mustResult(t, m) != "0x0" {
		t.Fatalf("nonce=%v", m["result"])
	}
	m = post(t, hs.URL, rpcJSON("eth_getCode", []any{EncodeAddress(caddr), "latest"}, 5))
	if mustResult(t, m) != EncodeBytes(code) {
		t.Fatalf("code=%v", m["result"])
	}
	m = post(t, hs.URL, rpcJSON("eth_getStorageAt", []any{EncodeAddress(caddr), "0x1", "latest"}, 6))
	got := mustResult(t, m).(string)
	if got != EncodeBytes(make([]byte, 32)) {
		t.Fatalf("storage=%s", got)
	}
}

func TestSendRawAndReceipt(t *testing.T) {
	raw, err := DecodeBytes("0x" + rawLegacy)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := c2block.DecodeTransaction(raw)
	if err != nil {
		t.Fatal(err)
	}
	st := statetrie.NewStateTrie()
	fund(st, tx.From, 2_000_000_000_000_000_000)
	setNonce(st, tx.From, 9)
	api := newAPI(st)
	hs := httptest.NewServer(NewServer(api))
	defer hs.Close()

	m := post(t, hs.URL, rpcJSON("eth_sendRawTransaction", []any{"0x" + rawLegacy}, 1))
	hash := mustResult(t, m).(string)
	if hash != EncodeHash(tx.Hash) {
		t.Fatalf("hash=%s want=%s", hash, EncodeHash(tx.Hash))
	}
	if _, err := api.ProduceBlock(100); err != nil {
		t.Fatal(err)
	}
	m = post(t, hs.URL, rpcJSON("eth_getTransactionReceipt", []any{hash}, 2))
	rec, ok := mustResult(t, m).(map[string]any)
	if !ok {
		t.Fatalf("reçu=%v", m["result"])
	}
	if rec["status"] != "0x1" {
		t.Fatalf("status=%v", rec["status"])
	}
	m = post(t, hs.URL, rpcJSON("eth_blockNumber", []any{}, 3))
	if mustResult(t, m) != "0x1" {
		t.Fatalf("hauteur=%v", m["result"])
	}
	m = post(t, hs.URL, rpcJSON("eth_getBlockByNumber", []any{"0x1", false}, 4))
	blk := mustResult(t, m).(map[string]any)
	txs, _ := blk["transactions"].([]any)
	if len(txs) != 1 || txs[0] != hash {
		t.Fatalf("bloc txs=%v", txs)
	}
	m = post(t, hs.URL, rpcJSON("eth_getBalance", []any{"0x3535353535353535353535353535353535353535", "latest"}, 5))
	if mustResult(t, m) != "0xde0b6b3a7640000" {
		t.Fatalf("destinataire=%v", m["result"])
	}
}

func TestCallNoMutationAndEstimate(t *testing.T) {
	st := statetrie.NewStateTrie()
	from := c2block.Address{0xA1}
	store := c2block.Address{0x51}
	retc := c2block.Address{0x42}
	fund(st, from, 10_000_000)
	putCode(st, store, []byte{0x60, 0x01, 0x60, 0x01, 0x55, 0x00})
	putCode(st, retc, []byte{0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3})
	api := newAPI(st)
	hs := httptest.NewServer(NewServer(api))
	defer hs.Close()

	call := map[string]any{
		"from": EncodeAddress(from),
		"to":   EncodeAddress(store),
		"gas":  "0x186a0",
	}
	m := post(t, hs.URL, rpcJSON("eth_call", []any{call, "latest"}, 1))
	_ = mustResult(t, m)
	m = post(t, hs.URL, rpcJSON("eth_getStorageAt", []any{EncodeAddress(store), "0x1", "latest"}, 2))
	if mustResult(t, m) != EncodeBytes(make([]byte, 32)) {
		t.Fatalf("eth_call a persisté le stockage: %v", m["result"])
	}

	callRet := map[string]any{
		"from": EncodeAddress(from),
		"to":   EncodeAddress(retc),
		"gas":  "0x186a0",
	}
	m = post(t, hs.URL, rpcJSON("eth_call", []any{callRet, "latest"}, 3))
	out := mustResult(t, m).(string)
	want := make([]byte, 32)
	want[31] = 42
	if out != EncodeBytes(want) {
		t.Fatalf("retour eth_call=%s", out)
	}

	est := map[string]any{
		"from": EncodeAddress(from),
		"to":   EncodeAddress(c2block.Address{0xB2}),
		"gas":  "0x5208",
	}
	m = post(t, hs.URL, rpcJSON("eth_estimateGas", []any{est}, 4))
	if mustResult(t, m) != "0x5208" {
		t.Fatalf("estimateGas=%v", m["result"])
	}
}

func TestGetLogsAndBatch(t *testing.T) {
	st := statetrie.NewStateTrie()
	from := c2block.Address{0xA1}
	c := c2block.Address{0x10}
	fund(st, from, 10_000_000)
	putCode(st, c, []byte{
		0x7f, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0x60, 0x00, 0x60, 0x00, 0xa1, 0x00,
	})
	api := newAPI(st)
	tx := &c2block.Transaction{
		Nonce:    0,
		GasPrice: evm256.FromU64(1),
		Gas:      50_000,
		To:       &c,
		From:     from,
		Hash:     c2block.Hash{0x11},
	}
	if err := api.Seq.Mempool.AddTx(tx); err != nil {
		t.Fatal(err)
	}
	if _, err := api.ProduceBlock(7); err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(NewServer(api))
	defer hs.Close()

	flt := map[string]any{
		"fromBlock": "0x0",
		"toBlock":   "latest",
		"address":   EncodeAddress(c),
	}
	m := post(t, hs.URL, rpcJSON("eth_getLogs", []any{flt}, 1))
	logs, ok := mustResult(t, m).([]any)
	if !ok || len(logs) != 1 {
		t.Fatalf("logs=%v", m["result"])
	}
	lg := logs[0].(map[string]any)
	if lg["address"] != EncodeAddress(c) {
		t.Fatalf("adresse log=%v", lg["address"])
	}
	topics, _ := lg["topics"].([]any)
	if len(topics) != 1 {
		t.Fatalf("topics=%v", topics)
	}

	batch := `[
		{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1},
		{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":2},
		{"jsonrpc":"2.0","method":"nope","params":[],"id":3}
	]`
	resp, err := http.Post(hs.URL, "application/json", strings.NewReader(batch))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var arr []map[string]any
	if err := json.Unmarshal(b, &arr); err != nil {
		t.Fatalf("batch json %s: %v", b, err)
	}
	if len(arr) != 3 {
		t.Fatalf("n=%d", len(arr))
	}
	if arr[0]["result"] != "0x1" {
		t.Fatalf("batch chainId=%v", arr[0]["result"])
	}
	if arr[1]["result"] != "0x1" {
		t.Fatalf("batch blockNumber=%v", arr[1]["result"])
	}
	errObj, _ := arr[2]["error"].(map[string]any)
	if errObj == nil || errObj["code"].(float64) != CodeNoMethod {
		t.Fatalf("method not found: %v", arr[2]["error"])
	}
}

func TestP2PSyncAndBroadcast(t *testing.T) {
	from := c2block.Address{0xA1}
	stL := statetrie.NewStateTrie()
	stF := statetrie.NewStateTrie()
	fund(stL, from, 1_000_000_000)
	fund(stF, from, 1_000_000_000)
	lead := NewNode(newAPI(stL), true)
	fol := NewNode(newAPI(stF), false)
	if lead.API.GenesisHash() != fol.API.GenesisHash() {
		t.Fatal("genèse divergente")
	}
	tx := mkTx(from, 0, 1, 1)
	if err := lead.API.Seq.Mempool.AddTx(tx); err != nil {
		t.Fatal(err)
	}
	if _, err := lead.Mine(50); err != nil {
		t.Fatal(err)
	}
	AttachPair(lead, fol)
	fol.CatchUp()
	waitHeight(t, fol.API, 1)
	if fol.API.Height() != 1 {
		t.Fatalf("suiveur hauteur=%d", fol.API.Height())
	}
	var want, got evm256.Uint256
	tu := addrToU256(c2block.Address{0xB2})
	lead.API.Seq.State.GetBalance(&tu, &want)
	fol.API.Seq.State.GetBalance(&tu, &got)
	if !evm256.Eq(&want, &got) {
		t.Fatalf("soldes divergents leader=%v suiveur=%v", want, got)
	}

	tx2 := mkTx(from, 1, 1, 2)
	if err := lead.API.Seq.Mempool.AddTx(tx2); err != nil {
		t.Fatal(err)
	}
	if _, err := lead.Mine(51); err != nil {
		t.Fatal(err)
	}
	waitHeight(t, fol.API, 2)
	res, herr := lead.API.Handle("eth_getTransactionReceipt", mustRaw(t, []any{EncodeHash(tx2.Hash)}))
	if herr != nil {
		t.Fatal(herr)
	}
	if rec, _ := res.(map[string]any); rec == nil || rec["status"] != "0x1" {
		t.Fatalf("reçu leader=%v", res)
	}
	fr, fe := fol.API.Handle("eth_getTransactionReceipt", mustRaw(t, []any{EncodeHash(tx2.Hash)}))
	if fe != nil {
		t.Fatal(fe)
	}
	if rec, _ := fr.(map[string]any); rec == nil || rec["status"] != "0x1" {
		t.Fatalf("reçu suiveur=%v", fr)
	}
}

func mustRaw(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func waitHeight(t *testing.T, api *EthAPI, n uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if api.Height() >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("hauteur %d non atteinte: %d", n, api.Height())
}

func TestConcurrentRPC(t *testing.T) {
	st := statetrie.NewStateTrie()
	api := newAPI(st)
	hs := httptest.NewServer(NewServer(api))
	defer hs.Close()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Post(hs.URL, "application/json", bytes.NewReader([]byte(rpcJSON("eth_blockNumber", []any{}, 1))))
			if err != nil {
				t.Error(err)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}()
	}
	wg.Wait()
}

func TestParseAndInvalid(t *testing.T) {
	api := newAPI(statetrie.NewStateTrie())
	hs := httptest.NewServer(NewServer(api))
	defer hs.Close()
	m := post(t, hs.URL, `{not json`)
	if m["error"] == nil {
		t.Fatal("parse error attendu")
	}
	code := m["error"].(map[string]any)["code"].(float64)
	if int(code) != CodeParse {
		t.Fatalf("code=%v", code)
	}
}
