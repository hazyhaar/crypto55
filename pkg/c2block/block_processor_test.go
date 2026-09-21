package c2block

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/statetrie"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fund(st *statetrie.StateTrie, addr Address, v uint64) {
	a := addrToU256(addr)
	d := evm256.FromU64(v)
	st.AddBalance(&a, &d)
}

func putCode(st *statetrie.StateTrie, addr Address, code []byte) {
	a := addrToU256(addr)
	acc, ok := st.GetAccount(&a)
	if !ok {
		acc = &statetrie.Account{}
	}
	acc.Code = append([]byte(nil), code...)
	h := keccak32(code)
	acc.CodeHash = h
	st.SetAccount(&a, acc)
}

func header() *BlockHeader {
	return &BlockHeader{
		Coinbase:  Address{0xC0},
		GasLimit:  30_000_000,
		Number:    1,
		Timestamp: 1,
	}
}

func sender() Address { return Address{0xA1} }

func TestValueTransfer(t *testing.T) {
	st := statetrie.NewStateTrie()
	from := sender()
	to := Address{0xB2}
	fund(st, from, 1_000_000)
	p := NewBlockProcessor(st)
	val := evm256.FromU64(1000)
	tx := &Transaction{
		Nonce:    0,
		GasPrice: evm256.FromU64(1),
		Gas:      21000,
		To:       &to,
		Value:    val,
		From:     from,
	}
	rec, err := p.ProcessTransaction(header(), tx)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != 1 {
		t.Fatalf("status=%d", rec.Status)
	}
	if rec.GasUsed != 21000 {
		t.Fatalf("gasUsed=%d", rec.GasUsed)
	}
	var got evm256.Uint256
	tu := addrToU256(to)
	st.GetBalance(&tu, &got)
	if !evm256.Eq(&got, &val) {
		t.Fatalf("destinataire=%v", got)
	}
}

func TestCreateAndCreate2(t *testing.T) {
	runtime := mustHex(t, "602a60005260206000f3")
	init := append(mustHex(t, "600a600c600039600a6000f3"), runtime...)
	st := statetrie.NewStateTrie()
	from := sender()
	fund(st, from, 10_000_000)
	p := NewBlockProcessor(st)
	h := header()
	rec, err := p.ProcessTransaction(h, &Transaction{
		Nonce: 0, GasPrice: evm256.FromU64(1), Gas: 500_000, Data: init, From: from,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != 1 {
		t.Fatalf("CREATE status=%d", rec.Status)
	}
	if rec.ContractAddress == (Address{}) {
		t.Fatal("adresse de contrat vide")
	}
	cu := addrToU256(rec.ContractAddress)
	acc, ok := st.GetAccount(&cu)
	if !ok || !bytes.Equal(acc.Code, runtime) {
		t.Fatalf("code déployé=%x", acc.Code)
	}

	creator := Address{0xD1}
	var salt Hash
	salt[31] = 7
	want2 := create2Address(creator, salt, keccak32(init))
	prefix := []byte{0x60, byte(len(init)), 0x60, 0x30, 0x60, 0x00, 0x39, 0x7f}
	prefix = append(prefix, salt[:]...)
	prefix = append(prefix, 0x60, byte(len(init)), 0x60, 0x00, 0x60, 0x00, 0xf5, 0x00)
	if len(prefix) != 0x30 {
		t.Fatalf("préfixe CREATE2=%d", len(prefix))
	}
	putCode(st, creator, append(prefix, init...))
	fund(st, creator, 1)
	rec2, err := p.ProcessTransaction(h, &Transaction{
		Nonce: p.nonceOf(from), GasPrice: evm256.FromU64(1), Gas: 800_000, To: &creator, From: from,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec2.Status != 1 {
		t.Fatalf("CREATE2 status=%d", rec2.Status)
	}
	w2 := addrToU256(want2)
	acc2, ok := st.GetAccount(&w2)
	if !ok || !bytes.Equal(acc2.Code, runtime) {
		t.Fatalf("CREATE2 code=%x want=%x", acc2.Code, want2)
	}
}

func TestNestedCallAndStaticCall(t *testing.T) {
	st := statetrie.NewStateTrie()
	from := sender()
	fund(st, from, 10_000_000)
	id := Address{0x04}
	caller := Address{0xCA}
	callCode := mustHex(t, "600160006001600060006004614000f160015500")
	putCode(st, caller, callCode)
	p := NewBlockProcessor(st)
	tx := &Transaction{
		Nonce:    0,
		GasPrice: evm256.FromU64(1),
		Gas:      200_000,
		To:       &caller,
		From:     from,
		Data:     []byte{0xab},
	}
	rec, err := p.ProcessTransaction(header(), tx)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != 1 {
		t.Fatalf("CALL status=%d", rec.Status)
	}
	var slot evm256.Uint256
	key := evm256.FromU64(1)
	au := addrToU256(caller)
	st.GetStorage(&au, &key, &slot)
	one := evm256.FromU64(1)
	if !evm256.Eq(&slot, &one) {
		t.Fatalf("résultat CALL=%v (precompile %x)", slot, id)
	}

	store := Address{0x51}
	putCode(st, store, mustHex(t, "600160015500"))
	scaller := Address{0x5C}
	putCode(st, scaller, mustHex(t, "6001600060006000730000000000000000000000000000000000000051614000fa60025500"))
	tx3 := &Transaction{
		Nonce:    p.nonceOf(from),
		GasPrice: evm256.FromU64(1),
		Gas:      200_000,
		To:       &scaller,
		From:     from,
	}
	rec3, err := p.ProcessTransaction(header(), tx3)
	if err != nil {
		t.Fatal(err)
	}
	if rec3.Status != 1 {
		t.Fatalf("STATICCALL status=%d", rec3.Status)
	}
	su := addrToU256(store)
	var stored evm256.Uint256
	st.GetStorage(&su, &key, &stored)
	if !evm256.IsZero(&stored) {
		t.Fatalf("STATICCALL a écrit le stockage: %v", stored)
	}
}

func TestRevertRollback(t *testing.T) {
	st := statetrie.NewStateTrie()
	from := sender()
	fund(st, from, 10_000_000)
	c := Address{0xEE}
	putCode(st, c, mustHex(t, "600160015560006000fd"))
	p := NewBlockProcessor(st)
	tx := &Transaction{
		Nonce:    0,
		GasPrice: evm256.FromU64(1),
		Gas:      100_000,
		To:       &c,
		From:     from,
	}
	rec, err := p.ProcessTransaction(header(), tx)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != 0 {
		t.Fatalf("REVERT doit échouer, status=%d", rec.Status)
	}
	var got evm256.Uint256
	key := evm256.FromU64(1)
	cu := addrToU256(c)
	st.GetStorage(&cu, &key, &got)
	if !evm256.IsZero(&got) {
		t.Fatalf("stockage après REVERT=%v", got)
	}
	if p.nonceOf(from) != 1 {
		t.Fatalf("nonce=%d", p.nonceOf(from))
	}
}

func TestPrecompiles(t *testing.T) {
	out, left, err := RunPrecompile(4, []byte("abc"), 1000)
	if err != nil || left == 0 || !bytes.Equal(out, []byte("abc")) {
		t.Fatalf("identity: out=%x err=%v left=%d", out, err, left)
	}
	sum := sha256.Sum256([]byte("abc"))
	out, _, err = RunPrecompile(2, []byte("abc"), 10_000)
	if err != nil || !bytes.Equal(out, sum[:]) {
		t.Fatalf("sha256: %x err=%v", out, err)
	}
	out, _, err = RunPrecompile(3, []byte("abc"), 10_000)
	if err != nil || len(out) != 32 {
		t.Fatalf("ripemd160: %x err=%v", out, err)
	}
	modin := make([]byte, 96+1+1+1)
	modin[31] = 1
	modin[63] = 1
	modin[95] = 1
	modin[96] = 2
	modin[97] = 3
	modin[98] = 5
	out, _, err = RunPrecompile(5, modin, 100_000)
	if err != nil || len(out) != 1 || out[0] != 3 {
		t.Fatalf("modexp 2^3 mod 5 = %x err=%v", out, err)
	}
	out, _, err = RunPrecompile(8, nil, 50_000)
	if err != nil || len(out) != 32 || out[31] != 1 {
		t.Fatalf("pairing vide: %x err=%v", out, err)
	}
	_, _, err = RunPrecompile(10, []byte{1, 2, 3}, 60_000)
	if err == nil {
		t.Fatal("kzg entrée courte doit échouer")
	}
	g := make([]byte, 128)
	g[31] = 1
	g[63] = 2
	out, _, err = RunPrecompile(6, g, 1000)
	if err != nil || len(out) != 64 {
		t.Fatalf("ecAdd: err=%v outlen=%d", err, len(out))
	}
	min := make([]byte, 96)
	copy(min[0:64], g[0:64])
	min[95] = 1
	out, _, err = RunPrecompile(7, min, 10_000)
	if err != nil || !bytes.Equal(out, g[0:64]) {
		t.Fatalf("ecMul *1: %x err=%v", out, err)
	}

	st := statetrie.NewStateTrie()
	from := sender()
	fund(st, from, 1_000_000)
	to := Address{0x04}
	p := NewBlockProcessor(st)
	tx := &Transaction{
		Nonce:    0,
		GasPrice: evm256.FromU64(1),
		Gas:      50_000,
		To:       &to,
		Data:     []byte("hello"),
		From:     from,
	}
	rec, err := p.ProcessTransaction(header(), tx)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != 1 {
		t.Fatalf("tx precompile status=%d", rec.Status)
	}
}

func TestReceiptsRootAndBloom(t *testing.T) {
	st := statetrie.NewStateTrie()
	from := sender()
	fund(st, from, 10_000_000)
	c := Address{0x10}
	putCode(st, c, mustHex(t, "7f0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef60006000a100"))
	p := NewBlockProcessor(st)
	h := header()
	tx := &Transaction{
		Nonce:    0,
		GasPrice: evm256.FromU64(1),
		Gas:      50_000,
		To:       &c,
		From:     from,
	}
	res, err := p.ProcessBlock(h, []*Transaction{tx})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Receipts) != 1 || res.Receipts[0].Status != 1 {
		t.Fatalf("receipts=%d status=%d", len(res.Receipts), res.Receipts[0].Status)
	}
	if len(res.Receipts[0].Logs) != 1 {
		t.Fatalf("logs=%d", len(res.Receipts[0].Logs))
	}
	empty := receiptsRoot(nil)
	if res.ReceiptsRoot == empty {
		t.Fatal("ReceiptsRoot ne doit pas être la racine vide")
	}
	var zeroBloom [256]byte
	if res.Bloom == zeroBloom || res.Receipts[0].Bloom == zeroBloom {
		t.Fatal("Bloom 2048 bits attendu non nul")
	}
	if h.ReceiptsRoot != res.ReceiptsRoot {
		t.Fatal("en-tête ReceiptsRoot non mis à jour")
	}
}

func TestDecodeTransactionInvalid(t *testing.T) {
	if _, err := DecodeTransaction(nil); err == nil {
		t.Fatal("nil")
	}
	if _, err := DecodeTransaction([]byte{0xff}); err == nil {
		t.Fatal("type inconnu")
	}
	if _, err := DecodeTransaction([]byte{0xc0}); err == nil {
		t.Fatal("liste vide")
	}
}

func TestDecodeTransactionLegacy(t *testing.T) {
	raw := mustHex(t, "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe63288898e2f910f04bc51d1dba5a8b57b8a4ba6ac7a0122dacd536abc73bba1586e5b5c72fa07d959584d2d7fec1d1f55f8ba297996c")
	tx, err := DecodeTransaction(raw)
	if err != nil {
		t.Fatalf("décodage: %v", err)
	}
	if tx.Type != TxLegacy || tx.Nonce != 9 || tx.Gas != 21000 {
		t.Fatalf("champs type=%d nonce=%d gas=%d", tx.Type, tx.Nonce, tx.Gas)
	}
	if tx.To == nil || tx.To[0] != 0x35 {
		t.Fatalf("to=%v", tx.To)
	}
	if tx.From == (Address{}) {
		t.Fatal("émetteur non recouvré")
	}
}

func TestBlake2F(t *testing.T) {
	in := make([]byte, 213)
	in[3] = 12
	iv := []byte{
		0x08, 0xc9, 0xbc, 0xf3, 0x67, 0xe6, 0x09, 0x6a, 0x3b, 0xa7, 0xca, 0x84, 0x85, 0xae, 0x67, 0xbb,
		0x2b, 0xf8, 0x94, 0xfe, 0x72, 0xf3, 0x6e, 0x3c, 0xf1, 0x36, 0x1d, 0x5f, 0x3a, 0xf5, 0x4f, 0xa5,
		0xd1, 0x82, 0xe6, 0xad, 0x7f, 0x52, 0x0e, 0x51, 0x1f, 0x6c, 0x3e, 0x2b, 0x8c, 0x68, 0x05, 0x9b,
		0x6b, 0xbd, 0x41, 0xfb, 0xab, 0xd9, 0x83, 0x1f, 0x79, 0x21, 0x7e, 0x13, 0x19, 0xcd, 0xe0, 0x5b,
	}
	copy(in[4:], iv)
	in[212] = 1
	out, _, err := RunPrecompile(9, in, 100)
	if err != nil || len(out) != 64 {
		t.Fatalf("blake2f err=%v len=%d", err, len(out))
	}
}

func TestEcrecoverPrecompile(t *testing.T) {
	in := make([]byte, 128)
	copy(in[0:32], mustHex(t, "456e9aea5e197a1f1af7a3e85a4931b6f6f3571c08c959be869f657baacf7853"))
	in[63] = 28
	copy(in[64:96], mustHex(t, "09242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038823c0"))
	copy(in[96:128], mustHex(t, "4c069c1a18b58ad15ea182ddf605d12cd12a6209d3221c04ff8ebdd77aebc8cd"))
	out, _, err := RunPrecompile(1, in, 4000)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 32 {
		t.Fatalf("len=%d", len(out))
	}
}
