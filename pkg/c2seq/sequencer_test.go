package c2seq

import (
	"bytes"
	"sync"
	"testing"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2block"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2crypto"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/statetrie"
)

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

func fund(st *statetrie.StateTrie, addr c2block.Address, v uint64) {
	a := addrToU256(addr)
	d := evm256.FromU64(v)
	st.AddBalance(&a, &d)
}

func TestMempoolNonceThenTip(t *testing.T) {
	mp := NewMempool()
	a := c2block.Address{0xA1}
	b := c2block.Address{0xA2}
	if err := mp.AddTx(mkTx(a, 1, 100, 2)); err != nil {
		t.Fatal(err)
	}
	if err := mp.AddTx(mkTx(a, 0, 1, 1)); err != nil {
		t.Fatal(err)
	}
	if err := mp.AddTx(mkTx(b, 0, 50, 3)); err != nil {
		t.Fatal(err)
	}
	if mp.Count() != 3 {
		t.Fatalf("count=%d", mp.Count())
	}
	batch := mp.PopBatch(1_000_000, 3)
	if len(batch) != 3 {
		t.Fatalf("lot=%d", len(batch))
	}
	if batch[0].From != b || batch[0].Nonce != 0 {
		t.Fatalf("nonce 0 de B (tip 50) d'abord, obtenu from=%x nonce=%d", batch[0].From, batch[0].Nonce)
	}
	if batch[1].From != a || batch[1].Nonce != 0 {
		t.Fatalf("nonce 0 de A ensuite, obtenu from=%x nonce=%d", batch[1].From, batch[1].Nonce)
	}
	if batch[2].From != a || batch[2].Nonce != 1 {
		t.Fatalf("nonce 1 de A en dernier, obtenu from=%x nonce=%d", batch[2].From, batch[2].Nonce)
	}
	if mp.Count() != 0 {
		t.Fatalf("mempool non vide: %d", mp.Count())
	}
}

func TestMempoolReplaceByFeeAndRemove(t *testing.T) {
	mp := NewMempool()
	a := c2block.Address{0xA1}
	low := mkTx(a, 0, 1, 1)
	if err := mp.AddTx(low); err != nil {
		t.Fatal(err)
	}
	if err := mp.AddTx(mkTx(a, 0, 1, 9)); err != ErrUnderpriced {
		t.Fatalf("remplacement sous-payé: %v", err)
	}
	high := mkTx(a, 0, 10, 2)
	if err := mp.AddTx(high); err != nil {
		t.Fatal(err)
	}
	if mp.Count() != 1 {
		t.Fatalf("count après remplacement=%d", mp.Count())
	}
	mp.RemoveTx(high.Hash)
	if mp.Count() != 0 {
		t.Fatalf("count après retrait=%d", mp.Count())
	}
}

func TestMempoolPopBatchGasCap(t *testing.T) {
	mp := NewMempool()
	a := c2block.Address{0xA1}
	if err := mp.AddTx(mkTx(a, 0, 1, 1)); err != nil {
		t.Fatal(err)
	}
	if err := mp.AddTx(mkTx(a, 1, 1, 2)); err != nil {
		t.Fatal(err)
	}
	batch := mp.PopBatch(21000, 10)
	if len(batch) != 1 || batch[0].Nonce != 0 {
		t.Fatalf("plafond gaz: lot=%d", len(batch))
	}
	if mp.Count() != 1 {
		t.Fatalf("reste=%d", mp.Count())
	}
	empty := mp.PopBatch(20999, 10)
	if len(empty) != 0 {
		t.Fatalf("tx trop chère en gaz extraite: %d", len(empty))
	}
}

func TestMempoolConcurrent(t *testing.T) {
	mp := NewMempool()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			from := c2block.Address{byte(i + 1)}
			_ = mp.AddTx(mkTx(from, 0, uint64(i+1), byte(i+1)))
			_ = mp.PopBatch(21000, 1)
		}(i)
	}
	wg.Wait()
}

func TestTimeboostBoundedWindow(t *testing.T) {
	tb := NewTimeboost(10)
	tx := mkTx(c2block.Address{0xE1}, 0, 1, 1)
	if err := tb.PushExpress(tx, 100); err != nil {
		t.Fatal(err)
	}
	got := tb.Drain(105)
	if len(got) != 1 || got[0].Hash != tx.Hash {
		t.Fatalf("file expresse dans la fenêtre: %d", len(got))
	}
	tx2 := mkTx(c2block.Address{0xE2}, 0, 1, 2)
	if err := tb.PushExpress(tx2, 200); err != nil {
		t.Fatal(err)
	}
	late := tb.Drain(211)
	if len(late) != 0 {
		t.Fatalf("fenêtre échue doit vider sans privilège: %d", len(late))
	}
	if tb.Count() != 0 {
		t.Fatalf("résidu express=%d", tb.Count())
	}
}

func TestRetryableAutoAndManualRedeem(t *testing.T) {
	eng := NewRetryableEngine()
	to := c2block.Address{0xB2}
	from := c2block.Address{0xA1}
	p := RetryableParams{
		From:             from,
		To:               &to,
		CallValue:        evm256.FromU64(10),
		Deposit:          evm256.FromU64(1_000_000),
		MaxSubmissionFee: evm256.FromU64(1_000_000),
		GasLimit:         50_000,
		MaxFeePerGas:     evm256.FromU64(1),
		Data:             []byte{0x01, 0x02},
		L1BaseFee:        evm256.FromU64(1),
		GasProvided:      100_000,
	}
	ticket, tx, err := eng.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if ticket == nil || tx == nil {
		t.Fatal("auto-redeem attendu")
	}
	if ticket.Status != RetryableAutoRedeemed {
		t.Fatalf("statut=%d", ticket.Status)
	}
	if _, err := eng.ManualRedeem(ticket.ID, 50_000, evm256.FromU64(1)); err != ErrTicketState {
		t.Fatalf("double redeem: %v", err)
	}

	p.GasProvided = 1400 + 6*2
	p.Data = []byte{0x03}
	p.GasProvided = 1400 + 6
	ticket2, tx2, err := eng.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if tx2 != nil || ticket2.Status != RetryableCreated {
		t.Fatalf("sans gaz restant le ticket reste créé: tx=%v statut=%d", tx2, ticket2.Status)
	}
	redeemed, err := eng.ManualRedeem(ticket2.ID, 30_000, evm256.FromU64(2))
	if err != nil {
		t.Fatal(err)
	}
	if redeemed == nil || redeemed.Gas != 30_000 {
		t.Fatalf("manual redeem incomplet")
	}
	got, ok := eng.Get(ticket2.ID)
	if !ok || got.Status != RetryableManualRedeemed {
		t.Fatalf("statut manuel=%v", got)
	}
}

func TestRetryableGasUnderflowSECARB10(t *testing.T) {
	if _, err := SafeSubGas(1, 2); err != ErrGasUnderflow {
		t.Fatalf("sous-débordement uint64: %v", err)
	}
	if _, err := SafeSubGas(0, 1); err != ErrGasUnderflow {
		t.Fatalf("zéro moins un: %v", err)
	}
	d, err := SafeSubGas(10, 3)
	if err != nil || d != 7 {
		t.Fatalf("soustraction nominale: %d %v", d, err)
	}
	eng := NewRetryableEngine()
	to := c2block.Address{0xB2}
	p := RetryableParams{
		From:             c2block.Address{0xA1},
		To:               &to,
		Deposit:          evm256.FromU64(1_000_000),
		MaxSubmissionFee: evm256.FromU64(1_000_000),
		GasLimit:         50_000,
		MaxFeePerGas:     evm256.FromU64(1),
		Data:             bytes.Repeat([]byte{0xaa}, 100),
		L1BaseFee:        evm256.FromU64(1),
		GasProvided:      1,
	}
	_, _, err = eng.Create(p)
	if err != ErrGasUnderflow {
		t.Fatalf("SEC-ARB-10: gaz fourni < coût de soumission, err=%v", err)
	}
	p.GasProvided = 1400 + 6*100 - 1
	_, _, err = eng.Create(p)
	if err != ErrGasUnderflow {
		t.Fatalf("SEC-ARB-10: un gaz de moins que le coût, err=%v", err)
	}
}

func TestRetryableGasOverflowSECARB11(t *testing.T) {
	if _, err := SafeAddGas(^uint64(0), 1); err != ErrGasOverflow {
		t.Fatalf("addition saturante: %v", err)
	}
	if _, err := SafeMulGas(^uint64(0), 2); err != ErrGasOverflow {
		t.Fatalf("multiplication saturante: %v", err)
	}
	sum, err := SafeAddGas(3, 4)
	if err != nil || sum != 7 {
		t.Fatalf("addition nominale: %d %v", sum, err)
	}
	prod, err := SafeMulGas(6, 7)
	if err != nil || prod != 42 {
		t.Fatalf("multiplication nominale: %d %v", prod, err)
	}
	huge := evm256.Uint256{0, 0, 0, 1 << 63}
	if _, err := mulU256U64Checked(huge, 2); err != ErrGasOverflow {
		t.Fatalf("256-bit * 2 débordement: %v", err)
	}
	max256 := evm256.Uint256{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}
	eng := NewRetryableEngine()
	to := c2block.Address{0xB2}
	p := RetryableParams{
		From:             c2block.Address{0xA1},
		To:               &to,
		Deposit:          max256,
		MaxSubmissionFee: max256,
		GasLimit:         2,
		MaxFeePerGas:     huge,
		L1BaseFee:        evm256.FromU64(1),
		GasProvided:      100_000,
	}
	_, _, err = eng.Create(p)
	if err != ErrGasOverflow {
		t.Fatalf("SEC-ARB-11: gasLimit * maxFee débordement, err=%v", err)
	}
	p.GasLimit = 1
	p.MaxFeePerGas = evm256.FromU64(1)
	p.L1BaseFee = huge
	p.Data = bytes.Repeat([]byte{1}, 8)
	_, _, err = eng.Create(p)
	if err != ErrGasOverflow {
		t.Fatalf("SEC-ARB-11: l1BaseFee * submissionGas, err=%v", err)
	}
	if _, err := eng.ManualRedeem([32]byte{0xff}, 2, huge); err != ErrGasOverflow {
		t.Fatalf("manual redeem overflow: %v", err)
	}
}

func TestProduceBlockAndCompressedBatch(t *testing.T) {
	st := statetrie.NewStateTrie()
	from := c2block.Address{0xA1}
	fund(st, from, 1_000_000_000)
	seq := NewSequencer(st)
	tx0 := mkTx(from, 0, 1, 1)
	tx1 := mkTx(from, 1, 2, 2)
	if err := seq.Mempool.AddTx(tx1); err != nil {
		t.Fatal(err)
	}
	if err := seq.Mempool.AddTx(tx0); err != nil {
		t.Fatal(err)
	}
	res, err := seq.ProduceBlock(42)
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || len(res.Receipts) != 2 {
		t.Fatalf("reçus=%v", res)
	}
	if res.Receipts[0].Status != 1 || res.Receipts[1].Status != 1 {
		t.Fatalf("statut reçu 0=%d 1=%d", res.Receipts[0].Status, res.Receipts[1].Status)
	}
	if seq.Header.Timestamp != 42 || seq.Header.Number != 1 {
		t.Fatalf("en-tête ts=%d n=%d", seq.Header.Timestamp, seq.Header.Number)
	}
	if len(seq.LastBatch) == 0 {
		t.Fatal("lot compressé vide")
	}
	got, err := seq.Poster.Unpack(seq.LastBatch)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("unpack=%d", len(got))
	}
	if got[0].Hash != tx0.Hash || got[1].Hash != tx1.Hash {
		t.Fatalf("ordre lot hash0=%x hash1=%x", got[0].Hash, got[1].Hash)
	}
	plain := make([]byte, maxBatchPlain)
	n, err := c2crypto.BrotliL2Decompress(seq.LastBatch, plain)
	if err != nil || n == 0 {
		t.Fatalf("brotli n=%d err=%v", n, err)
	}
}

func TestBatchPosterEmptyAndRoundTrip(t *testing.T) {
	p := NewBatchPoster()
	raw, err := p.Pack(nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Unpack(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("lot vide unpack=%d", len(got))
	}
	to := c2block.Address{0xCC}
	tx := &c2block.Transaction{
		Type:      c2block.TxDynamicFee,
		Nonce:     7,
		Gas:       21000,
		GasTipCap: evm256.FromU64(3),
		GasFeeCap: evm256.FromU64(9),
		GasPrice:  evm256.FromU64(9),
		To:        &to,
		Value:     evm256.FromU64(11),
		Data:      []byte{0xde, 0xad},
		From:      c2block.Address{0xAA},
		Hash:      c2block.Hash{0x11, 0x22},
	}
	packed, err := p.Pack([]*c2block.Transaction{tx})
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.Unpack(packed)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("n=%d", len(out))
	}
	if out[0].Nonce != 7 || out[0].Gas != 21000 || out[0].From != tx.From || out[0].Hash != tx.Hash {
		t.Fatalf("champs unpack=%+v", out[0])
	}
	if !bytes.Equal(out[0].Data, tx.Data) || *out[0].To != to {
		t.Fatalf("data/to unpack")
	}
}

func TestDelayedInboxRetryableIngestion(t *testing.T) {
	st := statetrie.NewStateTrie()
	from := c2block.Address{0xA1}
	to := c2block.Address{0xB2}
	fund(st, from, 1_000_000_000)
	seq := NewSequencer(st)
	seq.DelayedInbox = NewDelayedInbox(0)
	seq.DelayedInbox.Enqueue(DelayedMessage{
		Kind:             MsgRetryable,
		From:             from,
		To:               &to,
		Value:            evm256.FromU64(100),
		Deposit:          evm256.FromU64(1_000_000),
		MaxSubmissionFee: evm256.FromU64(1_000_000),
		GasLimit:         50_000,
		MaxFeePerGas:     evm256.FromU64(1),
		L1BaseFee:        evm256.FromU64(1),
		GasProvided:      100_000,
		PostedAt:         0,
	})
	res, err := seq.ProduceBlock(5)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Receipts) != 1 || res.Receipts[0].Status != 1 {
		t.Fatalf("ingestion retryable: reçus=%d", len(res.Receipts))
	}
	var got evm256.Uint256
	tu := addrToU256(to)
	st.GetBalance(&tu, &got)
	want := evm256.FromU64(100)
	if !evm256.Eq(&got, &want) {
		t.Fatalf("valeur transférée=%v", got)
	}
}

func TestTimeboostExpressBeforeMempool(t *testing.T) {
	st := statetrie.NewStateTrie()
	ex := c2block.Address{0xE1}
	reg := c2block.Address{0xA1}
	fund(st, ex, 1_000_000_000)
	fund(st, reg, 1_000_000_000)
	seq := NewSequencer(st)
	seq.Timeboost = NewTimeboost(1000)
	etx := mkTx(ex, 0, 1, 9)
	rtx := mkTx(reg, 0, 100, 8)
	if err := seq.Timeboost.PushExpress(etx, 1); err != nil {
		t.Fatal(err)
	}
	if err := seq.Mempool.AddTx(rtx); err != nil {
		t.Fatal(err)
	}
	res, err := seq.ProduceBlock(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(seq.LastTxs) != 2 {
		t.Fatalf("txs=%d", len(seq.LastTxs))
	}
	if seq.LastTxs[0].From != ex {
		t.Fatalf("express doit précéder le mempool: %x", seq.LastTxs[0].From)
	}
	if seq.LastTxs[1].From != reg {
		t.Fatalf("mempool en second: %x", seq.LastTxs[1].From)
	}
	if len(res.Receipts) != 2 {
		t.Fatalf("reçus=%d", len(res.Receipts))
	}
}

func TestMempoolNonceBeforeHigherTip(t *testing.T) {
	mp := NewMempool()
	a := c2block.Address{0xA1}
	b := c2block.Address{0xA2}
	if err := mp.AddTx(mkTx(a, 0, 100, 1)); err != nil {
		t.Fatal(err)
	}
	if err := mp.AddTx(mkTx(a, 1, 1000, 2)); err != nil {
		t.Fatal(err)
	}
	if err := mp.AddTx(mkTx(b, 0, 50, 3)); err != nil {
		t.Fatal(err)
	}
	batch := mp.PopBatch(1_000_000, 3)
	if len(batch) != 3 {
		t.Fatalf("lot=%d", len(batch))
	}
	if batch[0].From != a || batch[0].Nonce != 0 {
		t.Fatalf("A0 d'abord, from=%x nonce=%d", batch[0].From, batch[0].Nonce)
	}
	if batch[1].From != b || batch[1].Nonce != 0 {
		t.Fatalf("B0 avant A1 malgré un tip moindre, from=%x nonce=%d", batch[1].From, batch[1].Nonce)
	}
	if batch[2].From != a || batch[2].Nonce != 1 {
		t.Fatalf("A1 en dernier, from=%x nonce=%d", batch[2].From, batch[2].Nonce)
	}
}
