package c2torture

import (
	"bytes"
	"math/big"
	"math/rand"
	"sync"
	"testing"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2block"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2crypto"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2seq"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/onestep"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/statetrie"
)

var mod256 = new(big.Int).Lsh(big.NewInt(1), 256)

func u256ToBig(z evm256.Uint256) *big.Int {
	be := evm256.BytesBE(z)
	return new(big.Int).SetBytes(be[:])
}

func bigToU256(x *big.Int) evm256.Uint256 {
	t := new(big.Int).Mod(x, mod256)
	if t.Sign() < 0 {
		t.Add(t, mod256)
	}
	buf := t.FillBytes(make([]byte, 32))
	return evm256.FromBytesBE(buf)
}

func mustEq256(t *testing.T, op string, got, want evm256.Uint256) {
	t.Helper()
	if !evm256.Eq(&got, &want) {
		gb := evm256.BytesBE(got)
		wb := evm256.BytesBE(want)
		t.Fatalf("%s: obtenu=%x attendu=%x", op, gb, wb)
	}
}

func randU256(r *rand.Rand) evm256.Uint256 {
	return evm256.Uint256{r.Uint64(), r.Uint64(), r.Uint64(), r.Uint64()}
}

func edgeU256() []evm256.Uint256 {
	max := evm256.Uint256{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}
	return []evm256.Uint256{
		{},
		evm256.FromU64(1),
		evm256.FromU64(2),
		evm256.FromU64(^uint64(0)),
		{0, 1, 0, 0},
		{0, 0, 1, 0},
		{0, 0, 0, 1},
		{0, 0, 0, 1 << 63},
		{1 << 63, 0, 0, 0},
		max,
	}
}

func TestAdversarialArith256(t *testing.T) {
	edges := edgeU256()
	var out evm256.Uint256
	for i, a := range edges {
		for j, b := range edges {
			evm256.Add256(&a, &b, &out)
			sum := new(big.Int).Add(u256ToBig(a), u256ToBig(b))
			mustEq256(t, "Add256", out, bigToU256(sum))

			evm256.Sub256(&a, &b, &out)
			diff := new(big.Int).Sub(u256ToBig(a), u256ToBig(b))
			mustEq256(t, "Sub256", out, bigToU256(diff))

			evm256.Mul256(&a, &b, &out)
			prod := new(big.Int).Mul(u256ToBig(a), u256ToBig(b))
			mustEq256(t, "Mul256", out, bigToU256(prod))

			evm256.Div256(&a, &b, &out)
			var quot *big.Int
			if evm256.IsZero(&b) {
				quot = new(big.Int)
			} else {
				quot = new(big.Int).Div(u256ToBig(a), u256ToBig(b))
			}
			mustEq256(t, "Div256", out, bigToU256(quot))

			evm256.Mod256(&a, &b, &out)
			var rem *big.Int
			if evm256.IsZero(&b) {
				rem = new(big.Int)
			} else {
				rem = new(big.Int).Mod(u256ToBig(a), u256ToBig(b))
			}
			mustEq256(t, "Mod256", out, bigToU256(rem))

			evm256.Exp256(&a, &b, &out)
			exp := new(big.Int).Exp(u256ToBig(a), u256ToBig(b), mod256)
			mustEq256(t, "Exp256", out, bigToU256(exp))

			evm256.Shl256(&b, &a, &out)
			var shL evm256.Uint256
			if (b[1]|b[2]|b[3]) != 0 || b[0] >= 256 {
				shL = evm256.Uint256{}
			} else {
				shL = bigToU256(new(big.Int).Lsh(u256ToBig(a), uint(b[0])))
			}
			mustEq256(t, "Shl256", out, shL)

			evm256.Shr256(&b, &a, &out)
			var shR evm256.Uint256
			if (b[1]|b[2]|b[3]) != 0 || b[0] >= 256 {
				shR = evm256.Uint256{}
			} else {
				shR = bigToU256(new(big.Int).Rsh(u256ToBig(a), uint(b[0])))
			}
			mustEq256(t, "Shr256", out, shR)
			_ = i
			_ = j
		}
	}

	shifts := []evm256.Uint256{
		evm256.FromU64(256),
		evm256.FromU64(257),
		evm256.FromU64(511),
		evm256.FromU64(512),
		{0, 1, 0, 0},
		{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)},
	}
	val := evm256.Uint256{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}
	for _, s := range shifts {
		evm256.Shl256(&s, &val, &out)
		if !evm256.IsZero(&out) {
			t.Fatalf("Shl256 shift>=256 doit être zéro, shift=%v out=%v", s, out)
		}
		evm256.Shr256(&s, &val, &out)
		if !evm256.IsZero(&out) {
			t.Fatalf("Shr256 shift>=256 doit être zéro, shift=%v out=%v", s, out)
		}
	}

	zero := evm256.Uint256{}
	one := evm256.FromU64(1)
	evm256.Div256(&one, &zero, &out)
	if !evm256.IsZero(&out) {
		t.Fatal("Div256 par 0 doit rendre 0")
	}
	evm256.Mod256(&one, &zero, &out)
	if !evm256.IsZero(&out) {
		t.Fatal("Mod256 par 0 doit rendre 0")
	}

	r := rand.New(rand.NewSource(55))
	for n := 0; n < 4096; n++ {
		a := randU256(r)
		b := randU256(r)
		evm256.Add256(&a, &b, &out)
		mustEq256(t, "fuzz Add256", out, bigToU256(new(big.Int).Add(u256ToBig(a), u256ToBig(b))))
		evm256.Sub256(&a, &b, &out)
		mustEq256(t, "fuzz Sub256", out, bigToU256(new(big.Int).Sub(u256ToBig(a), u256ToBig(b))))
		evm256.Mul256(&a, &b, &out)
		mustEq256(t, "fuzz Mul256", out, bigToU256(new(big.Int).Mul(u256ToBig(a), u256ToBig(b))))
		if n%8 == 0 {
			expN := evm256.FromU64(uint64(n % 17))
			evm256.Exp256(&a, &expN, &out)
			want := new(big.Int).Exp(u256ToBig(a), big.NewInt(int64(n%17)), mod256)
			mustEq256(t, "fuzz Exp256", out, bigToU256(want))
		}
	}
}

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

func patchU16(b []byte, at int, v uint16) {
	b[at] = byte(v >> 8)
	b[at+1] = byte(v)
}

func deepReentrancyBytecode(maxDepth, revertAt int) []byte {
	var b []byte
	put := func(op ...byte) { b = append(b, op...) }
	put(0x60, 0x00)
	put(0x35)
	put(0x80)
	put(0x60, 0x01)
	put(0x90)
	put(0x55)
	put(0x61, byte(maxDepth>>8), byte(maxDepth))
	put(0x81)
	put(0x10)
	put(0x15)
	stopPush := len(b)
	put(0x61, 0x00, 0x00)
	put(0x57)
	put(0x80)
	put(0x60, 0x01)
	put(0x01)
	put(0x60, 0x00)
	put(0x52)
	put(0x60, 0x00)
	put(0x60, 0x00)
	put(0x60, 0x20)
	put(0x60, 0x00)
	put(0x60, 0x00)
	put(0x30, 0x5a, 0xf1, 0x50)
	var revertPush int
	if revertAt >= 0 {
		put(0x61, byte(revertAt>>8), byte(revertAt))
		put(0x14)
		revertPush = len(b)
		put(0x61, 0x00, 0x00)
		put(0x57)
	}
	put(0x00)
	var destRevert int
	if revertAt >= 0 {
		destRevert = len(b)
		put(0x5b, 0x60, 0x00, 0x60, 0x00, 0xfd)
	}
	destStop := len(b)
	put(0x5b, 0x00)
	patchU16(b, stopPush+1, uint16(destStop))
	if revertAt >= 0 {
		patchU16(b, revertPush+1, uint16(destRevert))
	}
	return b
}

func storageAt(st *statetrie.StateTrie, addr c2block.Address, slot uint64) evm256.Uint256 {
	a := addrToU256(addr)
	k := evm256.FromU64(slot)
	var v evm256.Uint256
	st.GetStorage(&a, &k, &v)
	return v
}

func runDeepTx(t *testing.T, st *statetrie.StateTrie, from, contract c2block.Address, nonce uint64) *c2block.Receipt {
	t.Helper()
	p := c2block.NewBlockProcessor(st)
	h := &c2block.BlockHeader{GasLimit: 1 << 42, Number: 1, Timestamp: 1}
	tx := &c2block.Transaction{
		Nonce:    nonce,
		GasPrice: evm256.Uint256{},
		Gas:      1 << 42,
		To:       &contract,
		From:     from,
		Data:     make([]byte, 32),
	}
	rec, err := p.ProcessTransaction(h, tx)
	if err != nil {
		t.Fatalf("transaction profonde: %v", err)
	}
	return rec
}

func TestAdversarialDeepReentrancy(t *testing.T) {
	from := c2block.Address{0xA1}
	full := c2block.Address{0xC1}
	part := c2block.Address{0xC2}

	st := statetrie.NewStateTrie()
	fund(st, from, 1)
	putCode(st, full, deepReentrancyBytecode(1023, -1))
	rec := runDeepTx(t, st, from, full, 0)
	if rec.Status != 1 {
		t.Fatalf("récursion 1024: status=%d", rec.Status)
	}
	one := evm256.FromU64(1)
	for slot := uint64(0); slot < 1024; slot++ {
		got := storageAt(st, full, slot)
		if !evm256.Eq(&got, &one) {
			t.Fatalf("SSTORE fantôme manquant au niveau %d: %v", slot, got)
		}
	}
	got := storageAt(st, full, 1024)
	if !evm256.IsZero(&got) {
		t.Fatalf("le niveau 1024 doit être rejeté, stockage=%v", got)
	}

	st2 := statetrie.NewStateTrie()
	fund(st2, from, 1)
	putCode(st2, part, deepReentrancyBytecode(1023, 512))
	rec2 := runDeepTx(t, st2, from, part, 0)
	if rec2.Status != 1 {
		t.Fatalf("REVERT partiel: status=%d", rec2.Status)
	}
	for slot := uint64(0); slot < 512; slot++ {
		got := storageAt(st2, part, slot)
		if !evm256.Eq(&got, &one) {
			t.Fatalf("niveau %d doit persister après REVERT 512: %v", slot, got)
		}
	}
	for slot := uint64(512); slot < 1024; slot++ {
		got := storageAt(st2, part, slot)
		if !evm256.IsZero(&got) {
			t.Fatalf("état fantôme au niveau %d après REVERT partiel: %v", slot, got)
		}
	}
	root := st2.ComputeRoot()
	if root == ([32]byte{}) {
		t.Fatal("racine MPT nulle après REVERT partiel")
	}
}

func brotliUncompressed(payload []byte) []byte {
	if len(payload) == 0 {
		return []byte{0x06}
	}
	var out []byte
	var acc uint64
	var nbits int
	put := func(v uint64, n int) {
		acc |= v << uint(nbits)
		nbits += n
		for nbits >= 8 {
			out = append(out, byte(acc))
			acc >>= 8
			nbits -= 8
		}
	}
	put(0, 1)
	put(0, 1)
	mlen := len(payload)
	m := uint64(mlen - 1)
	nib := 0
	bits := 16
	switch {
	case m < 1<<16:
		nib, bits = 0, 16
	case m < 1<<20:
		nib, bits = 1, 20
	default:
		nib, bits = 2, 24
	}
	put(uint64(nib), 2)
	put(m, bits)
	put(1, 1)
	for nbits%8 != 0 {
		put(0, 1)
	}
	for nbits > 0 {
		out = append(out, byte(acc))
		acc >>= 8
		nbits -= 8
	}
	out = append(out, payload...)
	out = append(out, 0x03)
	return out
}

func decompressGuarded(in, out []byte) (n int, err error, panicked any) {
	defer func() { panicked = recover() }()
	n, err = c2crypto.BrotliL2Decompress(in, out)
	return
}

func TestAdversarialBrotliBombs(t *testing.T) {
	const cap64 = 65536
	payloads := [][]byte{
		nil,
		{},
		{0x00},
		{0xff, 0xff, 0xff, 0xff},
		{0x11},
		{0x06},
		bytes.Repeat([]byte{0x61}, 16),
		bytes.Repeat([]byte{0x00}, 4096),
		bytes.Repeat([]byte{0xaa}, cap64),
		brotliUncompressed(bytes.Repeat([]byte{0x41}, 1024)),
		brotliUncompressed(bytes.Repeat([]byte{0x00}, cap64)),
		brotliUncompressed(bytes.Repeat([]byte{0x42}, cap64+1)),
		append(brotliUncompressed([]byte("cycle")), brotliUncompressed([]byte("cycle"))...),
		brotliUncompressed([]byte("hello"))[:3],
		bytes.Repeat([]byte{0x01, 0x02, 0x03, 0x01}, 8192),
		{0x81, 0x00, 0x00, 0x00},
	}
	for i, in := range payloads {
		raw := make([]byte, 8+cap64+8)
		for j := 0; j < 8; j++ {
			raw[j] = 0xaa
			raw[len(raw)-1-j] = 0x55
		}
		out := raw[8 : 8+cap64]
		n, err, panicked := decompressGuarded(in, out)
		if panicked != nil {
			t.Fatalf("bombe %d: panique %v", i, panicked)
		}
		if n < 0 || n > cap64 {
			t.Fatalf("bombe %d: longueur %d hors borne 64 Ko (err=%v)", i, n, err)
		}
		for j := 0; j < 8; j++ {
			if raw[j] != 0xaa || raw[len(raw)-1-j] != 0x55 {
				t.Fatalf("bombe %d: écriture hors bornes (canari)", i)
			}
		}
		if err != nil {
			switch err {
			case c2crypto.ErrBrotliArg, c2crypto.ErrBrotliCapacity, c2crypto.ErrBrotliTrunc,
				c2crypto.ErrBrotliFormat, c2crypto.ErrBrotliWindow, c2crypto.ErrBrotliDict:
			default:
				t.Fatalf("bombe %d: erreur non contrôlée %v", i, err)
			}
		}
	}
	huge := brotliUncompressed(bytes.Repeat([]byte{0x43}, cap64+1))
	out := make([]byte, cap64)
	n, err, panicked := decompressGuarded(huge, out)
	if panicked != nil {
		t.Fatalf("capacité 64 Ko: panique %v", panicked)
	}
	if err != c2crypto.ErrBrotliCapacity {
		t.Fatalf("flux > 64 Ko doit rendre ErrBrotliCapacity, n=%d err=%v", n, err)
	}
}

func TestAdversarialRetryableTickets(t *testing.T) {
	if _, err := c2seq.SafeSubGas(1, 2); err != c2seq.ErrGasUnderflow {
		t.Fatalf("SEC-ARB-10 sous-débordement: %v", err)
	}
	if _, err := c2seq.SafeAddGas(^uint64(0), 1); err != c2seq.ErrGasOverflow {
		t.Fatalf("SEC-ARB-11 débordement add: %v", err)
	}
	if _, err := c2seq.SafeMulGas(^uint64(0), 2); err != c2seq.ErrGasOverflow {
		t.Fatalf("SEC-ARB-11 débordement mul: %v", err)
	}

	eng := c2seq.NewRetryableEngine()
	to := c2block.Address{0xB2}
	from := c2block.Address{0xA1}
	p := c2seq.RetryableParams{
		From:             from,
		To:               &to,
		Deposit:          evm256.FromU64(1_000_000),
		MaxSubmissionFee: evm256.FromU64(1_000_000),
		GasLimit:         50_000,
		MaxFeePerGas:     evm256.FromU64(1),
		Data:             bytes.Repeat([]byte{0xaa}, 100),
		L1BaseFee:        evm256.FromU64(1),
		GasProvided:      1,
	}
	if _, _, err := eng.Create(p); err != c2seq.ErrGasUnderflow {
		t.Fatalf("SEC-ARB-10 gaz fourni < TxGas de soumission: %v", err)
	}

	huge := evm256.Uint256{0, 0, 0, 1 << 63}
	max256v := evm256.Uint256{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}
	p2 := c2seq.RetryableParams{
		From:             from,
		To:               &to,
		Deposit:          max256v,
		MaxSubmissionFee: max256v,
		GasLimit:         2,
		MaxFeePerGas:     huge,
		L1BaseFee:        evm256.FromU64(1),
		GasProvided:      100_000,
	}
	if _, _, err := eng.Create(p2); err != c2seq.ErrGasOverflow {
		t.Fatalf("SEC-ARB-11 gas abusif: %v", err)
	}

	const txGas = uint64(21000)
	p3 := c2seq.RetryableParams{
		From:             from,
		To:               &to,
		Deposit:          evm256.FromU64(1_000_000),
		MaxSubmissionFee: evm256.FromU64(1_000_000),
		GasLimit:         txGas - 1,
		MaxFeePerGas:     evm256.Uint256{},
		L1BaseFee:        evm256.FromU64(1),
		GasProvided:      100_000,
	}
	ticket, tx, err := eng.Create(p3)
	if err != nil {
		t.Fatalf("ticket gas < TxGas: %v", err)
	}
	if tx == nil || tx.Gas >= txGas {
		t.Fatalf("l2GasUsed/gas ticket=%v", tx)
	}
	st := statetrie.NewStateTrie()
	proc := c2block.NewBlockProcessor(st)
	if _, err := proc.ProcessTransaction(&c2block.BlockHeader{GasLimit: 30_000_000}, tx); err != c2block.ErrIntrinsicGas {
		t.Fatalf("l2GasUsed < TxGas doit être rejeté: %v ticket=%v", err, ticket)
	}

	p4 := p3
	p4.GasLimit = 0
	p4.GasProvided = 100_000
	t0, tx0, err := eng.Create(p4)
	if err != nil || tx0 != nil || t0 == nil {
		t.Fatalf("gasLimit 0: ticket=%v tx=%v err=%v", t0, tx0, err)
	}

	inbox := c2seq.NewDelayedInbox(10)
	inbox.Enqueue(c2seq.DelayedMessage{PostedAt: 0, From: from})
	inbox.Enqueue(c2seq.DelayedMessage{PostedAt: ^uint64(0), From: from})
	if n := len(inbox.PopReady(5)); n != 0 {
		t.Fatalf("timestamp trop tôt: %d", n)
	}
	ready := inbox.PopReady(^uint64(0))
	if len(ready) != 1 {
		t.Fatalf("timestamp extrême: prêts=%d", len(ready))
	}
	if n := len(inbox.PopReady(^uint64(0))); n != 0 {
		t.Fatalf("ticket d'expiration max ne doit pas échoir: %d", n)
	}
}

func applyCoWMutations(st *statetrie.StateTrie, n int) [32]byte {
	for i := 0; i < n; i++ {
		addr := evm256.FromU64(uint64(i%17 + 1))
		key := evm256.FromU64(uint64(i))
		val := evm256.FromU64(uint64(i*3 + 1))
		st.SetStorage(&addr, &key, &val)
		d := evm256.FromU64(uint64(i + 1))
		st.AddBalance(&addr, &d)
	}
	return st.ComputeRoot()
}

func TestAdversarialStateTrieCoW(t *testing.T) {
	st := statetrie.NewStateTrie()
	addr := evm256.FromU64(1)
	key := evm256.FromU64(2)
	v1 := evm256.FromU64(10)
	v2 := evm256.FromU64(20)
	v3 := evm256.FromU64(30)
	st.SetStorage(&addr, &key, &v1)
	snap0 := st.Snapshot()
	st.SetStorage(&addr, &key, &v2)
	snap1 := st.Snapshot()
	st.SetStorage(&addr, &key, &v3)
	var got evm256.Uint256
	st.GetStorage(&addr, &key, &got)
	if !evm256.Eq(&got, &v3) {
		t.Fatalf("avant revert: %v", got)
	}
	st.RevertToSnapshot(snap1)
	st.GetStorage(&addr, &key, &got)
	if !evm256.Eq(&got, &v2) {
		t.Fatalf("revert snap1: %v", got)
	}
	st.RevertToSnapshot(snap0)
	st.GetStorage(&addr, &key, &got)
	if !evm256.Eq(&got, &v1) {
		t.Fatalf("revert snap0: %v", got)
	}
	root := st.ComputeRoot()
	ref := statetrie.NewStateTrie()
	ref.SetStorage(&addr, &key, &v1)
	if ref.ComputeRoot() != root {
		t.Fatal("racine MPT non bit-exacte après CoW")
	}

	const workers = 8
	const muts = 64
	roots := make([][32]byte, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(i int) {
			defer wg.Done()
			local := statetrie.NewStateTrie()
			roots[i] = applyCoWMutations(local, muts)
			snap := local.Snapshot()
			extra := evm256.FromU64(99)
			a := evm256.FromU64(1)
			k := evm256.FromU64(0)
			local.SetStorage(&a, &k, &extra)
			local.RevertToSnapshot(snap)
			if local.ComputeRoot() != roots[i] {
				roots[i] = [32]byte{}
			}
		}(w)
	}
	wg.Wait()
	for i := 1; i < workers; i++ {
		if roots[i] != roots[0] || roots[0] == ([32]byte{}) {
			t.Fatalf("mutations concurrentes: racine %d=%x racine 0=%x", i, roots[i], roots[0])
		}
	}
}

func replayHeader() *c2block.BlockHeader {
	return &c2block.BlockHeader{
		Coinbase:  c2block.Address{0xC0},
		GasLimit:  30_000_000,
		Number:    1,
		Timestamp: 1,
	}
}

func expectedOf(res *c2block.BlockResult) ExpectedTransitionResult {
	return ExpectedTransitionResult{
		StateRoot:    res.StateRoot,
		ReceiptsRoot: res.ReceiptsRoot,
		GasUsed:      res.GasUsed,
		Bloom:        res.Bloom,
	}
}

func TestReplayCanonicalTransitions(t *testing.T) {
	from := c2block.Address{0xA1}
	to := c2block.Address{0xB2}
	store := c2block.Address{0x51}
	code := []byte{0x60, 0x2a, 0x60, 0x01, 0x55, 0x60, 0x01, 0x54, 0x00}

	seed := func() *statetrie.StateTrie {
		st := statetrie.NewStateTrie()
		fund(st, from, 10_000_000)
		putCode(st, store, code)
		return st
	}

	txs := []*c2block.Transaction{
		{
			Nonce:    0,
			GasPrice: evm256.FromU64(1),
			Gas:      21000,
			To:       &to,
			Value:    evm256.FromU64(1000),
			From:     from,
		},
		{
			Nonce:    1,
			GasPrice: evm256.FromU64(1),
			Gas:      200_000,
			To:       &store,
			From:     from,
		},
	}

	oracle := c2block.NewBlockProcessor(seed())
	res, err := oracle.ProcessBlock(replayHeader(), txs)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Receipts) != 2 || res.Receipts[0].Status != 1 || res.Receipts[1].Status != 1 {
		t.Fatalf("oracle receipts=%v", res.Receipts)
	}
	exp := expectedOf(res)

	rep, err := NewBlockReplayer(seed()).Replay(BlockReplaySpec{
		Header:         replayHeader(),
		Transactions:   txs,
		Expected:       exp,
		CaptureWitness: true,
		WitnessTxIndex: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("rejeu non bit-exact: %v", rep.Mismatches)
	}
	if rep.GasUsed != exp.GasUsed || rep.StateRoot != exp.StateRoot || rep.ReceiptsRoot != exp.ReceiptsRoot {
		t.Fatal("champs de rapport divergents")
	}
	if !bytes.Equal(rep.Bloom[:], exp.Bloom[:]) {
		t.Fatal("Bloom 2048 bits divergent")
	}
	if len(rep.Witnesses) == 0 {
		t.Fatal("aucun StepWitness capturé")
	}
	for i, w := range rep.Witnesses {
		ok, err := onestep.VerifyWitness(w)
		if !ok || err != nil {
			t.Fatalf("témoin %d: ok=%v err=%v", i, ok, err)
		}
	}

	txs2 := []*c2block.Transaction{
		{
			Nonce:    2,
			GasPrice: evm256.FromU64(1),
			Gas:      21000,
			To:       &to,
			Value:    evm256.FromU64(7),
			From:     from,
		},
	}
	stA := seed()
	pA := c2block.NewBlockProcessor(stA)
	if _, err := pA.ProcessBlock(replayHeader(), txs); err != nil {
		t.Fatal(err)
	}
	res2, err := pA.ProcessBlock(&c2block.BlockHeader{Coinbase: c2block.Address{0xC0}, GasLimit: 30_000_000, Number: 2, Timestamp: 2}, txs2)
	if err != nil {
		t.Fatal(err)
	}

	rB := NewBlockReplayer(seed())
	if _, err := rB.Replay(BlockReplaySpec{Header: replayHeader(), Transactions: txs, Expected: exp}); err != nil {
		t.Fatal(err)
	}
	rep2, err := rB.Replay(BlockReplaySpec{
		Header:       &c2block.BlockHeader{Coinbase: c2block.Address{0xC0}, GasLimit: 30_000_000, Number: 2, Timestamp: 2},
		Transactions: txs2,
		Expected:     expectedOf(res2),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep2.OK {
		t.Fatalf("séquence de blocs: %v", rep2.Mismatches)
	}
}
