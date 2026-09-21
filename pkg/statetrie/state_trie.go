package statetrie

import (
	"errors"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2crypto"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2evm"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
)

var (
	ErrInsufficientBalance = errors.New("statetrie: insufficient balance")

	emptyRoot     [32]byte
	emptyCodeHash [32]byte
)

func init() {
	c2crypto.Keccak256([]byte{0x80}, &emptyRoot)
	c2crypto.Keccak256(nil, &emptyCodeHash)
}

var _ c2evm.StateAccessor = (*StateTrie)(nil)

type storageKey struct {
	addr evm256.Uint256
	slot evm256.Uint256
}

const (
	journalAcc byte = iota
	journalStor
)

type journalEntry struct {
	kind    byte
	addr    evm256.Uint256
	slot    evm256.Uint256
	prevAcc *Account
	hadAcc  bool
	prevVal evm256.Uint256
	hadVal  bool
}

type StateTrie struct {
	accounts map[evm256.Uint256]*Account
	storage  map[storageKey]evm256.Uint256
	journal  []journalEntry
	reverts  []int
}

func NewStateTrie() *StateTrie {
	return &StateTrie{
		accounts: make(map[evm256.Uint256]*Account),
		storage:  make(map[storageKey]evm256.Uint256),
	}
}

func (t *StateTrie) ensure() {
	if t.accounts == nil {
		t.accounts = make(map[evm256.Uint256]*Account)
	}
	if t.storage == nil {
		t.storage = make(map[storageKey]evm256.Uint256)
	}
}

func cloneAccount(src *Account) *Account {
	if src == nil {
		return nil
	}
	dst := *src
	if src.Code != nil {
		dst.Code = append([]byte(nil), src.Code...)
	}
	return &dst
}

func (t *StateTrie) GetAccount(addr *evm256.Uint256) (*Account, bool) {
	t.ensure()
	acc, ok := t.accounts[*addr]
	if !ok {
		return nil, false
	}
	return cloneAccount(acc), true
}

func (t *StateTrie) SetAccount(addr *evm256.Uint256, acc *Account) {
	t.ensure()
	old, ok := t.accounts[*addr]
	t.journal = append(t.journal, journalEntry{
		kind:    journalAcc,
		addr:    *addr,
		hadAcc:  ok,
		prevAcc: cloneAccount(old),
	})
	if acc == nil {
		delete(t.accounts, *addr)
		return
	}
	t.accounts[*addr] = cloneAccount(acc)
}

func (t *StateTrie) GetBalance(addr *evm256.Uint256, out *evm256.Uint256) {
	t.ensure()
	acc, ok := t.accounts[*addr]
	if !ok {
		*out = evm256.Uint256{}
		return
	}
	*out = acc.Balance
}

func (t *StateTrie) ensureAccount(addr *evm256.Uint256) *Account {
	acc, ok := t.accounts[*addr]
	t.journal = append(t.journal, journalEntry{
		kind:    journalAcc,
		addr:    *addr,
		hadAcc:  ok,
		prevAcc: cloneAccount(acc),
	})
	if ok {
		return acc
	}
	acc = &Account{CodeHash: emptyCodeHash}
	t.accounts[*addr] = acc
	return acc
}

func (t *StateTrie) AddBalance(addr *evm256.Uint256, delta *evm256.Uint256) {
	t.ensure()
	acc := t.ensureAccount(addr)
	evm256.Add256(&acc.Balance, delta, &acc.Balance)
}

func (t *StateTrie) SubBalance(addr *evm256.Uint256, delta *evm256.Uint256) error {
	t.ensure()
	var bal evm256.Uint256
	acc, ok := t.accounts[*addr]
	if ok {
		bal = acc.Balance
	}
	if evm256.Cmp(&bal, delta) < 0 {
		return ErrInsufficientBalance
	}
	if !ok && evm256.IsZero(delta) {
		return nil
	}
	acc = t.ensureAccount(addr)
	evm256.Sub256(&acc.Balance, delta, &acc.Balance)
	return nil
}

func (t *StateTrie) GetStorage(addr, key, val *evm256.Uint256) {
	t.ensure()
	v, ok := t.storage[storageKey{addr: *addr, slot: *key}]
	if !ok {
		*val = evm256.Uint256{}
		return
	}
	*val = v
}

func (t *StateTrie) SetStorage(addr, key, val *evm256.Uint256) {
	t.ensure()
	sk := storageKey{addr: *addr, slot: *key}
	old, ok := t.storage[sk]
	t.journal = append(t.journal, journalEntry{
		kind:    journalStor,
		addr:    *addr,
		slot:    *key,
		hadVal:  ok,
		prevVal: old,
	})
	if evm256.IsZero(val) {
		delete(t.storage, sk)
		return
	}
	t.storage[sk] = *val
}

func (t *StateTrie) Snapshot() int {
	id := len(t.reverts)
	t.reverts = append(t.reverts, len(t.journal))
	return id
}

func (t *StateTrie) RevertToSnapshot(revision int) {
	if revision < 0 || revision >= len(t.reverts) {
		panic("statetrie: invalid snapshot")
	}
	jidx := t.reverts[revision]
	for i := len(t.journal) - 1; i >= jidx; i-- {
		t.applyRevert(t.journal[i])
	}
	t.journal = t.journal[:jidx]
	t.reverts = t.reverts[:revision]
}

func (t *StateTrie) applyRevert(e journalEntry) {
	switch e.kind {
	case journalAcc:
		if !e.hadAcc {
			delete(t.accounts, e.addr)
			return
		}
		t.accounts[e.addr] = e.prevAcc
	case journalStor:
		sk := storageKey{addr: e.addr, slot: e.slot}
		if !e.hadVal {
			delete(t.storage, sk)
			return
		}
		t.storage[sk] = e.prevVal
	}
}

const (
	mptEmpty byte = iota
	mptLeaf
	mptExt
	mptBranch
)

type mptNode struct {
	kind     byte
	nibbles  []byte
	value    []byte
	children [16]*mptNode
}

func commonPrefix(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	i := 0
	for i < n && a[i] == b[i] {
		i++
	}
	return i
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}

func newLeaf(key, value []byte) *mptNode {
	return &mptNode{kind: mptLeaf, nibbles: cloneBytes(key), value: cloneBytes(value)}
}

func newExt(key []byte, child *mptNode) *mptNode {
	n := &mptNode{kind: mptExt, nibbles: cloneBytes(key)}
	n.children[0] = child
	return n
}

func insertNode(n *mptNode, key, value []byte) *mptNode {
	if n == nil || n.kind == mptEmpty {
		return newLeaf(key, value)
	}
	switch n.kind {
	case mptLeaf:
		return insertLeaf(n, key, value)
	case mptExt:
		return insertExt(n, key, value)
	case mptBranch:
		return insertBranch(n, key, value)
	default:
		return newLeaf(key, value)
	}
}

func insertLeaf(n *mptNode, key, value []byte) *mptNode {
	if len(n.nibbles) == len(key) {
		eq := true
		for i := range key {
			if n.nibbles[i] != key[i] {
				eq = false
				break
			}
		}
		if eq {
			n.value = cloneBytes(value)
			return n
		}
	}
	cp := commonPrefix(n.nibbles, key)
	br := splitToBranch(n.nibbles[cp:], n.value, nil, key[cp:], value)
	if cp > 0 {
		return newExt(n.nibbles[:cp], br)
	}
	return br
}

func insertExt(n *mptNode, key, value []byte) *mptNode {
	cp := commonPrefix(n.nibbles, key)
	if cp == len(n.nibbles) {
		n.children[0] = insertNode(n.children[0], key[cp:], value)
		return n
	}
	oldRest := n.nibbles[cp:]
	oldChild := n.children[0]
	var oldNode *mptNode
	if len(oldRest) == 1 {
		oldNode = oldChild
	} else {
		oldNode = newExt(oldRest[1:], oldChild)
	}
	br := splitToBranch(oldRest, nil, oldNode, key[cp:], value)
	if cp > 0 {
		return newExt(n.nibbles[:cp], br)
	}
	return br
}

func insertBranch(n *mptNode, key, value []byte) *mptNode {
	if len(key) == 0 {
		n.value = cloneBytes(value)
		return n
	}
	n.children[key[0]] = insertNode(n.children[key[0]], key[1:], value)
	return n
}

func splitToBranch(oldRest, oldVal []byte, oldNode *mptNode, newRest, newVal []byte) *mptNode {
	br := &mptNode{kind: mptBranch}
	if len(oldRest) == 0 {
		br.value = cloneBytes(oldVal)
	} else {
		if oldNode == nil {
			oldNode = newLeaf(oldRest[1:], oldVal)
		}
		br.children[oldRest[0]] = oldNode
	}
	if len(newRest) == 0 {
		br.value = cloneBytes(newVal)
	} else {
		br.children[newRest[0]] = newLeaf(newRest[1:], newVal)
	}
	return br
}

func encodeNode(n *mptNode, out []byte) int {
	switch n.kind {
	case mptLeaf:
		return c2crypto.MptEncodeLeaf(n.nibbles, n.value, out)
	case mptExt:
		h := hashChild(n.children[0])
		return c2crypto.MptEncodeExtension(n.nibbles, &h, out)
	case mptBranch:
		var children [16][32]byte
		var has [16]int
		for i := 0; i < 16; i++ {
			if n.children[i] != nil {
				children[i] = hashChild(n.children[i])
				has[i] = 1
			}
		}
		return c2crypto.MptEncodeBranch(&children, &has, n.value, out)
	default:
		out[0] = 0x80
		return 1
	}
}

func hashChild(n *mptNode) [32]byte {
	var buf [1024]byte
	k := encodeNode(n, buf[:])
	var h [32]byte
	c2crypto.MptHashNode(buf[:k], &h)
	return h
}

func hashRoot(n *mptNode) [32]byte {
	if n == nil {
		return emptyRoot
	}
	var buf [1024]byte
	k := encodeNode(n, buf[:])
	var h [32]byte
	c2crypto.Keccak256(buf[:k], &h)
	return h
}

func hashToNibbles(h [32]byte) []byte {
	n := make([]byte, 64)
	for i := 0; i < 32; i++ {
		n[i*2] = h[i] >> 4
		n[i*2+1] = h[i] & 0x0f
	}
	return n
}

func keccak32(in []byte) [32]byte {
	var h [32]byte
	c2crypto.Keccak256(in, &h)
	return h
}

func rlpEncodeUint64(n uint64, out []byte) int {
	if n == 0 {
		out[0] = 0x80
		return 1
	}
	var tmp [8]byte
	i := 8
	for n != 0 {
		i--
		tmp[i] = byte(n)
		n >>= 8
	}
	return c2crypto.RlpEncodeBytes(tmp[i:], out)
}

func rlpEncodeUint256(z *evm256.Uint256, out []byte) int {
	if evm256.IsZero(z) {
		out[0] = 0x80
		return 1
	}
	be := evm256.BytesBE(*z)
	i := 0
	for i < 32 && be[i] == 0 {
		i++
	}
	return c2crypto.RlpEncodeBytes(be[i:], out)
}

func encodeAccount(nonce uint64, balance evm256.Uint256, storageRoot, codeHash [32]byte, out []byte) int {
	var nbuf, bbuf, sbuf, cbuf [40]byte
	nl := rlpEncodeUint64(nonce, nbuf[:])
	bl := rlpEncodeUint256(&balance, bbuf[:])
	sl := c2crypto.RlpEncodeBytes(storageRoot[:], sbuf[:])
	cl := c2crypto.RlpEncodeBytes(codeHash[:], cbuf[:])
	payload := nl + bl + sl + cl
	n := c2crypto.RlpEncodeListHeader(payload, out)
	copy(out[n:], nbuf[:nl])
	n += nl
	copy(out[n:], bbuf[:bl])
	n += bl
	copy(out[n:], sbuf[:sl])
	n += sl
	copy(out[n:], cbuf[:cl])
	n += cl
	return n
}

type slotPair struct {
	slot evm256.Uint256
	val  evm256.Uint256
}

func hashStorage(slots []slotPair) [32]byte {
	if len(slots) == 0 {
		return emptyRoot
	}
	var n *mptNode
	for i := range slots {
		be := evm256.BytesBE(slots[i].slot)
		nibs := hashToNibbles(keccak32(be[:]))
		var vbuf [40]byte
		vn := rlpEncodeUint256(&slots[i].val, vbuf[:])
		n = insertNode(n, nibs, vbuf[:vn])
	}
	return hashRoot(n)
}

func (t *StateTrie) ComputeRoot() [32]byte {
	t.ensure()
	if len(t.accounts) == 0 && len(t.storage) == 0 {
		return emptyRoot
	}
	byAddr := make(map[evm256.Uint256][]slotPair)
	for k, v := range t.storage {
		byAddr[k.addr] = append(byAddr[k.addr], slotPair{slot: k.slot, val: v})
	}
	var root *mptNode
	seen := make(map[evm256.Uint256]struct{}, len(t.accounts))
	for addr, acc := range t.accounts {
		seen[addr] = struct{}{}
		sr := hashStorage(byAddr[addr])
		codeHash := acc.CodeHash
		if codeHash == ([32]byte{}) {
			codeHash = emptyCodeHash
		}
		var abuf [256]byte
		an := encodeAccount(acc.Nonce, acc.Balance, sr, codeHash, abuf[:])
		be := evm256.BytesBE(addr)
		nibs := hashToNibbles(keccak32(be[:]))
		root = insertNode(root, nibs, abuf[:an])
	}
	for addr, slots := range byAddr {
		if _, ok := seen[addr]; ok {
			continue
		}
		sr := hashStorage(slots)
		var abuf [256]byte
		an := encodeAccount(0, evm256.Uint256{}, sr, emptyCodeHash, abuf[:])
		be := evm256.BytesBE(addr)
		nibs := hashToNibbles(keccak32(be[:]))
		root = insertNode(root, nibs, abuf[:an])
	}
	return hashRoot(root)
}
