// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. See LICENSE and NOTICE.

package statetrie

import (
	"bytes"
	"errors"
	"sync"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2crypto"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2evm"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
)

var (
	ErrInsufficientBalance = errors.New("statetrie: insufficient balance")
	ErrProofNotFound       = errors.New("statetrie: account not present in trie")

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

	// Zones réutilisées par le calcul de racine. Voir arena.go.
	arena          mptArena
	storageEntries []storageEntry
	accountEntries []accountEntry

	// mu protège l'intégrité de l'état, de l'historique de journal et des
	// structures partagées de l'arène de calcul de racine.
	mu sync.RWMutex
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

// reserveArena dimensionne les zones réutilisables pour l'état courant sous
// verrou mu. Elle n'est invoquée qu'à l'entrée de buildAccountTrie().
//
// Démonstration rigoureuse de la borne de nœuds :
// Lors d'une insertion, le trie alloue au pire cas jusqu'à 4 nœuds (extension de
// reste, branche, feuille, extension de préfixe). Comme les nœuds orphelins
// d'une scission intermédiaire ne sont pas recyclés au sein d'une même
// construction, le nombre maximal absolu d'allocations de nœuds est majoré par
// 4 allocations par clé insérée.
// Pour S slots de stockage et A comptes :
//   - Les tries de stockage cumulent au plus 4*S allocations de nœuds.
//   - Le trie de comptes contient au plus A comptes et au pire S adresses de
//     stockage orphelines (sans compte déclaré), soit au plus 4*(A + S) allocations.
//
// Le total maximal alloué est donc strictement majoré par :
//
//	4*S + 4*(A + S) = 4*A + 8*S <= 8*(A + S).
//
// La réservation de 8*(A + S) + 256 nœuds garantit donc une marge de sécurité
// minimale de 4*A + 256 nœuds, strictement supérieure à zéro même pour A = 0.
func (t *StateTrie) reserveArena() {
	n := len(t.accounts) + len(t.storage)
	if n == 0 {
		return
	}
	t.arena.ensureNodes(8*n + 256)
	t.arena.ensureBytes(640*n + 32768)
	if cap(t.storageEntries) < len(t.storage) {
		t.storageEntries = make([]storageEntry, 0, len(t.storage))
	}
	if cap(t.accountEntries) < len(t.accounts) {
		t.accountEntries = make([]accountEntry, 0, len(t.accounts))
	}
}

func normalizeAddr(addr *evm256.Uint256) evm256.Uint256 {
	if addr == nil {
		return evm256.Uint256{}
	}
	res := *addr
	res[3] = 0
	res[2] &= 0x00000000ffffffff
	return res
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
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.accounts == nil {
		return nil, false
	}
	a := normalizeAddr(addr)
	acc, ok := t.accounts[a]
	if !ok {
		return nil, false
	}
	return cloneAccount(acc), true
}

func (t *StateTrie) SetAccount(addr *evm256.Uint256, acc *Account) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ensure()
	a := normalizeAddr(addr)
	old, ok := t.accounts[a]
	t.journal = append(t.journal, journalEntry{
		kind:    journalAcc,
		addr:    a,
		hadAcc:  ok,
		prevAcc: cloneAccount(old),
	})
	if acc == nil {
		delete(t.accounts, a)
		for k, v := range t.storage {
			if k.addr == a {
				t.journal = append(t.journal, journalEntry{
					kind:    journalStor,
					addr:    a,
					slot:    k.slot,
					hadVal:  true,
					prevVal: v,
				})
				delete(t.storage, k)
			}
		}
		return
	}
	t.accounts[a] = cloneAccount(acc)
}

func (t *StateTrie) GetBalance(addr *evm256.Uint256, out *evm256.Uint256) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.accounts == nil {
		*out = evm256.Uint256{}
		return
	}
	a := normalizeAddr(addr)
	acc, ok := t.accounts[a]
	if !ok {
		*out = evm256.Uint256{}
		return
	}
	*out = acc.Balance
}

func (t *StateTrie) ensureAccount(addr *evm256.Uint256) *Account {
	a := normalizeAddr(addr)
	acc, ok := t.accounts[a]
	t.journal = append(t.journal, journalEntry{
		kind:    journalAcc,
		addr:    a,
		hadAcc:  ok,
		prevAcc: cloneAccount(acc),
	})
	if ok {
		return acc
	}
	acc = &Account{CodeHash: emptyCodeHash}
	t.accounts[a] = acc
	return acc
}

func (t *StateTrie) AddBalance(addr *evm256.Uint256, delta *evm256.Uint256) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ensure()
	a := normalizeAddr(addr)
	_, ok := t.accounts[a]
	if !ok && evm256.IsZero(delta) {
		return
	}
	acc := t.ensureAccount(addr)
	evm256.Add256(&acc.Balance, delta, &acc.Balance)
}

func (t *StateTrie) SubBalance(addr *evm256.Uint256, delta *evm256.Uint256) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ensure()
	a := normalizeAddr(addr)
	var bal evm256.Uint256
	acc, ok := t.accounts[a]
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
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.storage == nil {
		*val = evm256.Uint256{}
		return
	}
	a := normalizeAddr(addr)
	v, ok := t.storage[storageKey{addr: a, slot: *key}]
	if !ok {
		*val = evm256.Uint256{}
		return
	}
	*val = v
}

func (t *StateTrie) SetStorage(addr, key, val *evm256.Uint256) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ensure()
	a := normalizeAddr(addr)
	sk := storageKey{addr: a, slot: *key}
	old, ok := t.storage[sk]
	t.journal = append(t.journal, journalEntry{
		kind:    journalStor,
		addr:    a,
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
	t.mu.Lock()
	defer t.mu.Unlock()
	id := len(t.reverts)
	t.reverts = append(t.reverts, len(t.journal))
	return id
}

func (t *StateTrie) RevertToSnapshot(revision int) {
	t.mu.Lock()
	defer t.mu.Unlock()
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

// Commit scelle les mutations courantes : le journal et les points de reprise
// sont tronqués à zéro. Les entrées ainsi libérées cessent d'être réversibles,
// ce qui autorise la récupération de la mémoire des comptes clonés.
func (t *StateTrie) Commit() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.journal = t.journal[:0]
	t.reverts = t.reverts[:0]
}

// DiscardSnapshot libère les points de reprise d'indice supérieur ou égal à rev
// sans rejouer de rollback. Si plus aucun point de reprise ne subsiste, le
// journal est compacté à zéro ; sinon il demeure intact pour que les points de
// reprise conservés gardent des indices de journal valides.
func (t *StateTrie) DiscardSnapshot(rev int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if rev < 0 || rev >= len(t.reverts) {
		return
	}
	t.reverts = t.reverts[:rev]
	if len(t.reverts) == 0 {
		t.journal = t.journal[:0]
	}
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

func encodeNode(n *mptNode, out []byte) int {
	switch n.kind {
	case mptLeaf:
		return c2crypto.MptEncodeLeaf(n.nibbles, n.value, out)
	case mptExt:
		var cbuf [1024]byte
		ck := encodeNode(n.children[0], cbuf[:])
		return c2crypto.MptEncodeExtension(n.nibbles, cbuf[:ck], out)
	case mptBranch:
		var children [16][]byte
		var has [16]int
		var cbuf [16][1024]byte
		for i := 0; i < 16; i++ {
			if n.children[i] != nil {
				ck := encodeNode(n.children[i], cbuf[i][:])
				children[i] = cbuf[i][:ck]
				has[i] = 1
			}
		}
		return c2crypto.MptEncodeBranch(&children, &has, n.value, out)
	default:
		out[0] = 0x80
		return 1
	}
}

func encodeNodeRLP(n *mptNode) []byte {
	var buf [1024]byte
	k := encodeNode(n, buf[:])
	return cloneBytes(buf[:k])
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

// addrKey renvoie la clé de trie d'une adresse Ethereum : les nibbles du
// keccak256 des 20 octets canoniques de l'adresse, et non des 32 octets
// préfixés de zéros du mot evm256.
func addrKey(addr evm256.Uint256) []byte {
	a := normalizeAddr(&addr)
	be := evm256.BytesBE(a)
	return hashToNibbles(keccak32(be[12:32]))
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

func (t *StateTrie) ComputeRoot() [32]byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ensure()
	if len(t.accounts) == 0 && len(t.storage) == 0 {
		return emptyRoot
	}
	return hashRoot(t.buildAccountTrie())
}

// GenerateProof renvoie la preuve de Merkle du compte adressé addr, sous la
// forme canonique Ethereum : la liste des nœuds RLP le long du chemin de la
// racine jusqu'à la feuille de compte. Le nœud racine est toujours présent ;
// un descendant n'est présent que s'il est référencé par empreinte, c'est-à-dire
// si son encodage RLP atteint 32 octets. Les descendants plus courts sont
// insérés bruts dans le nœud parent et n'ont donc pas d'entrée propre.
func (t *StateTrie) GenerateProof(addr evm256.Uint256) ([][]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ensure()
	root := t.buildAccountTrie()
	if root == nil {
		return nil, ErrProofNotFound
	}
	key := addrKey(addr)
	proof := make([][]byte, 0, 8)
	proof = append(proof, encodeNodeRLP(root))
	n := root
	found := false
	for n != nil && !found {
		var child *mptNode
		switch n.kind {
		case mptLeaf:
			if bytes.Equal(n.nibbles, key) {
				found = true
			}
			n = nil
			continue
		case mptExt:
			if len(key) < len(n.nibbles) || !bytes.Equal(n.nibbles, key[:len(n.nibbles)]) {
				return proof, ErrProofNotFound
			}
			key = key[len(n.nibbles):]
			child = n.children[0]
		case mptBranch:
			if len(key) == 0 {
				found = len(n.value) > 0
				n = nil
				continue
			}
			idx := key[0]
			key = key[1:]
			child = n.children[idx]
		default:
			n = nil
			continue
		}
		if child == nil {
			n = nil
			continue
		}
		enc := encodeNodeRLP(child)
		if len(enc) >= 32 {
			proof = append(proof, enc)
		}
		n = child
	}
	if !found {
		return proof, ErrProofNotFound
	}
	return proof, nil
}
