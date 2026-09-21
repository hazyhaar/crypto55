package statetrie

import (
	"slices"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
)

// storageEntry associe un couple (slot, valeur) à l'adresse de son compte.
// Le regroupement s'effectue sur une tranche triée par adresse, ce qui évite
// toute table de hachage temporaire dans le chemin de calcul de racine.
type storageEntry struct {
	addr evm256.Uint256
	slot evm256.Uint256
	val  evm256.Uint256
}

// accountEntry associe une adresse de compte à son état, afin de trier les
// comptes avant la fusion avec les écritures de stockage.
type accountEntry struct {
	addr evm256.Uint256
	acc  *Account
}

// mptArena regroupe les nœuds et les octets du trie Merkle Patricia dans deux
// zones contiguës réutilisées d'un appel à l'autre. Les nœuds sont adressés par
// emplacement dans la tranche a.nodes ; toute reprise de capacité (ensureNodes)
// doit intervenir avant la création du premier pointeur de l'arbre, sous peine
// d'invalider les pointeurs enfants.
type mptArena struct {
	nodes     []mptNode
	nodeCount int
	bytesBuf  []byte
	byteCount int
}

const nibbleLen = 64

// ensureNodes garantit une capacité d'au moins n nœuds. Une réallocation
// n'intervient que si la capacité courante est insuffisante ; elle doit être
// invoquée avant tout allocNode de la construction en cours.
func (a *mptArena) ensureNodes(n int) {
	if len(a.nodes) < n {
		a.nodes = make([]mptNode, n)
	}
}

// ensureBytes garantit un tampon d'octets d'au moins n octets.
func (a *mptArena) ensureBytes(n int) {
	if len(a.bytesBuf) < n {
		a.bytesBuf = make([]byte, n)
	}
}

// reset réarme les compteurs logiques sans toucher aux capacités.
func (a *mptArena) reset() {
	a.nodeCount = 0
	a.byteCount = 0
}

// allocNode renvoie un nœud vierge du type demandé. Le nœud est indexé par
// nodeCount et intégralement remis à zéro, enfants compris.
func (a *mptArena) allocNode(kind byte) *mptNode {
	if a.nodeCount >= len(a.nodes) {
		panic("statetrie: arène mpt saturée - capacité insuffisante")
	}
	n := &a.nodes[a.nodeCount]
	a.nodeCount++
	*n = mptNode{kind: kind}
	return n
}

// growBytes double au besoin la zone d'octets. La copie laisse intactes les
// tranches déjà distribuées, qui pointent vers l'ancienne zone : les octets
// alloués ne sont jamais réécrits après coup.
func (a *mptArena) growBytes(n int) {
	size := len(a.bytesBuf) * 2
	if size < 8192 {
		size = 8192
	}
	for size < n {
		size *= 2
	}
	buf := make([]byte, size)
	copy(buf, a.bytesBuf)
	a.bytesBuf = buf
}

// allocBytes recopie b dans la zone d'octets et renvoie la vue stable qui y
// correspond.
func (a *mptArena) allocBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	start := a.byteCount
	end := start + len(b)
	if end > len(a.bytesBuf) {
		a.growBytes(end)
	}
	dst := a.bytesBuf[start:end]
	copy(dst, b)
	a.byteCount = end
	return dst
}

// allocNibbles décompose une empreinte de 32 octets en 64 nibbles et les écrit
// dans la zone d'octets.
func (a *mptArena) allocNibbles(h [32]byte) []byte {
	start := a.byteCount
	end := start + nibbleLen
	if end > len(a.bytesBuf) {
		a.growBytes(end)
	}
	dst := a.bytesBuf[start:end]
	a.byteCount = end
	for i := 0; i < 32; i++ {
		dst[i*2] = h[i] >> 4
		dst[i*2+1] = h[i] & 0x0f
	}
	return dst
}

func newLeaf(a *mptArena, key, value []byte) *mptNode {
	n := a.allocNode(mptLeaf)
	n.nibbles = a.allocBytes(key)
	n.value = a.allocBytes(value)
	return n
}

func newExt(a *mptArena, key []byte, child *mptNode) *mptNode {
	n := a.allocNode(mptExt)
	n.nibbles = a.allocBytes(key)
	n.children[0] = child
	return n
}

func insertNode(a *mptArena, n *mptNode, key, value []byte) *mptNode {
	if n == nil || n.kind == mptEmpty {
		return newLeaf(a, key, value)
	}
	switch n.kind {
	case mptLeaf:
		return insertLeaf(a, n, key, value)
	case mptExt:
		return insertExt(a, n, key, value)
	case mptBranch:
		return insertBranch(a, n, key, value)
	default:
		return newLeaf(a, key, value)
	}
}

func insertLeaf(a *mptArena, n *mptNode, key, value []byte) *mptNode {
	if len(n.nibbles) == len(key) {
		eq := true
		for i := range key {
			if n.nibbles[i] != key[i] {
				eq = false
				break
			}
		}
		if eq {
			n.value = a.allocBytes(value)
			return n
		}
	}
	cp := commonPrefix(n.nibbles, key)
	br := splitToBranch(a, n.nibbles[cp:], n.value, nil, key[cp:], value)
	if cp > 0 {
		return newExt(a, n.nibbles[:cp], br)
	}
	return br
}

func insertExt(a *mptArena, n *mptNode, key, value []byte) *mptNode {
	cp := commonPrefix(n.nibbles, key)
	if cp == len(n.nibbles) {
		n.children[0] = insertNode(a, n.children[0], key[cp:], value)
		return n
	}
	oldRest := n.nibbles[cp:]
	oldChild := n.children[0]
	var oldNode *mptNode
	if len(oldRest) == 1 {
		oldNode = oldChild
	} else {
		oldNode = newExt(a, oldRest[1:], oldChild)
	}
	br := splitToBranch(a, oldRest, nil, oldNode, key[cp:], value)
	if cp > 0 {
		return newExt(a, n.nibbles[:cp], br)
	}
	return br
}

func insertBranch(a *mptArena, n *mptNode, key, value []byte) *mptNode {
	if len(key) == 0 {
		n.value = a.allocBytes(value)
		return n
	}
	n.children[key[0]] = insertNode(a, n.children[key[0]], key[1:], value)
	return n
}

func splitToBranch(a *mptArena, oldRest, oldVal []byte, oldNode *mptNode, newRest, newVal []byte) *mptNode {
	br := a.allocNode(mptBranch)
	if len(oldRest) == 0 {
		br.value = a.allocBytes(oldVal)
	} else {
		if oldNode == nil {
			oldNode = newLeaf(a, oldRest[1:], oldVal)
		}
		br.children[oldRest[0]] = oldNode
	}
	if len(newRest) == 0 {
		br.value = a.allocBytes(newVal)
	} else {
		br.children[newRest[0]] = newLeaf(a, newRest[1:], newVal)
	}
	return br
}

// buildStorageTrieRange construit le trie de stockage d'un groupe contigu de
// storageEntry (indices [lo, hi)) dans l'arène fournie. Les entrées doivent
// partager la même adresse ; l'ordre des slots y est indifférent, le trie
// Merkle Patricia étant canonique.
func buildStorageTrieRange(a *mptArena, entries []storageEntry, lo, hi int) *mptNode {
	var n *mptNode
	for i := lo; i < hi; i++ {
		be := evm256.BytesBE(entries[i].slot)
		nibs := a.allocNibbles(keccak32(be[:]))
		var vbuf [40]byte
		vn := rlpEncodeUint256(&entries[i].val, vbuf[:])
		n = insertNode(a, n, nibs, vbuf[:vn])
	}
	return n
}

// storageRootOfRange renvoie la racine du trie de stockage d'un groupe contigu.
func storageRootOfRange(a *mptArena, entries []storageEntry, lo, hi int) [32]byte {
	if lo >= hi {
		return emptyRoot
	}
	return hashRoot(buildStorageTrieRange(a, entries, lo, hi))
}

// slotPair est la forme historique d'un couple (slot, valeur) sans adresse,
// conservée pour les preuves de stockage hors du chemin de calcul de racine.
type slotPair struct {
	slot evm256.Uint256
	val  evm256.Uint256
}

// buildStorageTrie construit un trie de stockage à partir de couples isolés en
// allouant une arène locale. Ce chemin, emprunté par la génération de preuves,
// n'est pas soumis à l'exigence zéro allocation.
func buildStorageTrie(slots []slotPair) *mptNode {
	a := &mptArena{}
	a.ensureNodes(4*len(slots) + 64)
	a.ensureBytes(640*len(slots) + 16384)
	var n *mptNode
	for i := range slots {
		be := evm256.BytesBE(slots[i].slot)
		nibs := a.allocNibbles(keccak32(be[:]))
		var vbuf [40]byte
		vn := rlpEncodeUint256(&slots[i].val, vbuf[:])
		n = insertNode(a, n, nibs, vbuf[:vn])
	}
	return n
}

func hashStorage(slots []slotPair) [32]byte {
	if len(slots) == 0 {
		return emptyRoot
	}
	return hashRoot(buildStorageTrie(slots))
}

// insertAccount encode l'état d'un compte et l'insère dans le trie de comptes.
func (t *StateTrie) insertAccount(root *mptNode, addr evm256.Uint256, nonce uint64, bal evm256.Uint256, sr, codeHash [32]byte) *mptNode {
	a := &t.arena
	var abuf [256]byte
	an := encodeAccount(nonce, bal, sr, codeHash, abuf[:])
	be := evm256.BytesBE(addr)
	return insertNode(a, root, a.allocNibbles(keccak32(be[12:32])), abuf[:an])
}

// buildAccountTrie construit le trie de comptes sans aucune allocation sur le
// tas lorsque l'arène a été pré-réservée : les écritures de stockage sont
// regroupées sur une tranche triée par adresse, puis fusionnées avec les
// comptes triés de la même façon. Les adresses présentes en stockage sans
// compte sont insérées comme comptes vides.
//
// L'appel n'est pas réentrant : l'arène est partagée et remise à zéro à chaque
// construction.
func (t *StateTrie) buildAccountTrie() *mptNode {
	t.reserveArena()
	a := &t.arena

	entries := t.storageEntries[:0]
	for k, v := range t.storage {
		entries = append(entries, storageEntry{addr: k.addr, slot: k.slot, val: v})
	}
	t.storageEntries = entries
	slices.SortFunc(entries, func(x, y storageEntry) int {
		if c := evm256.Cmp(&x.addr, &y.addr); c != 0 {
			return c
		}
		return evm256.Cmp(&x.slot, &y.slot)
	})

	accts := t.accountEntries[:0]
	for addr, acc := range t.accounts {
		accts = append(accts, accountEntry{addr: addr, acc: acc})
	}
	t.accountEntries = accts
	slices.SortFunc(accts, func(x, y accountEntry) int {
		return evm256.Cmp(&x.addr, &y.addr)
	})

	a.reset()

	var root *mptNode
	ei := 0
	for ai := 0; ai < len(accts); ai++ {
		addr := accts[ai].addr
		for ei < len(entries) && evm256.Cmp(&entries[ei].addr, &addr) < 0 {
			start := ei
			for ei < len(entries) && entries[ei].addr == entries[start].addr {
				ei++
			}
			sr := storageRootOfRange(a, entries, start, ei)
			root = t.insertAccount(root, entries[start].addr, 0, evm256.Uint256{}, sr, emptyCodeHash)
		}
		start := ei
		for ei < len(entries) && entries[ei].addr == addr {
			ei++
		}
		sr := storageRootOfRange(a, entries, start, ei)
		acc := accts[ai].acc
		codeHash := acc.CodeHash
		if codeHash == ([32]byte{}) {
			codeHash = emptyCodeHash
		}
		root = t.insertAccount(root, addr, acc.Nonce, acc.Balance, sr, codeHash)
	}
	for ei < len(entries) {
		start := ei
		for ei < len(entries) && entries[ei].addr == entries[start].addr {
			ei++
		}
		sr := storageRootOfRange(a, entries, start, ei)
		root = t.insertAccount(root, entries[start].addr, 0, evm256.Uint256{}, sr, emptyCodeHash)
	}
	return root
}
