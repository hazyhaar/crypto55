package statetrie

import (
	"bytes"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2crypto"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
)

// EncodeStorageValue renvoie l'encodage RLP canonique d'une valeur de stockage
// Ethereum : l'entier minimal en big-endian, préfixé par 0x80 lorsqu'il est nul.
// C'est la forme sous laquelle la feuille du trie de stockage porte la valeur,
// et donc la forme attendue par la vérification de preuve.
func EncodeStorageValue(val evm256.Uint256) []byte {
	var buf [40]byte
	n := rlpEncodeUint256(&val, buf[:])
	return append([]byte(nil), buf[:n]...)
}

// collectStorageProof rassemble la chaîne de nœuds RLP le long du chemin de la
// racine jusqu'à la position du slot. Le nœud racine est toujours présent ; un
// descendant n'entre dans la preuve que s'il est référencé par empreinte, c'est
// à dire si son encodage RLP atteint 32 octets. Les descendants plus courts sont
// insérés bruts dans leur parent et ne disposent donc pas d'une entrée propre.
func collectStorageProof(root *mptNode, key []byte) [][]byte {
	if root == nil {
		return nil
	}
	proof := make([][]byte, 0, 8)
	proof = append(proof, encodeNodeRLP(root))
	n := root
	for n != nil {
		var child *mptNode
		switch n.kind {
		case mptLeaf:
			n = nil
			continue
		case mptExt:
			if len(key) < len(n.nibbles) || !bytes.Equal(n.nibbles, key[:len(n.nibbles)]) {
				n = nil
				continue
			}
			key = key[len(n.nibbles):]
			child = n.children[0]
		case mptBranch:
			if len(key) == 0 {
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
	return proof
}

// GenerateStorageProof produit la racine de stockage du compte adressé addr et
// la preuve Merkle du slot demandé dans le trie de stockage de ce compte. Un
// compte sans écriture renvoie la racine vide et la preuve canonique d'exclusion
// (0x80), qui atteste que tout slot y vaut zéro.
func (t *StateTrie) GenerateStorageProof(addr, slot evm256.Uint256) ([32]byte, [][]byte, error) {
	t.ensure()
	a := normalizeAddr(&addr)
	var slots []slotPair
	for k, v := range t.storage {
		if k.addr == a {
			slots = append(slots, slotPair{slot: k.slot, val: v})
		}
	}
	root := buildStorageTrie(slots)
	if root == nil {
		return emptyRoot, [][]byte{{0x80}}, nil
	}
	storageRoot := hashRoot(root)
	be := evm256.BytesBE(slot)
	key := hashToNibbles(keccak32(be[:]))
	return storageRoot, collectStorageProof(root, key), nil
}

// VerifyStorageProof vérifie une preuve Merkle Patricia Trie canonique contre
// une racine de stockage, pour la clé keccak256(abi.encode(slot)) et la valeur
// RLP attendue. La fonction suit la règle Yellow Paper : un enfant de moins de
// 32 octets est inséré brut et décodé en place, un enfant de 32 octets est un
// renvoi par empreinte keccak256 vers l'entrée suivante de la preuve. Elle
// accepte une preuve d'exclusion lorsque la valeur attendue est l'entier nul
// encodé 0x80.
func VerifyStorageProof(storageRoot, keyHash [32]byte, expectedValueRLP []byte, proof [][]byte) bool {
	if len(proof) == 0 {
		return false
	}
	var h [32]byte
	c2crypto.Keccak256(proof[0], &h)
	if h != storageRoot {
		return false
	}
	if len(proof[0]) == 1 && proof[0][0] == 0x80 {
		return isNullRLP(expectedValueRLP)
	}
	return walkProof(proof, 0, proof[0], 0, keyHash, expectedValueRLP, 0)
}

func isNullRLP(v []byte) bool {
	return len(v) == 1 && v[0] == 0x80
}

func rlpItem(b []byte, off int) (isList bool, dataOff, dataLen, nextOff int, ok bool) {
	if off < 0 || off >= len(b) {
		return false, 0, 0, off, false
	}
	p := b[off]
	switch {
	case p < 0x80:
		return false, off, 1, off + 1, true
	case p <= 0xb7:
		l := int(p - 0x80)
		if off+1+l > len(b) {
			return false, 0, 0, off, false
		}
		return false, off + 1, l, off + 1 + l, true
	case p <= 0xbf:
		ll := int(p - 0xb7)
		if off+1+ll > len(b) {
			return false, 0, 0, off, false
		}
		l, ok := rlpLen(b[off+1 : off+1+ll])
		if !ok || off+1+ll+l > len(b) {
			return false, 0, 0, off, false
		}
		return false, off + 1 + ll, l, off + 1 + ll + l, true
	case p <= 0xf7:
		l := int(p - 0xc0)
		if off+1+l > len(b) {
			return false, 0, 0, off, false
		}
		return true, off + 1, l, off + 1 + l, true
	default:
		ll := int(p - 0xf7)
		if off+1+ll > len(b) {
			return false, 0, 0, off, false
		}
		l, ok := rlpLen(b[off+1 : off+1+ll])
		if !ok || off+1+ll+l > len(b) {
			return false, 0, 0, off, false
		}
		return true, off + 1 + ll, l, off + 1 + ll + l, true
	}
}

func rlpLen(prefix []byte) (int, bool) {
	if len(prefix) == 0 || len(prefix) > 8 {
		return 0, false
	}
	n := 0
	for _, c := range prefix {
		n = n<<8 | int(c)
	}
	return n, true
}

func keyNibble(keyHash [32]byte, idx int) byte {
	b := keyHash[idx>>1]
	if idx&1 == 0 {
		return b >> 4
	}
	return b & 0x0f
}

func compactInfo(node []byte, off, length int) (isLeaf, odd bool, pathLen int, ok bool) {
	if length == 0 {
		return false, false, 0, false
	}
	flag := node[off] >> 4
	isLeaf = flag&2 != 0
	odd = flag&1 != 0
	pathLen = (length - 1) * 2
	if odd {
		pathLen++
	}
	return isLeaf, odd, pathLen, true
}

func compactNibble(node []byte, off, length int, odd bool, j int) byte {
	if odd {
		if j == 0 {
			return node[off] & 0x0f
		}
		j--
	}
	b := node[off+1+j/2]
	if j&1 == 0 {
		return b >> 4
	}
	return b & 0x0f
}

func pathMatches(node []byte, off, length int, odd bool, pathLen int, keyHash [32]byte, pos int) bool {
	if pos+pathLen > 64 {
		return false
	}
	for j := 0; j < pathLen; j++ {
		if compactNibble(node, off, length, odd, j) != keyNibble(keyHash, pos+j) {
			return false
		}
	}
	return true
}

func descendProof(proof [][]byte, ptr int, node []byte, itemStart, itemNext int, isList bool, dataOff, dataLen, pos int, keyHash [32]byte, expected []byte, depth int) bool {
	if depth > 64 {
		return false
	}
	if isList {
		child := node[itemStart:itemNext]
		return walkProof(proof, ptr, child, pos, keyHash, expected, depth+1)
	}
	if dataLen == 0 {
		return isNullRLP(expected)
	}
	if dataLen != 32 {
		return false
	}
	if ptr+1 >= len(proof) {
		return false
	}
	child := proof[ptr+1]
	var h [32]byte
	c2crypto.Keccak256(child, &h)
	if !bytes.Equal(h[:], node[dataOff:dataOff+32]) {
		return false
	}
	return walkProof(proof, ptr+1, child, pos, keyHash, expected, depth+1)
}

func walkProof(proof [][]byte, ptr int, node []byte, pos int, keyHash [32]byte, expected []byte, depth int) bool {
	if depth > 64 {
		return false
	}
	kind, dataOff, dataLen, _, ok := rlpItem(node, 0)
	if !ok || !kind {
		return false
	}
	end := dataOff + dataLen
	cnt := 0
	for o := dataOff; o < end; {
		_, _, _, nxt, ok := rlpItem(node, o)
		if !ok {
			return false
		}
		o = nxt
		cnt++
	}
	switch cnt {
	case 2:
		l1, p1Off, p1Len, n1, ok1 := rlpItem(node, dataOff)
		l2, p2Off, p2Len, n2, ok2 := rlpItem(node, n1)
		if !ok1 || !ok2 || l1 || l2 {
			return false
		}
		isLeaf, odd, pathLen, ok := compactInfo(node, p1Off, p1Len)
		if !ok {
			return false
		}
		if isLeaf {
			if pos+pathLen != 64 {
				return isNullRLP(expected)
			}
			if !pathMatches(node, p1Off, p1Len, odd, pathLen, keyHash, pos) {
				return isNullRLP(expected)
			}
			return bytes.Equal(node[p2Off:p2Off+p2Len], expected)
		}
		if pos+pathLen >= 64 {
			return isNullRLP(expected)
		}
		if !pathMatches(node, p1Off, p1Len, odd, pathLen, keyHash, pos) {
			return isNullRLP(expected)
		}
		return descendProof(proof, ptr, node, n1, n2, l2, p2Off, p2Len, pos+pathLen, keyHash, expected, depth)
	case 17:
		off := dataOff
		pos64 := pos >= 64
		want := byte(0)
		if !pos64 {
			want = keyNibble(keyHash, pos)
		}
		for i := 0; i < 16; i++ {
			isList, cOff, cLen, nxt, ok := rlpItem(node, off)
			if !ok {
				return false
			}
			if !pos64 && byte(i) == want {
				return descendProof(proof, ptr, node, off, nxt, isList, cOff, cLen, pos+1, keyHash, expected, depth)
			}
			off = nxt
		}
		isList, vOff, vLen, _, ok := rlpItem(node, off)
		if !ok || isList {
			return false
		}
		if pos == 64 {
			if vLen == 0 {
				return isNullRLP(expected)
			}
			return bytes.Equal(node[vOff:vOff+vLen], expected)
		}
		return false
	default:
		return false
	}
}
