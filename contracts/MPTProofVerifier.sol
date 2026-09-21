// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

/// @title MPTProofVerifier
/// @notice Vérification pure d'une preuve de Merkle Patricia Trie canonique
///         Ethereum contre une racine de stockage. La clé est
///         keccak256(abi.encode(slot)) et la valeur feuille est l'entier
///         minimal big-endian encodé en RLP (0x80 pour zéro). La règle
///         Yellow Paper est appliquée : un enfant de moins de 32 octets est
///         inséré brut et décodé en place, un enfant de 32 octets est un
///         renvoi par empreinte keccak256 vers l'entrée suivante de la preuve.
library MPTProofVerifier {
    function verifyStorageProof(
        bytes32 storageRoot,
        bytes32 keyHash,
        bytes memory expectedValueRLP,
        bytes[] calldata proof
    ) internal pure returns (bool) {
        if (proof.length == 0) {
            return false;
        }
        if (keccak256(proof[0]) != storageRoot) {
            return false;
        }
        if (proof[0].length == 1 && proof[0][0] == 0x80) {
            return _isNull(expectedValueRLP);
        }
        return _walk(proof[0], keyHash, expectedValueRLP, proof);
    }

    function _isNull(bytes memory e) private pure returns (bool) {
        return e.length == 1 && e[0] == 0x80;
    }

    function _keyNibble(bytes32 keyHash, uint256 idx) private pure returns (uint256) {
        uint256 b = uint256(uint8(keyHash[idx >> 1]));
        if (idx & 1 == 0) {
            return b >> 4;
        }
        return b & 0x0f;
    }

    function _load32(bytes memory b, uint256 off) private pure returns (bytes32 out) {
        assembly {
            out := mload(add(add(b, 0x20), off))
        }
    }

    function _slice(bytes memory b, uint256 start, uint256 len)
        private
        pure
        returns (bytes memory out)
    {
        out = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = b[start + i];
        }
    }

    function _bytesEq(bytes memory a, uint256 aOff, uint256 aLen, bytes memory b)
        private
        pure
        returns (bool)
    {
        if (aLen != b.length) {
            return false;
        }
        for (uint256 i = 0; i < aLen; i++) {
            if (a[aOff + i] != b[i]) {
                return false;
            }
        }
        return true;
    }

    /// @dev Décode un élément RLP à l'offset off. isList distingue une liste
    ///      d'une chaîne d'octets ; dataOff/dataLen délimitent la charge utile.
    function _rlp(bytes memory b, uint256 off)
        private
        pure
        returns (bool isList, uint256 dataOff, uint256 dataLen, uint256 nextOff, bool ok)
    {
        if (off >= b.length) {
            return (false, 0, 0, off, false);
        }
        uint8 p = uint8(b[off]);
        if (p < 0x80) {
            return (false, off, 1, off + 1, true);
        }
        if (p <= 0xb7) {
            uint256 shortLen = p - 0x80;
            if (off + 1 + shortLen > b.length) {
                return (false, 0, 0, off, false);
            }
            return (false, off + 1, shortLen, off + 1 + shortLen, true);
        }
        if (p <= 0xbf) {
            uint256 strPrefix = p - 0xb7;
            if (off + 1 + strPrefix > b.length) {
                return (false, 0, 0, off, false);
            }
            (uint256 strLen, bool strOk) = _rlpLen(b, off + 1, strPrefix);
            if (!strOk || off + 1 + strPrefix + strLen > b.length) {
                return (false, 0, 0, off, false);
            }
            return (false, off + 1 + strPrefix, strLen, off + 1 + strPrefix + strLen, true);
        }
        if (p <= 0xf7) {
            uint256 listLen = p - 0xc0;
            if (off + 1 + listLen > b.length) {
                return (false, 0, 0, off, false);
            }
            return (true, off + 1, listLen, off + 1 + listLen, true);
        }
        uint256 listPrefix = p - 0xf7;
        if (off + 1 + listPrefix > b.length) {
            return (false, 0, 0, off, false);
        }
        (uint256 longListLen, bool longOk) = _rlpLen(b, off + 1, listPrefix);
        if (!longOk || off + 1 + listPrefix + longListLen > b.length) {
            return (false, 0, 0, off, false);
        }
        return (true, off + 1 + listPrefix, longListLen, off + 1 + listPrefix + longListLen, true);
    }

    function _rlpLen(bytes memory b, uint256 off, uint256 ll)
        private
        pure
        returns (uint256 n, bool ok)
    {
        if (ll == 0 || ll > 8) {
            return (0, false);
        }
        for (uint256 i = 0; i < ll; i++) {
            n = (n << 8) | uint256(uint8(b[off + i]));
        }
        return (n, true);
    }

    function _compactInfo(bytes memory node, uint256 off, uint256 length)
        private
        pure
        returns (bool isLeaf, bool odd, uint256 pathLen, bool ok)
    {
        if (length == 0) {
            return (false, false, 0, false);
        }
        uint256 flag = uint256(uint8(node[off])) >> 4;
        isLeaf = flag & 2 != 0;
        odd = flag & 1 != 0;
        pathLen = (length - 1) * 2;
        if (odd) {
            pathLen++;
        }
        return (isLeaf, odd, pathLen, true);
    }

    function _compactNibble(bytes memory node, uint256 off, bool odd, uint256 j)
        private
        pure
        returns (uint256)
    {
        if (odd) {
            if (j == 0) {
                return uint256(uint8(node[off])) & 0x0f;
            }
            j--;
        }
        uint256 b = uint256(uint8(node[off + 1 + (j >> 1)]));
        if (j & 1 == 0) {
            return b >> 4;
        }
        return b & 0x0f;
    }

    function _pathMatches(
        bytes memory node,
        uint256 off,
        bool odd,
        uint256 pathLen,
        bytes32 keyHash,
        uint256 pos
    ) private pure returns (bool) {
        if (pos + pathLen > 64) {
            return false;
        }
        for (uint256 j = 0; j < pathLen; j++) {
            if (_compactNibble(node, off, odd, j) != _keyNibble(keyHash, pos + j)) {
                return false;
            }
        }
        return true;
    }

    /// @dev Résout l'enfant d'un nœud : un enfant encodé sous forme de liste
    ///      est déjà en place et se découpe depuis le tampon courant ; un
    ///      renvoi de 32 octets est vérifié puis résolu vers l'entrée suivante
    ///      de la preuve. Tout autre cas est un échec.
    function _descend(
        bytes[] calldata proof,
        bytes memory node,
        uint256 itemStart,
        uint256 itemNext,
        bool isList,
        uint256 dataOff,
        uint256 dataLen,
        uint256 ptr
    ) private pure returns (bool ok, bytes memory child, uint256 childPtr) {
        if (isList) {
            return (true, _slice(node, itemStart, itemNext - itemStart), ptr);
        }
        if (dataLen != 32 || ptr + 1 >= proof.length) {
            return (false, node, ptr);
        }
        bytes memory candidate = proof[ptr + 1];
        if (keccak256(candidate) != _load32(node, dataOff)) {
            return (false, node, ptr);
        }
        return (true, candidate, ptr + 1);
    }

    function _walk(
        bytes memory root,
        bytes32 keyHash,
        bytes memory expected,
        bytes[] calldata proof
    ) private pure returns (bool) {
        bytes memory node = root;
        uint256 pos = 0;
        uint256 ptr = 0;
        for (uint256 guard = 0; guard < 130; guard++) {
            (bool isList, uint256 dataOff, uint256 dataLen,, bool ok) = _rlp(node, 0);
            if (!ok || !isList) {
                return false;
            }
            uint256 end = dataOff + dataLen;
            uint256 cnt = 0;
            uint256 o = dataOff;
            while (o < end) {
                uint256 nxt;
                (, , , nxt, ok) = _rlp(node, o);
                if (!ok) {
                    return false;
                }
                o = nxt;
                cnt++;
            }

            bool descend;
            bool childIsList;
            uint256 itemStart;
            uint256 itemNext;
            uint256 cOff;
            uint256 cLen;

            if (cnt == 2) {
                (bool l1, uint256 p1Off, uint256 p1Len, uint256 n1, bool ok1) = _rlp(node, dataOff);
                (bool l2, uint256 p2Off, uint256 p2Len, uint256 n2, bool ok2) = _rlp(node, n1);
                if (!ok1 || !ok2 || l1 || l2) {
                    return false;
                }
                (bool isLeaf, bool odd, uint256 pathLen, bool cok) = _compactInfo(node, p1Off, p1Len);
                if (!cok) {
                    return false;
                }
                if (isLeaf) {
                    if (pos + pathLen != 64) {
                        return _isNull(expected);
                    }
                    if (!_pathMatches(node, p1Off, odd, pathLen, keyHash, pos)) {
                        return _isNull(expected);
                    }
                    return _bytesEq(node, p2Off, p2Len, expected);
                }
                if (pos + pathLen >= 64) {
                    return _isNull(expected);
                }
                if (!_pathMatches(node, p1Off, odd, pathLen, keyHash, pos)) {
                    return _isNull(expected);
                }
                pos += pathLen;
                descend = true;
                childIsList = l2;
                itemStart = n1;
                itemNext = n2;
                cOff = p2Off;
                cLen = p2Len;
            } else if (cnt == 17) {
                bool pos64 = pos >= 64;
                uint256 want = pos64 ? 0 : _keyNibble(keyHash, pos);
                uint256 off = dataOff;
                for (uint256 i = 0; i < 16; i++) {
                    (bool cIsList, uint256 ccOff, uint256 ccLen, uint256 nxt, bool cok) = _rlp(node, off);
                    if (!cok) {
                        return false;
                    }
                    if (!pos64 && i == want) {
                        descend = true;
                        childIsList = cIsList;
                        itemStart = off;
                        itemNext = nxt;
                        cOff = ccOff;
                        cLen = ccLen;
                        pos += 1;
                        break;
                    }
                    off = nxt;
                }
                if (!descend) {
                    (bool vIsList, uint256 vOff, uint256 vLen,, bool vok) = _rlp(node, off);
                    if (!vok || vIsList) {
                        return false;
                    }
                    if (pos == 64) {
                        if (vLen == 0) {
                            return _isNull(expected);
                        }
                        return _bytesEq(node, vOff, vLen, expected);
                    }
                    return false;
                }
            } else {
                return false;
            }

            if (!childIsList && cLen == 0) {
                return _isNull(expected);
            }

            (bool dok, bytes memory child, uint256 childPtr) =
                _descend(proof, node, itemStart, itemNext, childIsList, cOff, cLen, ptr);
            if (!dok) {
                return false;
            }
            node = child;
            ptr = childPtr;
        }
        return false;
    }
}

/// @dev Encodage RLP de l'entier minimal big-endian d'une valeur de stockage.
library StorageValueRLP {
    function encode(uint256 value) internal pure returns (bytes memory out) {
        if (value == 0) {
            return hex"80";
        }
        if (value <= 0x7f) {
            out = new bytes(1);
            out[0] = bytes1(uint8(value));
            return out;
        }
        uint256 len = 0;
        uint256 v = value;
        while (v != 0) {
            len++;
            v >>= 8;
        }
        out = new bytes(1 + len);
        out[0] = bytes1(uint8(0x80 + len));
        for (uint256 i = 0; i < len; i++) {
            out[1 + i] = bytes1(uint8(value >> (8 * (len - 1 - i))));
        }
    }
}
