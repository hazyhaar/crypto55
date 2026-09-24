// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. See LICENSE and NOTICE.

package c2torture

import (
	"bytes"
	"reflect"
	"testing"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2block"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2crypto"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2seq"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/statetrie"
)

// Ce fichier rejoue de bout en bout un lot Brotli L2 réellement produit par le
// séquenceur c2seq du dépôt : Pack (Brotli L2) -> BrotliL2Decompress ->
// Unpack (séquençage) -> BlockReplayer.Replay (transition de bloc) ->
// validation bit-exacte de la racine d'état, des receipts et du bloom.
//
// Aucun lot Arbitrum One authentique n'est embarqué : l'espace de travail n'en
// contient aucun, et le format de bordure L1 de Nitro (sélecteur d'appel,
// préfixe de compression, enveloppe de lot) n'est pas implémenté par
// c2seq.BatchPoster. Le harnais vérifie donc la chaîne réelle
// Brotli -> séquençage -> transition sur les octets que le dépôt sait
// réellement produire et consommer, sans rebaptiser ces octets « lot Arbitrum ».

const arbtestGasLimit = uint64(30_000_000)

func arbtestBatchContracts() (sstoreCode, logCode []byte) {
	// PUSH1 42; PUSH1 1; SSTORE; STOP.
	sstoreCode = []byte{0x60, 0x2a, 0x60, 0x01, 0x55, 0x00}
	// PUSH32 topic; PUSH1 0 (taille); PUSH1 0 (offset); LOG1; STOP.
	topic := make([]byte, 32)
	topic[0], topic[1] = 0xde, 0xad
	logCode = append([]byte{0x7f}, topic...)
	logCode = append(logCode, 0x60, 0x00, 0x60, 0x00, 0xa1, 0x00)
	return
}

func arbtestSeed(senderA, senderB, contractA, contractB c2block.Address, sstoreCode, logCode []byte) *statetrie.StateTrie {
	st := statetrie.NewStateTrie()
	fund(st, senderA, 1_000_000)
	fund(st, senderB, 1_000_000)
	putCode(st, contractA, sstoreCode)
	putCode(st, contractB, logCode)
	return st
}

func arbtestTxs(senderA, senderB, contractA, contractB c2block.Address) []*c2block.Transaction {
	price := evm256.FromU64(1)
	return []*c2block.Transaction{
		{
			Type: c2block.TxLegacy, Nonce: 0, Gas: 100_000,
			GasPrice: price, GasTipCap: price, GasFeeCap: price,
			To: &contractA, From: senderA, Hash: c2block.Hash{0xaa},
		},
		{
			Type: c2block.TxLegacy, Nonce: 0, Gas: 100_000,
			GasPrice: price, GasTipCap: price, GasFeeCap: price,
			To: &contractB, From: senderB, Hash: c2block.Hash{0xbb},
		},
	}
}

func TestLocalBatchReplayBitExact(t *testing.T) {
	senderA := c2block.Address{0x11}
	senderB := c2block.Address{0x12}
	contractA := c2block.Address{0x22}
	contractB := c2block.Address{0x33}
	sstoreCode, logCode := arbtestBatchContracts()
	seed := func() *statetrie.StateTrie {
		return arbtestSeed(senderA, senderB, contractA, contractB, sstoreCode, logCode)
	}
	txs := arbtestTxs(senderA, senderB, contractA, contractB)
	header := func() *c2block.BlockHeader {
		return &c2block.BlockHeader{
			GasLimit: arbtestGasLimit, Number: 1, Timestamp: 1,
			Coinbase: c2block.Address{0xc0},
		}
	}

	// 1. Compression L2 réelle par le séquenceur.
	poster := c2seq.NewBatchPoster()
	packed, err := poster.Pack(txs)
	if err != nil {
		t.Fatal(err)
	}
	if len(packed) == 0 {
		t.Fatal("lot Brotli vide")
	}

	// 2. Décompression par la primitive c2crypto.
	plain := make([]byte, 512*1024)
	n, err := c2crypto.BrotliL2Decompress(packed, plain)
	if err != nil {
		t.Fatalf("BrotliL2Decompress: %v", err)
	}
	if n <= 0 || n > len(plain) {
		t.Fatalf("longueur décompressée=%d", n)
	}
	decompressed := plain[:n]
	if decompressed[0] < 0xc0 {
		t.Fatalf("le flux décompressé n'est pas une liste RLP: 0x%02x", decompressed[0])
	}
	if bytes.Equal(decompressed, packed) {
		t.Fatal("le décodeur a recopié l'entrée au lieu de décompresser")
	}

	// 3. Dépaquetage des transactions séquencées.
	unpacked, err := poster.Unpack(packed)
	if err != nil {
		t.Fatal(err)
	}
	if len(unpacked) != len(txs) {
		t.Fatalf("transactions dépaquetées=%d attendu=%d", len(unpacked), len(txs))
	}
	for i := range txs {
		want := *txs[i]
		want.V, want.R, want.S = evm256.Uint256{}, evm256.Uint256{}, evm256.Uint256{}
		if !reflect.DeepEqual(*unpacked[i], want) {
			t.Fatalf("tx %d: champs d'exécution altérés\n obtenu=%+v\n attendu=%+v", i, unpacked[i], &want)
		}
	}

	// 4. Référence : transition de bloc directe sur état frais.
	refState := seed()
	refRes, err := c2block.NewBlockProcessor(refState).ProcessBlock(header(), unpacked)
	if err != nil {
		t.Fatal(err)
	}
	if len(refRes.Receipts) != 2 {
		t.Fatalf("reçus de référence=%d", len(refRes.Receipts))
	}
	if refRes.Bloom == ([256]byte{}) {
		t.Fatal("le bloom de référence est vide alors qu'un LOG1 a été émis")
	}
	if got := storageAt(refState, contractA, 1); got != evm256.FromU64(42) {
		t.Fatalf("SSTORE non appliqué: %x", evm256.BytesBE(got))
	}

	// 5. Replay via BlockReplayer, sur le même lot dépaqueté.
	replay, err := NewBlockReplayer(seed()).Replay(BlockReplaySpec{
		Header:       header(),
		Transactions: unpacked,
		Expected: ExpectedTransitionResult{
			StateRoot:    [32]byte(refRes.StateRoot),
			ReceiptsRoot: [32]byte(refRes.ReceiptsRoot),
			GasUsed:      refRes.GasUsed,
			Bloom:        refRes.Bloom,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !replay.OK {
		t.Fatalf("replay non bit-exact: %v", replay.Mismatches)
	}
	if replay.StateRoot != [32]byte(refRes.StateRoot) ||
		replay.ReceiptsRoot != [32]byte(refRes.ReceiptsRoot) ||
		replay.GasUsed != refRes.GasUsed ||
		replay.Bloom != refRes.Bloom {
		t.Fatal("identité de transition rompue malgré OK")
	}

	// 6. Sentinelles d'intégrité : chaque attente falsifiée doit être détectée.
	// 6.a Racine d'état falsifiée
	tamperedState := refRes.StateRoot
	tamperedState[0] ^= 0x01
	badState, err := NewBlockReplayer(seed()).Replay(BlockReplaySpec{
		Header:       header(),
		Transactions: unpacked,
		Expected: ExpectedTransitionResult{
			StateRoot:    [32]byte(tamperedState),
			ReceiptsRoot: [32]byte(refRes.ReceiptsRoot),
			GasUsed:      refRes.GasUsed,
			Bloom:        refRes.Bloom,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if badState.OK {
		t.Fatal("une racine d'état falsifiée a été acceptée")
	}

	// 6.b Racine des reçus falsifiée
	tamperedReceipts := refRes.ReceiptsRoot
	tamperedReceipts[0] ^= 0x01
	badReceipts, err := NewBlockReplayer(seed()).Replay(BlockReplaySpec{
		Header:       header(),
		Transactions: unpacked,
		Expected: ExpectedTransitionResult{
			StateRoot:    [32]byte(refRes.StateRoot),
			ReceiptsRoot: [32]byte(tamperedReceipts),
			GasUsed:      refRes.GasUsed,
			Bloom:        refRes.Bloom,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if badReceipts.OK {
		t.Fatal("une racine des reçus falsifiée a été acceptée")
	}

	// 6.c Bloom des logs falsifié
	tamperedBloom := refRes.Bloom
	tamperedBloom[0] ^= 0x01
	badBloom, err := NewBlockReplayer(seed()).Replay(BlockReplaySpec{
		Header:       header(),
		Transactions: unpacked,
		Expected: ExpectedTransitionResult{
			StateRoot:    [32]byte(refRes.StateRoot),
			ReceiptsRoot: [32]byte(refRes.ReceiptsRoot),
			GasUsed:      refRes.GasUsed,
			Bloom:        tamperedBloom,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if badBloom.OK {
		t.Fatal("un Bloom falsifié a été accepté")
	}

	// 6.d Gaz consommé falsifié
	badGas, err := NewBlockReplayer(seed()).Replay(BlockReplaySpec{
		Header:       header(),
		Transactions: unpacked,
		Expected: ExpectedTransitionResult{
			StateRoot:    [32]byte(refRes.StateRoot),
			ReceiptsRoot: [32]byte(refRes.ReceiptsRoot),
			GasUsed:      refRes.GasUsed + 1,
			Bloom:        refRes.Bloom,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if badGas.OK {
		t.Fatal("un gaz consommé falsifié a été accepté")
	}
}

// TestArbitrumBatchBrotliIntegrity vérifie que le décodeur refuse un flux
// tronqué ou corrompu au lieu de rendre silencieusement un lot partiel.
func TestArbitrumBatchBrotliIntegrity(t *testing.T) {
	txs := arbtestTxs(
		c2block.Address{0x11}, c2block.Address{0x12},
		c2block.Address{0x22}, c2block.Address{0x33},
	)
	packed, err := c2seq.NewBatchPoster().Pack(txs)
	if err != nil {
		t.Fatal(err)
	}

	// Cas 1 : troncature à -1 octet
	truncated1 := packed[:len(packed)-1]
	if _, err := c2seq.NewBatchPoster().Unpack(truncated1); err == nil {
		t.Fatal("un lot Brotli tronqué à -1 octet a été accepté")
	}

	// Cas 2 : troncature à mi-flux
	truncatedHalf := packed[:len(packed)/2]
	if _, err := c2seq.NewBatchPoster().Unpack(truncatedHalf); err == nil {
		t.Fatal("un lot Brotli tronqué à mi-flux a été accepté")
	}

	// Cas 3 : troncature agressive (2 octets)
	truncatedShort := packed[:2]
	if _, err := c2seq.NewBatchPoster().Unpack(truncatedShort); err == nil {
		t.Fatal("un lot Brotli de 2 octets a été accepté")
	}

	// Cas 4 : altération de l'en-tête Brotli (rejet mécanique au déballage)
	corruptedHeader := append([]byte(nil), packed...)
	corruptedHeader[0] ^= 0xff
	if _, err := c2seq.NewBatchPoster().Unpack(corruptedHeader); err == nil {
		t.Fatal("un lot Brotli avec en-tête altéré a été accepté")
	}

	// Cas 5 : altération du payload au cœur du flux (la dérivation ne doit pas reproduire la suite originale)
	corruptedPayload := append([]byte(nil), packed...)
	corruptedPayload[len(corruptedPayload)/2] ^= 0xff
	if alteredTxs, err := c2seq.NewBatchPoster().Unpack(corruptedPayload); err == nil {
		if reflect.DeepEqual(alteredTxs, txs) {
			t.Fatal("un lot au payload altéré ne doit pas restituer les transactions originales")
		}
	}
}
