// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. See LICENSE and NOTICE.

package c2block

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/statetrie"
)

func TestRevertDiscardsLogs(t *testing.T) {
	st := statetrie.NewStateTrie()
	from := sender()
	fund(st, from, 10_000_000)
	c := Address{0xEE}
	putCode(st, c, mustHex(t, "5f5fa05f5ffd"))
	p := NewBlockProcessor(st)
	rec, err := p.ProcessTransaction(header(), &Transaction{
		Nonce:    0,
		GasPrice: evm256.FromU64(1),
		Gas:      100_000,
		To:       &c,
		From:     from,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != 0 {
		t.Fatalf("REVERT doit echouer, status=%d", rec.Status)
	}
	if len(rec.Logs) != 0 {
		t.Fatalf("journaux conserves apres REVERT: %d", len(rec.Logs))
	}
	var zero [256]byte
	if rec.Bloom != zero {
		t.Fatal("filtre de Bloom non nul apres REVERT")
	}
}

func TestProcessBlockAtomicity(t *testing.T) {
	st := statetrie.NewStateTrie()
	from := sender()
	fund(st, from, 1_000_000)
	to := Address{0xB2}
	other := Address{0xC3}
	p := NewBlockProcessor(st)
	h := header()
	tx1 := &Transaction{
		Nonce:    0,
		GasPrice: evm256.FromU64(1),
		Gas:      21000,
		To:       &to,
		Value:    evm256.FromU64(1000),
		From:     from,
	}
	tx2 := &Transaction{
		Nonce:    5,
		GasPrice: evm256.FromU64(1),
		Gas:      21000,
		To:       &other,
		From:     from,
	}
	_, err := p.ProcessBlock(h, []*Transaction{tx1, tx2})
	if !errors.Is(err, ErrNonce) {
		t.Fatalf("erreur attendue ErrNonce, obtenu %v", err)
	}
	fromU := addrToU256(from)
	var bal evm256.Uint256
	st.GetBalance(&fromU, &bal)
	wantBal := evm256.FromU64(1_000_000)
	if !evm256.Eq(&bal, &wantBal) {
		t.Fatalf("solde emetteur non restaure: %v", bal)
	}
	tu := addrToU256(to)
	var dest evm256.Uint256
	st.GetBalance(&tu, &dest)
	if !evm256.IsZero(&dest) {
		t.Fatalf("effet du bloc annule conserve: %v", dest)
	}
	if p.nonceOf(from) != 0 {
		t.Fatalf("nonce emetteur non restaure: %d", p.nonceOf(from))
	}
}

func TestDelegateAndCallCodeUseTargetCode(t *testing.T) {
	target := Address{0xDD}
	targetCode := mustHex(t, "600760005500")
	dcAddr := Address{0xCA}
	ccAddr := Address{0xCB}
	dc := "6000600060006000" + "73" + hex.EncodeToString(target[:]) + "61fffff400"
	cc := "60006000600060006000" + "73" + hex.EncodeToString(target[:]) + "61fffff200"

	st := statetrie.NewStateTrie()
	from := sender()
	fund(st, from, 10_000_000)
	putCode(st, target, targetCode)
	putCode(st, dcAddr, mustHex(t, dc))
	putCode(st, ccAddr, mustHex(t, cc))
	p := NewBlockProcessor(st)
	h := header()
	key := evm256.FromU64(0)

	for _, c := range []Address{dcAddr, ccAddr} {
		addr := c
		rec, err := p.ProcessTransaction(h, &Transaction{
			Nonce:    p.nonceOf(from),
			GasPrice: evm256.FromU64(1),
			Gas:      200_000,
			To:       &addr,
			From:     from,
		})
		if err != nil {
			t.Fatal(err)
		}
		if rec.Status != 1 {
			t.Fatalf("appel %x status=%d", c, rec.Status)
		}
		var got evm256.Uint256
		cu := addrToU256(c)
		st.GetStorage(&cu, &key, &got)
		wantSlot := evm256.FromU64(7)
		if !evm256.Eq(&got, &wantSlot) {
			t.Fatalf("contexte %x slot0=%v attendu 7", c, got)
		}
	}

	var tgot evm256.Uint256
	tu := addrToU256(target)
	st.GetStorage(&tu, &key, &tgot)
	if !evm256.IsZero(&tgot) {
		t.Fatalf("stockage de la cible modifie: %v", tgot)
	}
}

// TestDelegateAndCallCodePrecompiles vérifie que DELEGATECALL et CALLCODE
// exécutent le précompilé visé par l'adresse cible `to`, et non un code vide :
// le condensat SHA-256 de « abc » doit être écrit dans le stockage du contrat
// appelant, preuve que le précompilé a bien été invoqué sous son contexte.
func TestDelegateAndCallCodePrecompiles(t *testing.T) {
	dcAddr := Address{0xDA}
	ccAddr := Address{0xDB}
	dc := "62616263600052602060006003601d600261fffff45060005160005500"
	cc := "62616263600052602060006003601d6000600261fffff25060005160005500"

	st := statetrie.NewStateTrie()
	from := sender()
	fund(st, from, 10_000_000)
	putCode(st, dcAddr, mustHex(t, dc))
	putCode(st, ccAddr, mustHex(t, cc))
	p := NewBlockProcessor(st)
	h := header()
	key := evm256.FromU64(0)
	sum := sha256.Sum256([]byte("abc"))
	want := evm256.FromBytesBE(sum[:])

	for _, c := range []Address{dcAddr, ccAddr} {
		addr := c
		rec, err := p.ProcessTransaction(h, &Transaction{
			Nonce:    p.nonceOf(from),
			GasPrice: evm256.FromU64(1),
			Gas:      200_000,
			To:       &addr,
			From:     from,
		})
		if err != nil {
			t.Fatal(err)
		}
		if rec.Status != 1 {
			t.Fatalf("appel %x status=%d", c, rec.Status)
		}
		var got evm256.Uint256
		cu := addrToU256(c)
		st.GetStorage(&cu, &key, &got)
		if !evm256.Eq(&got, &want) {
			t.Fatalf("contexte %x slot0=%v attendu digest sha256=%v", c, got, want)
		}
	}
}
