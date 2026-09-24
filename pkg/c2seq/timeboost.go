// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 HazyHaar. See LICENSE and NOTICE.

package c2seq

import (
	"errors"
	"sync"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2block"
)

const (
	DefaultExpressWindow = 60
	MaxExpressQueue      = 1024
)

var (
	ErrExpressWindow = errors.New("c2seq: express lane window closed")
	ErrExpressFull   = errors.New("c2seq: express lane full")
)

type expressItem struct {
	tx       *c2block.Transaction
	deadline uint64
}

type Timeboost struct {
	mu     sync.Mutex
	window uint64
	items  []expressItem
}

func NewTimeboost(window uint64) *Timeboost {
	if window == 0 {
		window = DefaultExpressWindow
	}
	return &Timeboost{window: window}
}

func (t *Timeboost) Window() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.window
}

func (t *Timeboost) PushExpress(tx *c2block.Transaction, now uint64) error {
	if tx == nil {
		return ErrNilTx
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.items) >= MaxExpressQueue {
		return ErrExpressFull
	}
	dl, err := SafeAddGas(now, t.window)
	if err != nil {
		dl = ^uint64(0)
	}
	t.items = append(t.items, expressItem{tx: tx, deadline: dl})
	return nil
}

func (t *Timeboost) Drain(now uint64) []*c2block.Transaction {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.items) == 0 {
		return nil
	}
	var out []*c2block.Transaction
	keep := t.items[:0]
	for _, it := range t.items {
		if now > it.deadline {
			continue
		}
		out = append(out, it.tx)
	}
	t.items = keep
	return out
}

func (t *Timeboost) Count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.items)
}
