package c2rpc

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2block"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
)

const (
	p2pHello     = "hello"
	p2pNewBlock  = "new_block"
	p2pGetBlocks = "get_blocks"
	p2pBlocks    = "blocks"
	maxP2PFrame  = 16 << 20
)

var ErrP2PTooLarge = errors.New("c2rpc: p2p frame too large")

type p2pEnvelope struct {
	Kind    string          `json:"kind"`
	Payload json.RawMessage `json:"payload,omitempty"`
	From    uint64          `json:"from,omitempty"`
	ChainID uint64          `json:"chainId,omitempty"`
	Genesis string          `json:"genesis,omitempty"`
}

type wireTx struct {
	Type      uint8   `json:"type"`
	Nonce     uint64  `json:"nonce"`
	Gas       uint64  `json:"gas"`
	GasPrice  string  `json:"gasPrice"`
	GasTipCap string  `json:"gasTipCap"`
	GasFeeCap string  `json:"gasFeeCap"`
	From      string  `json:"from"`
	To        *string `json:"to"`
	Value     string  `json:"value"`
	Data      string  `json:"data"`
	Hash      string  `json:"hash"`
	ChainID   string  `json:"chainId"`
}

type wireHeader struct {
	ParentHash   string `json:"parentHash"`
	Coinbase     string `json:"coinbase"`
	StateRoot    string `json:"stateRoot"`
	ReceiptsRoot string `json:"receiptsRoot"`
	Number       uint64 `json:"number"`
	GasLimit     uint64 `json:"gasLimit"`
	GasUsed      uint64 `json:"gasUsed"`
	Timestamp    uint64 `json:"timestamp"`
	Extra        string `json:"extra"`
	Nonce        uint64 `json:"nonce"`
	BaseFee      string `json:"baseFee"`
	ChainID      string `json:"chainId"`
	Bloom        string `json:"bloom"`
}

type wireBlock struct {
	Hash   string     `json:"hash"`
	Header wireHeader `json:"header"`
	Txs    []wireTx   `json:"txs"`
}

type peerConn struct {
	conn net.Conn
	wch  chan []byte
}

type Node struct {
	mu     sync.Mutex
	API    *EthAPI
	Leader bool
	peers  []*peerConn
}

func NewNode(api *EthAPI, leader bool) *Node {
	if api == nil {
		api = NewEthAPI(nil)
	}
	return &Node{API: api, Leader: leader}
}

func newPeer(conn net.Conn) *peerConn {
	p := &peerConn{conn: conn, wch: make(chan []byte, 32)}
	go p.writeLoop()
	return p
}

func (p *peerConn) writeLoop() {
	for b := range p.wch {
		if err := writeP2P(p.conn, b); err != nil {
			return
		}
	}
}

func AttachPair(a, b *Node) {
	c1, c2 := net.Pipe()
	p1 := newPeer(c1)
	p2 := newPeer(c2)
	go a.readLoop(p1)
	go b.readLoop(p2)
	a.addPeer(p1)
	b.addPeer(p2)
}

func (n *Node) hello() p2pEnvelope {
	return p2pEnvelope{
		Kind:    p2pHello,
		ChainID: n.API.chainID,
		Genesis: EncodeHash(n.API.GenesisHash()),
	}
}

func (n *Node) addPeer(p *peerConn) {
	n.mu.Lock()
	n.peers = append(n.peers, p)
	n.mu.Unlock()
	_ = n.write(p, n.hello())
}

func (n *Node) write(p *peerConn, env p2pEnvelope) error {
	b, err := json.Marshal(env)
	if err != nil {
		return err
	}
	select {
	case p.wch <- b:
		return nil
	default:
		go func() { p.wch <- b }()
		return nil
	}
}

func writeP2P(w io.Writer, payload []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readP2P(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxP2PFrame {
		return nil, ErrP2PTooLarge
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (n *Node) readLoop(p *peerConn) {
	for {
		raw, err := readP2P(p.conn)
		if err != nil {
			return
		}
		var env p2pEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			continue
		}
		n.handle(p, env)
	}
}

func (n *Node) handle(p *peerConn, env p2pEnvelope) {
	switch env.Kind {
	case p2pHello:
		if env.Genesis != "" && env.Genesis != EncodeHash(n.API.GenesisHash()) {
			_ = p.conn.Close()
		}
	case p2pNewBlock:
		var wb wireBlock
		if err := json.Unmarshal(env.Payload, &wb); err != nil {
			return
		}
		sb, err := fromWire(wb)
		if err != nil {
			return
		}
		_ = n.API.ImportBlock(sb)
	case p2pGetBlocks:
		n.replyBlocks(p, env.From)
	case p2pBlocks:
		var list []wireBlock
		if err := json.Unmarshal(env.Payload, &list); err != nil {
			return
		}
		for i := range list {
			sb, err := fromWire(list[i])
			if err != nil {
				return
			}
			if err := n.API.ImportBlock(sb); err != nil {
				return
			}
		}
	}
}

func (n *Node) replyBlocks(p *peerConn, from uint64) {
	n.API.mu.Lock()
	list := make([]wireBlock, 0)
	for i := from; i < uint64(len(n.API.blocks)); i++ {
		list = append(list, toWire(n.API.blocks[i]))
	}
	n.API.mu.Unlock()
	b, err := json.Marshal(list)
	if err != nil {
		return
	}
	_ = n.write(p, p2pEnvelope{Kind: p2pBlocks, Payload: b})
}

func (n *Node) BroadcastLatest() {
	sb := n.API.Latest()
	if sb == nil || sb.Header.Number == 0 {
		return
	}
	b, err := json.Marshal(toWire(sb))
	if err != nil {
		return
	}
	n.mu.Lock()
	peers := append([]*peerConn(nil), n.peers...)
	n.mu.Unlock()
	env := p2pEnvelope{Kind: p2pNewBlock, Payload: b}
	for _, p := range peers {
		_ = n.write(p, env)
	}
}

func (n *Node) CatchUp() {
	from := n.API.Height() + 1
	n.mu.Lock()
	peers := append([]*peerConn(nil), n.peers...)
	n.mu.Unlock()
	env := p2pEnvelope{Kind: p2pGetBlocks, From: from}
	for _, p := range peers {
		_ = n.write(p, env)
	}
}

func (n *Node) Mine(ts uint64) (*SealedBlock, error) {
	sb, err := n.API.ProduceBlock(ts)
	if err != nil {
		return nil, err
	}
	n.BroadcastLatest()
	return sb, nil
}

func toWire(sb *SealedBlock) wireBlock {
	wh := wireHeader{
		ParentHash:   EncodeHash(sb.Header.ParentHash),
		Coinbase:     EncodeAddress(sb.Header.Coinbase),
		StateRoot:    EncodeHash(sb.Header.StateRoot),
		ReceiptsRoot: EncodeHash(sb.Header.ReceiptsRoot),
		Number:       sb.Header.Number,
		GasLimit:     sb.Header.GasLimit,
		GasUsed:      sb.Header.GasUsed,
		Timestamp:    sb.Header.Timestamp,
		Extra:        EncodeBytes(sb.Header.Extra),
		Nonce:        sb.Header.Nonce,
		BaseFee:      EncodeUint256(sb.Header.BaseFee),
		ChainID:      EncodeUint256(sb.Header.ChainID),
		Bloom:        EncodeBytes(sb.Header.Bloom[:]),
	}
	txs := make([]wireTx, len(sb.Txs))
	for i, tx := range sb.Txs {
		w := wireTx{
			Type:      tx.Type,
			Nonce:     tx.Nonce,
			Gas:       tx.Gas,
			GasPrice:  EncodeUint256(tx.GasPrice),
			GasTipCap: EncodeUint256(tx.GasTipCap),
			GasFeeCap: EncodeUint256(tx.GasFeeCap),
			From:      EncodeAddress(tx.From),
			Value:     EncodeUint256(tx.Value),
			Data:      EncodeBytes(tx.Data),
			Hash:      EncodeHash(tx.Hash),
			ChainID:   EncodeUint256(tx.ChainID),
		}
		if tx.To != nil {
			s := EncodeAddress(*tx.To)
			w.To = &s
		}
		txs[i] = w
	}
	return wireBlock{Hash: EncodeHash(sb.Hash), Header: wh, Txs: txs}
}

func fromWire(w wireBlock) (*SealedBlock, error) {
	h := c2block.BlockHeader{
		Number:    w.Header.Number,
		GasLimit:  w.Header.GasLimit,
		GasUsed:   w.Header.GasUsed,
		Timestamp: w.Header.Timestamp,
		Nonce:     w.Header.Nonce,
	}
	var err error
	if h.ParentHash, err = DecodeHash(w.Header.ParentHash); err != nil {
		return nil, err
	}
	if h.Coinbase, err = DecodeAddress(w.Header.Coinbase); err != nil {
		return nil, err
	}
	if h.StateRoot, err = DecodeHash(w.Header.StateRoot); err != nil {
		return nil, err
	}
	if h.ReceiptsRoot, err = DecodeHash(w.Header.ReceiptsRoot); err != nil {
		return nil, err
	}
	if w.Header.Extra != "" && w.Header.Extra != "0x" {
		if h.Extra, err = DecodeBytes(w.Header.Extra); err != nil {
			return nil, err
		}
	}
	if w.Header.BaseFee != "" {
		if h.BaseFee, err = DecodeUint256(w.Header.BaseFee); err != nil {
			return nil, err
		}
	}
	if w.Header.ChainID != "" {
		if h.ChainID, err = DecodeUint256(w.Header.ChainID); err != nil {
			return nil, err
		}
	}
	if w.Header.Bloom != "" && w.Header.Bloom != "0x" {
		b, err := DecodeBytes(w.Header.Bloom)
		if err != nil {
			return nil, err
		}
		copy(h.Bloom[:], b)
	}
	txs := make([]*c2block.Transaction, len(w.Txs))
	for i, wt := range w.Txs {
		tx, err := fromWireTx(wt)
		if err != nil {
			return nil, err
		}
		txs[i] = tx
	}
	sb := &SealedBlock{Header: h, Txs: txs}
	if w.Hash != "" {
		if sb.Hash, err = DecodeHash(w.Hash); err != nil {
			return nil, err
		}
	}
	return sb, nil
}

func fromWireTx(w wireTx) (*c2block.Transaction, error) {
	tx := &c2block.Transaction{Type: w.Type, Nonce: w.Nonce, Gas: w.Gas}
	var err error
	if tx.From, err = DecodeAddress(w.From); err != nil {
		return nil, err
	}
	if tx.Hash, err = DecodeHash(w.Hash); err != nil {
		return nil, err
	}
	if w.To != nil {
		a, err := DecodeAddress(*w.To)
		if err != nil {
			return nil, err
		}
		tx.To = &a
	}
	if w.Value != "" {
		if tx.Value, err = DecodeUint256(w.Value); err != nil {
			return nil, err
		}
	}
	if w.GasPrice != "" {
		if tx.GasPrice, err = DecodeUint256(w.GasPrice); err != nil {
			return nil, err
		}
	}
	if w.GasTipCap != "" {
		if tx.GasTipCap, err = DecodeUint256(w.GasTipCap); err != nil {
			return nil, err
		}
	}
	if w.GasFeeCap != "" {
		if tx.GasFeeCap, err = DecodeUint256(w.GasFeeCap); err != nil {
			return nil, err
		}
	}
	if w.Data != "" && w.Data != "0x" {
		if tx.Data, err = DecodeBytes(w.Data); err != nil {
			return nil, err
		}
	}
	if w.ChainID != "" {
		if tx.ChainID, err = DecodeUint256(w.ChainID); err != nil {
			return nil, err
		}
	}
	if evm256.IsZero(&tx.GasFeeCap) {
		tx.GasFeeCap = tx.GasPrice
	}
	if evm256.IsZero(&tx.GasTipCap) {
		tx.GasTipCap = tx.GasPrice
	}
	return tx, nil
}
