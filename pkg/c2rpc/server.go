package c2rpc

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode"
)

const (
	wsGUID     = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	maxRPCBody = 32 << 20
	maxWSFrame = 16 << 20
)

type Server struct {
	API  *EthAPI
	HTTP *http.Server
}

func NewServer(api *EthAPI) *Server {
	if api == nil {
		api = NewEthAPI(nil)
	}
	return &Server{API: api}
}

func (s *Server) ListenAndServe(addr string) error {
	s.HTTP = &http.Server{
		Addr:              addr,
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s.HTTP.ListenAndServe()
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		s.serveWS(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRPCBody+1))
	if err != nil {
		s.writeJSON(w, marshalParse(nil))
		return
	}
	if len(body) > maxRPCBody {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	out := s.Dispatch(body)
	if len(out) == 0 {
		w.WriteHeader(http.StatusOK)
		return
	}
	s.writeJSON(w, out)
}

func (s *Server) writeJSON(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) Dispatch(body []byte) []byte {
	body = trimSpace(body)
	if len(body) == 0 {
		return marshalParse(nil)
	}
	if body[0] == '[' {
		return s.dispatchBatch(body)
	}
	if body[0] != '{' {
		return marshalParse(nil)
	}
	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		return marshalParse(nil)
	}
	resp := s.serveOne(&req)
	if resp == nil {
		return nil
	}
	b, err := json.Marshal(resp)
	if err != nil {
		return marshalParse(req.ID)
	}
	return b
}

func trimSpace(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && unicode.IsSpace(rune(b[i])) {
		i++
	}
	for j > i && unicode.IsSpace(rune(b[j-1])) {
		j--
	}
	return b[i:j]
}

func marshalParse(id json.RawMessage) []byte {
	b, _ := json.Marshal(Response{
		JSONRPC: "2.0",
		Error:   rpcErr(CodeParse, "parse error"),
		ID:      id,
	})
	return b
}

func (s *Server) dispatchBatch(body []byte) []byte {
	var reqs []Request
	if err := json.Unmarshal(body, &reqs); err != nil {
		return marshalParse(nil)
	}
	if len(reqs) == 0 {
		b, _ := json.Marshal(Response{
			JSONRPC: "2.0",
			Error:   rpcErr(CodeInvalidReq, "empty batch"),
			ID:      nil,
		})
		return b
	}
	out := make([]Response, 0, len(reqs))
	for i := range reqs {
		resp := s.serveOne(&reqs[i])
		if resp == nil {
			continue
		}
		out = append(out, *resp)
	}
	if len(out) == 0 {
		return nil
	}
	b, err := json.Marshal(out)
	if err != nil {
		return marshalParse(nil)
	}
	return b
}

func (s *Server) serveOne(req *Request) *Response {
	if len(req.ID) == 0 {
		if req.JSONRPC == "2.0" && req.Method != "" {
			_, _ = s.API.Handle(req.Method, req.Params)
		}
		return nil
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		return &Response{
			JSONRPC: "2.0",
			Error:   rpcErr(CodeInvalidReq, "invalid request"),
			ID:      req.ID,
		}
	}
	res, err := s.API.Handle(req.Method, req.Params)
	if err != nil {
		return &Response{JSONRPC: "2.0", Error: err, ID: req.ID}
	}
	return &Response{JSONRPC: "2.0", Result: res, ID: req.ID}
}

func wsAccept(key string) string {
	sum := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func (s *Server) serveWS(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "missing websocket key", http.StatusBadRequest)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	_, _ = bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	_, _ = bufrw.WriteString("Upgrade: websocket\r\n")
	_, _ = bufrw.WriteString("Connection: Upgrade\r\n")
	_, _ = bufrw.WriteString("Sec-WebSocket-Accept: " + wsAccept(key) + "\r\n\r\n")
	if err := bufrw.Flush(); err != nil {
		return
	}
	for {
		op, payload, err := readWSFrame(bufrw)
		if err != nil {
			return
		}
		switch op {
		case 0x8:
			_ = writeWSFrame(bufrw, 0x8, payload)
			_ = bufrw.Flush()
			return
		case 0x9:
			_ = writeWSFrame(bufrw, 0xA, payload)
			_ = bufrw.Flush()
		case 0xA:
		case 0x1, 0x2:
			out := s.Dispatch(payload)
			if len(out) == 0 {
				continue
			}
			if err := writeWSFrame(bufrw, 0x1, out); err != nil {
				return
			}
			if err := bufrw.Flush(); err != nil {
				return
			}
		default:
			return
		}
	}
}

func readWSFrame(r io.Reader) (byte, []byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	op := hdr[0] & 0x0f
	masked := hdr[1]&0x80 != 0
	n := uint64(hdr[1] & 0x7f)
	switch n {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		n = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		n = binary.BigEndian.Uint64(ext[:])
	}
	if n > maxWSFrame {
		return 0, nil, io.ErrUnexpectedEOF
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(r, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i&3]
		}
	}
	return op, payload, nil
}

func writeWSFrame(w io.Writer, op byte, payload []byte) error {
	n := len(payload)
	var hdr []byte
	hdr = append(hdr, 0x80|op)
	switch {
	case n < 126:
		hdr = append(hdr, byte(n))
	case n <= 0xffff:
		hdr = append(hdr, 126, byte(n>>8), byte(n))
	default:
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		hdr = append(hdr, 127)
		hdr = append(hdr, ext[:]...)
	}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}
