// The Go reference: gorilla/websocket.
//
// The line protocol, and the shape of every answer, are ws_probe.c's: tab-
// separated `id kind split arg hex` on stdin, one `id split json` line out,
// every string hex. Five kinds. gorilla is not sans-I/O: a Conn wraps a
// net.Conn and reads and writes it itself, so the driver gives it a net.Conn
// of its own, a buffer that serves the case's bytes to Read (all at once, or
// one octet per call) and keeps what is Written. No socket, no goroutine, no
// clock: when the bytes are used up Read says EOF, which gorilla reports as an
// abnormal closure (1006), which is the answer "the input ended" (end "open").
//
// ws       Upgrader.Upgrade over the canned request, on a ResponseWriter that
//          can be hijacked and hands out that net.Conn; then NextReader in a
//          loop, with the ping, pong and close handlers wrapped to record what
//          they were given (and calling the defaults, which are what answer a
//          Ping with a Pong and a Close with its echo).
// wc       Dialer.Dial with NetDialContext returning that net.Conn, which
//          answers the client's request with the canned 101, the Sec-WebSocket-
//          Accept of the RFC's example key replaced by the one for the key the
//          Dialer drew (it draws its own and offers no way to set it), and then
//          the case's bytes.
// hs, hc   The same, for the opening handshake: Upgrade over the request head
//          (and a refusal is what its returnError wrote), Dial over the
//          response head.
//
// Things that are gorilla's and not the library's, so a disagreement is not
// misread:
//
//   - permessage-deflate: gorilla supports it "without context takeover" only
//     (its documentation: the extension is experimental). A server answers
//     any offer with server_no_context_takeover and client_no_context_takeover
//     both, ignoring the offer's other parameters; a client accepts only a
//     response that has both and ignores the rest. So a ws case whose spec has
//     permessage-deflate without client_no_context_takeover, and a wc case
//     without server_no_context_takeover, describe a connection gorilla cannot
//     be in, and the driver answers {"na":...}; diff_ws.py counts those apart
//     and refuses an "na" for any other case.
//   - Close: gorilla's default close handler echoes the code and drops the
//     reason.
//   - No UTF-8 check on text messages (the application's, by its README): the
//     driver adds none, so gorilla delivers invalid text as it is.
//   - A client offers exactly "permessage-deflate; server_no_context_takeover;
//     client_no_context_takeover" (Dialer.EnableCompression) and cannot offer
//     anything else, so an hc case with another offer answers {"na":...}.
//   - SetReadLimit is 1 MiB, the cap this library was given. gorilla counts it
//     over the octets on the wire, compressed ones included.
//
// Version: the module version is read from the binary's build info, so that
// the pin is what was compiled and not a string typed here.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	rfcKey    = "dGhlIHNhbXBsZSBub25jZQ=="
	rfcAccept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
	maxMsg    = 1 << 20
)

func hx(b []byte) string { return hex.EncodeToString(b) }

func hxo(s string, ok bool) *string {
	if !ok {
		return nil
	}
	h := hx([]byte(s))
	return &h
}

// ---- the spec ---------------------------------------------------------------

type spec struct {
	protos     []string
	d          bool
	snct, cnct bool
	smb, cmb   int
	ocmb       bool
}

func parseSpec(arg string) spec {
	var s spec
	if arg == "-" {
		return s
	}
	for _, tok := range strings.Split(arg, ";") {
		switch {
		case tok == "role=client" || tok == "role=server":
		case strings.HasPrefix(tok, "p="):
			for _, p := range strings.Split(tok[2:], ",") {
				if p != "" {
					s.protos = append(s.protos, p)
				}
			}
		case tok == "d":
			s.d = true
		case tok == "snct":
			s.snct = true
		case tok == "cnct":
			s.cnct = true
		case strings.HasPrefix(tok, "smb="):
			s.smb, _ = strconv.Atoi(tok[4:])
		case strings.HasPrefix(tok, "cmb="):
			s.cmb, _ = strconv.Atoi(tok[4:])
		case tok == "ocmb":
			s.ocmb = true
		default:
			fmt.Fprintf(os.Stderr, "unknown spec token %q\n", tok)
			os.Exit(2)
		}
	}
	return s
}

func (s spec) deflateText() string {
	t := "permessage-deflate"
	if s.snct {
		t += "; server_no_context_takeover"
	}
	if s.cnct {
		t += "; client_no_context_takeover"
	}
	if s.smb != 0 {
		t += fmt.Sprintf("; server_max_window_bits=%d", s.smb)
	}
	if s.cmb != 0 {
		t += fmt.Sprintf("; client_max_window_bits=%d", s.cmb)
	}
	return t
}

func serverRequest(s spec) []byte {
	h := "GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\n" +
		"Connection: Upgrade\r\nSec-WebSocket-Key: " + rfcKey + "\r\nSec-WebSocket-Version: 13\r\n"
	if s.d {
		h += "Sec-WebSocket-Extensions: " + s.deflateText() + "\r\n"
	}
	return []byte(h + "\r\n")
}

func clientResponse(s spec) []byte {
	h := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + rfcAccept + "\r\n"
	if s.d {
		h += "Sec-WebSocket-Extensions: " + s.deflateText() + "\r\n"
	}
	return []byte(h + "\r\n")
}

func acceptFor(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// ---- frames in what gorilla wrote ---------------------------------------------

func parseFrames(raw []byte) [][]any {
	out := [][]any{}
	i, n := 0, len(raw)
	for i+2 <= n {
		op := int(raw[i] & 15)
		masked := raw[i+1]&0x80 != 0
		ln := uint64(raw[i+1] & 0x7f)
		at := i + 2
		if ln == 126 {
			if at+2 > n {
				break
			}
			ln = uint64(binary.BigEndian.Uint16(raw[at:]))
			at += 2
		} else if ln == 127 {
			if at+8 > n {
				break
			}
			ln = binary.BigEndian.Uint64(raw[at:])
			at += 8
		}
		var key [4]byte
		if masked {
			if at+4 > n {
				break
			}
			copy(key[:], raw[at:at+4])
			at += 4
		}
		if ln > uint64(n-at) {
			break
		}
		body := make([]byte, ln)
		for k := range body {
			body[k] = raw[at+k] ^ key[k%4]
		}
		out = append(out, []any{op, hx(body)})
		i = at + int(ln)
	}
	return out
}

// ---- the net.Conn -----------------------------------------------------------------

type conn struct {
	in       []byte
	byteWise bool
	out      bytes.Buffer
	mark     int // what was Written before this is the handshake
	respond  func(request []byte) []byte
	started  bool
}

func (c *conn) Read(p []byte) (int, error) {
	if c.respond != nil && !c.started {
		c.started = true
		c.mark = c.out.Len()
		c.in = append(c.respond(c.out.Bytes()), c.in...)
	}
	if len(c.in) == 0 {
		return 0, io.EOF
	}
	n := len(c.in)
	if c.byteWise {
		n = 1
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, c.in[:n])
	c.in = c.in[n:]
	return n, nil
}

func (c *conn) Write(p []byte) (int, error)        { return c.out.Write(p) }
func (c *conn) Close() error                       { return nil }
func (c *conn) LocalAddr() net.Addr                { return addr{} }
func (c *conn) RemoteAddr() net.Addr               { return addr{} }
func (c *conn) SetDeadline(time.Time) error        { return nil }
func (c *conn) SetReadDeadline(time.Time) error    { return nil }
func (c *conn) SetWriteDeadline(time.Time) error   { return nil }

type addr struct{}

func (addr) Network() string { return "buffer" }
func (addr) String() string  { return "ref-gows" }

// hijackable is the ResponseWriter Upgrade needs: it records what a refusal
// wrote, and hands out the net.Conn.
type hijackable struct {
	c      *conn
	status int
	header http.Header
	body   bytes.Buffer
}

func (w *hijackable) Header() http.Header         { return w.header }
func (w *hijackable) Write(p []byte) (int, error) { return w.body.Write(p) }
func (w *hijackable) WriteHeader(code int)        { w.status = code }
func (w *hijackable) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.c, bufio.NewReadWriter(bufio.NewReader(w.c), bufio.NewWriter(w.c)), nil
}

// ---- ws and wc ----------------------------------------------------------------------

type stream struct {
	Evs  [][]any `json:"evs"`
	Sent [][]any `json:"sent"`
	End  string  `json:"end"`
	Fail string  `json:"fail"`
	Err  string  `json:"err"`
	Na   string  `json:"na,omitempty"`
}

func na(why string) stream {
	return stream{Evs: [][]any{}, Sent: [][]any{}, End: "open", Na: why}
}

func runStream(client bool, split, arg string, data []byte) (res stream) {
	s := parseSpec(arg)
	if s.d && ((!client && !s.cnct) || (client && !s.snct)) {
		return na("gorilla/websocket does permessage-deflate without context takeover only")
	}
	res = stream{Evs: [][]any{}, Sent: [][]any{}, End: "open"}
	defer func() {
		if e := recover(); e != nil {
			res.End = "failed"
			res.Err = hx([]byte(fmt.Sprintf("panic: %v", e)))
		}
	}()
	cn := &conn{in: data, byteWise: split == "byte"}
	var c *websocket.Conn
	if client {
		// gorilla's client accepts a response only if it names both
		// no_context_takeover parameters (client.go), so that is what the
		// canned response says; the spec's own parameters are for the others.
		resp := s
		if resp.d {
			resp.snct, resp.cnct, resp.smb, resp.cmb = true, true, 0, 0
		}
		cn.respond = func([]byte) []byte { return rewriteAccept(clientResponse(resp), cn.out.Bytes()) }
		d := websocket.Dialer{
			NetDialContext:    func(context.Context, string, string) (net.Conn, error) { return cn, nil },
			EnableCompression: s.d,
		}
		var err error
		c, _, err = d.Dial("ws://server.example.com/chat", nil)
		if err != nil {
			res.End = "failed"
			res.Err = hx([]byte("the handshake failed: " + err.Error()))
			return res
		}
	} else {
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(serverRequest(s))))
		if err != nil {
			panic(err)
		}
		w := &hijackable{c: cn, header: http.Header{}}
		up := websocket.Upgrader{
			CheckOrigin:       func(*http.Request) bool { return true },
			EnableCompression: s.d,
		}
		c, err = up.Upgrade(w, req, nil)
		if err != nil {
			res.End = "failed"
			res.Err = hx([]byte("the handshake was refused: " + err.Error()))
			return res
		}
		cn.mark = cn.out.Len()
	}
	if s.d && !strings.Contains(strings.ToLower(string(cn.out.Bytes())), "permessage-deflate") && !client {
		panic("gorilla did not negotiate permessage-deflate")
	}
	c.SetReadLimit(maxMsg)
	closed := false
	pingDefault, closeDefault := c.PingHandler(), c.CloseHandler()
	c.SetPingHandler(func(m string) error {
		res.Evs = append(res.Evs, []any{"ping", hx([]byte(m)), nil})
		return pingDefault(m)
	})
	c.SetPongHandler(func(m string) error {
		res.Evs = append(res.Evs, []any{"pong", hx([]byte(m)), nil})
		return nil
	})
	c.SetCloseHandler(func(code int, text string) error {
		closed = true
		res.Evs = append(res.Evs, []any{"close", hx([]byte(text)), code})
		return closeDefault(code, text)
	})
	for {
		mt, r, err := c.NextReader()
		if err == nil {
			var msg []byte
			msg, err = io.ReadAll(r)
			if err == nil {
				kind := "text"
				if mt == websocket.BinaryMessage {
					kind = "binary"
				}
				res.Evs = append(res.Evs, []any{kind, hx(msg), nil})
				continue
			}
		}
		var ce *websocket.CloseError
		switch {
		case closed:
			res.End = "closed"
		case errors.As(err, &ce) && ce.Code == websocket.CloseAbnormalClosure:
			res.End = "open" // the input ended: EOF is what gorilla calls 1006
		default:
			res.End = "failed"
			res.Fail = hx([]byte(err.Error()))
		}
		break
	}
	written := cn.out.Bytes()
	res.Sent = parseFrames(written[cn.mark:])
	return res
}

// rewriteAccept puts the accept value of the key the Dialer drew where the
// canned response has the RFC example's.
func rewriteAccept(resp, request []byte) []byte {
	for _, line := range strings.Split(string(request), "\r\n") {
		if i := strings.Index(strings.ToLower(line), "sec-websocket-key:"); i == 0 {
			key := strings.TrimSpace(line[len("sec-websocket-key:"):])
			return bytes.ReplaceAll(resp, []byte(rfcAccept), []byte(acceptFor(key)))
		}
	}
	return resp
}

// ---- hs ---------------------------------------------------------------------------------

type hsAnswer struct {
	Status     int     `json:"status"`
	Accept     *string `json:"accept"`
	Protocol   *string `json:"protocol"`
	Extensions *string `json:"extensions"`
	ParseError bool    `json:"parse_error"`
	Err        string  `json:"err"`
}

func headOf(raw []byte) (int, http.Header) {
	r, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), nil)
	if err != nil {
		return 0, http.Header{}
	}
	return r.StatusCode, r.Header
}

func runHS(arg string, data []byte) (ans hsAnswer) {
	s := parseSpec(arg)
	ans = hsAnswer{}
	defer func() {
		if e := recover(); e != nil {
			ans = hsAnswer{Status: 500, Err: hx([]byte(fmt.Sprintf("panic: %v", e)))}
		}
	}()
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(data)))
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return ans // the head never ended
		}
		ans.Status = 400
		ans.ParseError = true
		ans.Err = hx([]byte(err.Error()))
		return ans
	}
	cn := &conn{}
	w := &hijackable{c: cn, header: http.Header{}}
	up := websocket.Upgrader{
		CheckOrigin:       func(*http.Request) bool { return true },
		EnableCompression: s.d,
		Subprotocols:      s.protos,
	}
	_, err = up.Upgrade(w, req, nil)
	if err != nil {
		ans.Status = w.status
		ans.Err = hx([]byte(err.Error()))
		return ans
	}
	status, h := headOf(cn.out.Bytes())
	ans.Status = status
	ans.Accept = hxo(h.Get("Sec-WebSocket-Accept"), h.Get("Sec-WebSocket-Accept") != "")
	ans.Protocol = hxo(h.Get("Sec-WebSocket-Protocol"), h.Get("Sec-WebSocket-Protocol") != "")
	ans.Extensions = hxo(h.Get("Sec-WebSocket-Extensions"), h.Get("Sec-WebSocket-Extensions") != "")
	return ans
}

// ---- hc ---------------------------------------------------------------------------------

type hcAnswer struct {
	Accepted   bool           `json:"accepted"`
	Protocol   *string        `json:"protocol"`
	Deflate    map[string]int `json:"deflate"`
	ParseError bool           `json:"parse_error"`
	Err        string         `json:"err"`
	Na         string         `json:"na,omitempty"`
}

func runHC(arg string, data []byte) (ans hcAnswer) {
	s := parseSpec(arg)
	ans = hcAnswer{}
	if s.d && !(s.snct && s.cnct && s.smb == 0 && s.cmb == 0 && !s.ocmb) {
		// A Dialer with EnableCompression offers exactly
		// "permessage-deflate; server_no_context_takeover; client_no_context_takeover"
		// and nothing else can be offered; a case with another offer describes
		// a client gorilla cannot be.
		return hcAnswer{Na: "gorilla/websocket offers only permessage-deflate with both no_context_takeover parameters"}
	}
	defer func() {
		if e := recover(); e != nil {
			ans = hcAnswer{Err: hx([]byte(fmt.Sprintf("panic: %v", e)))}
		}
	}()
	cn := &conn{}
	cn.respond = func(request []byte) []byte { return rewriteAccept(data, request) }
	d := websocket.Dialer{
		NetDialContext:    func(context.Context, string, string) (net.Conn, error) { return cn, nil },
		Subprotocols:      s.protos,
		EnableCompression: s.d,
	}
	c, _, err := d.Dial("ws://server.example.com/chat", nil)
	if err != nil {
		ans.Err = hx([]byte(err.Error()))
		// A response http.ReadResponse could not read is the parse error.
		ans.ParseError = !errors.Is(err, websocket.ErrBadHandshake) && !strings.Contains(err.Error(), "bad status") &&
			!strings.Contains(err.Error(), "invalid compression")
		return ans
	}
	ans.Accepted = true
	if p := c.Subprotocol(); p != "" {
		h := hx([]byte(p))
		ans.Protocol = &h
	}
	// newDecompressionReader is unexported, and set exactly when the client
	// accepted the extension (client.go); reading it is the only way to ask.
	if !reflect.ValueOf(c).Elem().FieldByName("newDecompressionReader").IsNil() {
		// gorilla negotiates only this, whatever else the response said.
		ans.Deflate = map[string]int{"snct": 1, "cnct": 1, "smb": 0, "cmb": 0}
	}
	return ans
}

// ---- main ---------------------------------------------------------------------------------

func version() string {
	v := "unknown"
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/gorilla/websocket" {
				v = d.Version
			}
		}
	}
	return fmt.Sprintf("gorilla/websocket %s (%s)", v, runtime.Version())
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println(version())
		return
	}
	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for {
		line, err := in.ReadString('\n')
		if len(line) > 0 {
			f := strings.Split(strings.TrimRight(line, "\n"), "\t")
			if len(f) != 5 {
				fmt.Fprintf(os.Stderr, "a case needs five tab-separated fields: %q\n", line)
				os.Exit(2)
			}
			data, derr := hex.DecodeString(f[4])
			if derr != nil {
				fmt.Fprintln(os.Stderr, "bad hex")
				os.Exit(2)
			}
			var res any
			switch f[1] {
			case "ws":
				res = runStream(false, f[2], f[3], data)
			case "wc":
				res = runStream(true, f[2], f[3], data)
			case "hs":
				res = runHS(f[3], data)
			case "hc":
				res = runHC(f[3], data)
			default:
				fmt.Fprintf(os.Stderr, "unknown kind %q\n", f[1])
				os.Exit(2)
			}
			js, _ := json.Marshal(res)
			fmt.Fprintf(out, "%s\t%s\t%s\n", f[0], f[2], js)
			out.Flush()
		}
		if err != nil {
			break
		}
	}
}
