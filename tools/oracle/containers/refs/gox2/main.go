// The Go HTTP/2 reference: golang.org/x/net/http2's server and its HPACK.
//
// A server-side ingest harness, same protocol as the other h2 drivers:
// tab-separated `id kind split arg hex` on stdin, one `id split json` line
// out, every string hex. Three kinds:
//
//	h2  the case bytes are a client's whole byte stream (preface included);
//	    http2.Server.ServeConn reads them over a conn of our own and the
//	    handler records every request it is given. What the server sent back
//	    is parsed afterwards for RST_STREAM and GOAWAY, which is how "resets"
//	    and "conn_error" are read: Go reports neither through an API.
//	hd  hpack.Decoder on one header block, no HTTP-level validation.
//	he  hpack.Encoder on a blob of fields, default policy.
//
// Things that are Go's and not the library's, so a disagreement is not
// misread:
//
//   - The handler sees net/http's Request, not frames. Go canonicalises
//     header names and keeps no order across names, so headers are listed in
//     name order (names lower-cased back; order within a name kept). Host,
//     the pseudo-headers and Cookie are whatever Go made of them: method is
//     r.Method, authority r.Host, path r.RequestURI, scheme r.URL.Scheme.
//   - The stream id is not exposed either; it is read from the response
//     writer's unexported rws.stream.id by reflection. That is tied to the
//     pinned module version, and falls back to 0 if the layout changes (the
//     image's --version line names the version that was measured).
//   - The validation (pseudo-headers, upper-case names, connection-specific
//     fields, te, content-length against DATA) is Go's own in its frame
//     reader, processHeaders and newWriterAndRequest. Nothing is added here.
//   - The listener's settings are set to what the shared spec advertises:
//     MAX_HEADER_LIST_SIZE is MaxHeaderBytes plus the 320 Go adds, so
//     65216 advertises 65536, and the per-stream upload buffer is 65535
//     because that is also the INITIAL_WINDOW_SIZE Go advertises. The
//     per-connection buffer is left at Go's default (1 MiB: Go raises the
//     connection window with a WINDOW_UPDATE right after its SETTINGS).
//
// The input is a complete byte string, but Go reads from a live connection
// and stops serving at EOF, handlers included. So the conn serves the bytes,
// waits until the server has gone quiet (settle: nothing written, no handler
// started or finished, for a few milliseconds; the reader only asks for more
// input after the serve loop has taken every frame it was given, so a quiet
// server has processed everything), then says EOF, which cancels any handler
// still waiting for a body, and waits again for those to record what they had.
// The waits are a quiet period, not a clock the answer depends on.
//
// Go can also PANIC in a goroutine of its own that no recover here can reach:
// golang.org/x/net v0.50.0 indexes an array of frame parsers by frame type
// with holes at 0x0a-0x0f, so a peer's frame of one of those types (ALTSVC
// 0x0a and ORIGIN 0x0c among them) is a nil function call and ends the whole
// process. So main is a supervisor: it runs the worker (this binary with
// --worker) one case at a time, and when the worker dies it answers that case
// with err "PROCESS CRASH: ..." and starts another. diff_h2.py reads that as
// the reference failing, which is the truth about it.
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type msg struct {
	Stream    uint32      `json:"stream"`
	Method    *string     `json:"method"`
	Scheme    *string     `json:"scheme"`
	Authority *string     `json:"authority"`
	Path      *string     `json:"path"`
	Headers   [][2]string `json:"headers"`
	Body      string      `json:"body"`
	Trailers  [][2]string `json:"trailers"`
	Ended     bool        `json:"ended"`
}

type h2result struct {
	Msgs      []msg      `json:"msgs"`
	Resets    [][2]int64 `json:"resets"`
	ConnError *uint32    `json:"conn_error"`
	// Answers are the error responses Go itself wrote, status 400 and up (the
	// handler only ever gives 200): a malformed request is answered 400, not
	// reset. [stream, status].
	Answers [][2]int64 `json:"answers"`
	Closed  bool       `json:"closed"`
	Err       string     `json:"err"`
}

func hx(s string) string { return hex.EncodeToString([]byte(s)) }

func hxp(s string, ok bool) *string {
	if !ok {
		return nil
	}
	h := hx(s)
	return &h
}

// fields lists a header map in name order; Go keeps no order across names.
func fields(h http.Header) [][2]string {
	names := make([]string, 0, len(h))
	for k := range h {
		names = append(names, k)
	}
	sort.Strings(names)
	out := [][2]string{}
	for _, k := range names {
		for _, v := range h[k] {
			out = append(out, [2]string{hx(strings.ToLower(k)), hx(v)})
		}
	}
	return out
}

// streamID reads the stream's id out of http2's unexported responseWriter.
func streamID(w http.ResponseWriter) (id uint32) {
	defer func() {
		if recover() != nil {
			id = 0
		}
	}()
	v := reflect.ValueOf(w).Elem().FieldByName("rws").Elem().
		FieldByName("stream").Elem().FieldByName("id")
	return uint32(v.Uint())
}

// bufConn serves the case bytes to Read and collects what is Written.
type bufConn struct {
	mu       sync.Mutex
	in       []byte
	eof      int32 // set when this conn said EOF: after that, the server closing is no surprise
	byteWise bool
	out      bytes.Buffer
	acts     int64 // counts Writes, Reads and handler events: the server being busy
}

func (c *bufConn) Read(p []byte) (int, error) {
	atomic.AddInt64(&c.acts, 1)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.in) == 0 {
		// The input is used up. A real peer would simply have nothing more to
		// say for now, not hang up: an EOF at once would end the serve loop
		// before it had flushed what it had queued (a GOAWAY for a flow-control
		// overflow is queued, and written after the loop's next turn, which an
		// EOF pre-empts). So the server is given time to go quiet first.
		c.mu.Unlock()
		last, quiet := atomic.LoadInt64(&c.acts), 0
		need := 6
		if v := os.Getenv("GOX2_QUIET"); v != "" {
			fmt.Sscanf(v, "%d", &need)
		}
		for quiet < need {
			time.Sleep(300 * time.Microsecond)
			if cur := atomic.LoadInt64(&c.acts); cur == last {
				quiet++
			} else {
				quiet, last = 0, cur
			}
		}
		c.mu.Lock()
		atomic.StoreInt32(&c.eof, 1)
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

func (c *bufConn) Write(p []byte) (int, error) {
	atomic.AddInt64(&c.acts, 1)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.out.Write(p)
}
func (c *bufConn) written() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.out.Bytes()...)
}
func (c *bufConn) Close() error                     { return nil }
func (c *bufConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (c *bufConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (c *bufConn) SetDeadline(time.Time) error      { return nil }
func (c *bufConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bufConn) SetWriteDeadline(time.Time) error { return nil }

type logSink struct{ add func(string) }

func (l logSink) Write(p []byte) (int, error) {
	l.add("log: " + strings.TrimSpace(string(p)))
	return len(p), nil
}

type dummyAddr struct{}

func (dummyAddr) Network() string { return "pipe" }
func (dummyAddr) String() string  { return "ref-gox2" }

// reqState is one request as its handler is seeing it: recorded when the
// handler starts, so that a request the server accepted and then stopped
// feeding (a connection error closes the reader, and the server then sits out
// a one-second GOAWAY timer) is still a request, with ended false.
type reqState struct {
	m        msg
	body     []byte
	trailers http.Header
}

func runH2(data []byte, byteWise bool) h2result {
	res := h2result{Msgs: []msg{}, Resets: [][2]int64{}, Answers: [][2]int64{}}
	var mu sync.Mutex
	var errs []string
	addErr := func(s string) {
		mu.Lock()
		errs = append(errs, s)
		mu.Unlock()
	}
	conn := &bufConn{in: data, byteWise: byteWise}
	var reqs []*reqState

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&conn.acts, 1)
		defer atomic.AddInt64(&conn.acts, 1)
		defer func() {
			if e := recover(); e != nil {
				addErr(fmt.Sprintf("handler panic: %v", e))
			}
		}()
		st := &reqState{}
		st.m = msg{Stream: streamID(w)}
		st.m.Method = hxp(r.Method, true)
		st.m.Authority = hxp(r.Host, r.Host != "")
		st.m.Path = hxp(r.RequestURI, r.RequestURI != "")
		if r.URL != nil {
			st.m.Scheme = hxp(r.URL.Scheme, r.URL.Scheme != "")
		}
		st.m.Headers = fields(r.Header)
		mu.Lock()
		reqs = append(reqs, st)
		mu.Unlock()
		buf := make([]byte, 4096)
		for {
			n, berr := r.Body.Read(buf)
			if n > 0 {
				atomic.AddInt64(&conn.acts, 1)
				mu.Lock()
				st.body = append(st.body, buf[:n]...)
				mu.Unlock()
			}
			if berr == io.EOF {
				mu.Lock()
				st.m.Ended = true
				st.trailers = r.Trailer
				mu.Unlock()
				break
			}
			if berr != nil {
				addErr("body: " + berr.Error())
				break
			}
		}
		w.WriteHeader(200)
	})

	srv := &http2.Server{
		MaxConcurrentStreams:      100,
		MaxReadFrameSize:          16384,
		MaxUploadBufferPerStream:  65535,
		MaxDecoderHeaderTableSize: 4096,
		MaxEncoderHeaderTableSize: 4096,
	}
	opts := &http2.ServeConnOpts{
		Handler: h,
		// ErrorLog is where Go says why it dropped a connection it never
		// answered (a bad preface writes nothing at all); it goes to "err".
		BaseConfig: &http.Server{
			MaxHeaderBytes: 65536 - 320,
			ErrorLog:       log.New(logSink{addErr}, "", 0),
		},
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if e := recover(); e != nil {
				addErr(fmt.Sprintf("ServeConn panic: %v", e))
			}
		}()
		srv.ServeConn(conn, opts)
	}()

	// Wait for the server to go quiet. It has finished with the input when it
	// has stopped reading, writing and running handlers for about 2.5ms (the
	// reader asks for more only after the serve loop has taken every frame it
	// was given, so a quiet server has processed everything). ServeConn itself
	// may not return for a second: after a GOAWAY with an error code it waits
	// out a timer, so its return is not what this waits for; but if it does
	// return (the input ran out and the reader saw EOF) the handlers are
	// released with an error, and a little more quiet lets them record it.
	need := 9
	if v := os.Getenv("GOX2_QUIET"); v != "" {
		fmt.Sscanf(v, "%d", &need)
	}
	deadline := time.Now().Add(5 * time.Second)
	last, quiet := int64(-1), 0
	for time.Now().Before(deadline) {
		time.Sleep(300 * time.Microsecond)
		cur := atomic.LoadInt64(&conn.acts)
		if cur == last && cur > 0 {
			if quiet++; quiet >= need {
				break
			}
		} else {
			quiet, last = 0, cur
		}
	}
	if time.Now().After(deadline) {
		addErr("timeout")
	}
	// ServeConn returning before this conn said EOF is the server hanging up
	// on its own: a refusal that sends no GOAWAY (a frame it could not parse, a
	// bad preface), which conn_error cannot show.
	select {
	case <-done:
		if atomic.LoadInt32(&conn.eof) == 0 {
			res.Closed = true
		}
	default:
	}

	written := conn.written()
	if os.Getenv("GOX2_DUMP") != "" {
		fmt.Fprintf(os.Stderr, "WRITTEN %x\nERRS %v\n", written, errs)
	}
	fr := http2.NewFramer(io.Discard, bytes.NewReader(written))
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			if err != io.EOF {
				addErr("output frame: " + err.Error())
			}
			break
		}
		switch f := f.(type) {
		case *http2.MetaHeadersFrame:
			var code int64
			fmt.Sscanf(f.PseudoValue("status"), "%d", &code)
			if code >= 400 && f.StreamID != 0 { // 1xx are interim (100-continue), 200 is the handler's
				res.Answers = append(res.Answers, [2]int64{int64(f.StreamID), code})
			}
		case *http2.RSTStreamFrame:
			if f.StreamID != 0 {
				res.Resets = append(res.Resets, [2]int64{int64(f.StreamID), int64(f.ErrCode)})
			}
		case *http2.GoAwayFrame:
			if f.ErrCode != 0 && res.ConnError == nil {
				c := uint32(f.ErrCode)
				res.ConnError = &c
			}
		}
	}
	// Go reads the preface after it has sent its SETTINGS and, when it is
	// wrong, closes with no GOAWAY and no log line: say so, since neither
	// "resets" nor "conn_error" can.
	pre := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	n := len(data)
	if n > len(pre) {
		n = len(pre)
	}
	if string(data[:n]) != pre[:n] && res.ConnError == nil {
		addErr("bad preface: closed silently, no GOAWAY")
	}
	mu.Lock()
	defer mu.Unlock()
	for _, st := range reqs {
		m := st.m
		m.Body = hex.EncodeToString(st.body)
		m.Trailers = fields(st.trailers)
		res.Msgs = append(res.Msgs, m)
	}
	res.Err = strings.Join(errs, "; ")
	return res
}

type hdresult struct {
	List  [][2]string `json:"list"`
	Error bool        `json:"error"`
	Err   string      `json:"err"`
}

func runHD(arg string, data []byte) (res hdresult) {
	res.List = [][2]string{}
	var size uint32
	fmt.Sscanf(arg, "%d", &size)
	defer func() {
		if e := recover(); e != nil {
			res.Error, res.Err = true, fmt.Sprintf("panic: %v", e)
		}
	}()
	d := hpack.NewDecoder(size, func(f hpack.HeaderField) {
		res.List = append(res.List, [2]string{hx(f.Name), hx(f.Value)})
	})
	d.SetMaxStringLength(0) // 0 is no limit
	d.SetAllowedMaxDynamicTableSize(size)
	if _, err := d.Write(data); err != nil {
		res.Error, res.Err = true, err.Error()
		return
	}
	if err := d.Close(); err != nil {
		res.Error, res.Err = true, err.Error()
	}
	return
}

type heresult struct {
	Hex string `json:"hex"`
	Err string `json:"err,omitempty"`
}

func runHE(arg string, data []byte) (res heresult) {
	defer func() {
		if e := recover(); e != nil {
			res.Err = fmt.Sprintf("panic: %v", e)
		}
	}()
	var size uint32
	fmt.Sscanf(arg, "%d", &size)
	var buf bytes.Buffer
	e := hpack.NewEncoder(&buf)
	e.SetMaxDynamicTableSize(size)
	for len(data) > 0 {
		if len(data) < 4 {
			res.Err = "short blob"
			return
		}
		nl := int(binary.BigEndian.Uint32(data))
		if len(data) < 4+nl+4 {
			res.Err = "short blob"
			return
		}
		name := data[4 : 4+nl]
		data = data[4+nl:]
		vl := int(binary.BigEndian.Uint32(data))
		if len(data) < 4+vl {
			res.Err = "short blob"
			return
		}
		val := data[4 : 4+vl]
		data = data[4+vl:]
		if err := e.WriteField(hpack.HeaderField{Name: string(name), Value: string(val)}); err != nil {
			res.Err = err.Error()
			return
		}
	}
	res.Hex = hex.EncodeToString(buf.Bytes())
	return
}

func version() string {
	v := "unknown"
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "golang.org/x/net" {
				v = d.Version
				if d.Replace != nil {
					v = d.Replace.Version
				}
			}
		}
	}
	return "x/net/http2 " + v + " (" + runtime.Version() + ")"
}

// worker answers cases from stdin in this process.
func worker() {
	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for {
		line, err := in.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if line != "" {
			f := strings.Split(line, "\t")
			if len(f) != 5 {
				fmt.Fprintln(os.Stderr, "bad line")
				os.Exit(2)
			}
			data, derr := hex.DecodeString(f[4])
			if derr != nil {
				fmt.Fprintln(os.Stderr, "bad hex")
				os.Exit(2)
			}
			var r interface{}
			switch f[1] {
			case "h2":
				r = runH2(data, f[2] == "byte")
			case "hd":
				r = runHD(f[3], data)
			case "he":
				r = runHE(f[3], data)
			default:
				r = map[string]string{"err": "unknown kind " + f[1]}
			}
			j, _ := json.Marshal(r)
			fmt.Fprintf(out, "%s\t%s\t%s\n", f[0], f[2], j)
			out.Flush() // lockstep: the supervisor reads each answer before sending the next case
		}
		if err != nil {
			return
		}
	}
}

// crashAnswer is what a case that killed the worker is answered with.
func crashAnswer(kind, why string) string {
	why = strings.ReplaceAll(strings.ReplaceAll(why, "\\", "/"), "\"", "'")
	switch kind {
	case "hd":
		return `{"list":[],"error":true,"err":"PROCESS CRASH: ` + why + `"}`
	case "he":
		return `{"hex":"","err":"PROCESS CRASH: ` + why + `"}`
	}
	return `{"msgs":[],"resets":[],"conn_error":null,"err":"PROCESS CRASH: ` + why + `"}`
}

// supervise runs the worker one case at a time, and survives its death.
func supervise() {
	self, _ := os.Executable()
	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	var cmd *exec.Cmd
	var wIn io.WriteCloser
	var wOut *bufio.Reader
	var errBuf *bytes.Buffer
	start := func() {
		errBuf = &bytes.Buffer{}
		cmd = exec.Command(self, "--worker")
		cmd.Stderr = errBuf
		wIn, _ = cmd.StdinPipe()
		o, _ := cmd.StdoutPipe()
		wOut = bufio.NewReaderSize(o, 1<<20)
		if err := cmd.Start(); err != nil {
			fmt.Fprintln(os.Stderr, "cannot start the worker:", err)
			os.Exit(2)
		}
	}
	stop := func() {
		wIn.Close()
		cmd.Process.Kill()
		cmd.Wait()
	}
	start()
	defer stop()
	for {
		line, err := in.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if line != "" {
			f := strings.Split(line, "\t")
			if len(f) != 5 {
				fmt.Fprintln(os.Stderr, "bad line")
				os.Exit(2)
			}
			var answer string
			_, werr := io.WriteString(wIn, line+"\n")
			if werr == nil {
				type reply struct {
					s   string
					err error
				}
				ch := make(chan reply, 1)
				go func() { s, e := wOut.ReadString('\n'); ch <- reply{s, e} }()
				select {
				case r := <-ch:
					if r.err == nil {
						answer = strings.TrimRight(r.s, "\n")
					} else {
						werr = r.err
					}
				case <-time.After(60 * time.Second):
					werr = fmt.Errorf("no answer in 60s")
				}
			}
			if werr != nil {
				stop()
				why := strings.TrimSpace(errBuf.String())
				if i := strings.Index(why, "\n"); i >= 0 {
					why = why[:i]
				}
				if why == "" {
					why = werr.Error()
				}
				fmt.Fprintf(out, "%s\t%s\t%s\n", f[0], f[2], crashAnswer(f[1], why))
				start()
			} else {
				fmt.Fprintf(out, "%s\n", answer)
			}
		}
		if err != nil {
			return
		}
	}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println(version())
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "--worker" {
		worker()
		return
	}
	supervise()
}
