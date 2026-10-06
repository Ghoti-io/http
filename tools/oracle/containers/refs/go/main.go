// The Go reference: net/http's own message reader.
//
// http.ReadRequest and http.ReadResponse are what net/http's server and
// transport read messages with, and the framing code behind their bodies is
// the one every Go HTTP/1.1 program uses. Same protocol as http_probe.c:
// tab-separated cases on stdin, one `id split json` line out, every string hex.
//
// Go has no strictness switch for these. Two things it does that are not the
// parser's, so that a disagreement is not misread: net/http's *Server* (not
// ReadRequest) is what rejects a missing or repeated Host, and Go moves Host,
// Content-Length and Transfer-Encoding out of the header map, which diff.py
// accounts for rather than compares.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"testing/iotest"
)

type message struct {
	Start    map[string]interface{} `json:"start"`
	Headers  [][2]string            `json:"headers"`
	Body     string                 `json:"body"`
	Trailers [][2]string            `json:"trailers"`
	Upgrade  bool                   `json:"upgrade"`
}

type result struct {
	Msgs []message `json:"msgs"`
	End  string    `json:"end"`
	Err  string    `json:"err"`
}

func hx(s string) string { return hex.EncodeToString([]byte(s)) }

// fields lists a header map in name order. Go's map has no arrival order
// across names, so the comparison is by name; order within a name is kept.
func fields(h http.Header) [][2]string {
	names := make([]string, 0, len(h))
	for k := range h {
		names = append(names, k)
	}
	sort.Strings(names)
	out := [][2]string{}
	for _, k := range names {
		for _, v := range h[k] {
			out = append(out, [2]string{hx(k), hx(v)})
		}
	}
	return out
}

func classify(err error) (string, string) {
	// net/http says "unexpected EOF" in two ways: wrapping io.ErrUnexpectedEOF,
	// and as text in an error of its own ("http: unexpected EOF reading trailer").
	//
	// And net/http looks ahead for the empty line that ends a trailer section
	// before it reads one, to bound the memory a peer can make it hold; at the
	// end of input with no such line it says "suspiciously long trailer", which
	// for input that is simply cut short means cut short. (A trailer section
	// over the reader's 4 KiB buffer would also say it, and would be read here
	// as incomplete: no case in this corpus is that long.)
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) ||
		strings.Contains(err.Error(), "unexpected EOF") ||
		strings.Contains(err.Error(), "suspiciously long trailer") {
		return "incomplete", err.Error()
	}
	return "error", err.Error()
}

func connectionUpgrade(h http.Header) bool {
	if len(h.Values("Upgrade")) == 0 {
		return false
	}
	for _, v := range h.Values("Connection") {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), "upgrade") {
				return true
			}
		}
	}
	return false
}

func run(isReq bool, method string, data []byte, byteWise bool) result {
	var src io.Reader = bytes.NewReader(data)
	if byteWise {
		src = iotest.OneByteReader(src)
	}
	br := bufio.NewReader(src)
	res := result{Msgs: []message{}, End: "clean"}
	pending := method
	if pending == "-" {
		pending = "GET"
	}
	for {
		var m message
		// ReadResponse turns a clean end of input into ErrUnexpectedEOF, so
		// "nothing more to read" is decided here, for both directions alike.
		if _, perr := br.Peek(1); perr == io.EOF {
			return res
		}
		if isReq {
			req, err := http.ReadRequest(br)
			if err == io.EOF {
				return res
			}
			if err != nil {
				res.End, res.Err = classify(err)
				return res
			}
			body, berr := io.ReadAll(req.Body)
			if berr != nil {
				res.End, res.Err = classify(berr)
				return res
			}
			// Host is moved to req.Host by ReadRequest, and Content-Length and
			// Transfer-Encoding are consumed into the request's fields.
			m = message{
				Start: map[string]interface{}{
					"method": hx(req.Method), "target": hx(req.RequestURI),
					"ver": fmt.Sprintf("%d.%d", req.ProtoMajor, req.ProtoMinor)},
				Headers: fields(req.Header), Body: hex.EncodeToString(body),
				Trailers: fields(req.Trailer),
				Upgrade:  req.Method == "CONNECT" || connectionUpgrade(req.Header),
			}
		} else {
			resp, err := http.ReadResponse(br, &http.Request{Method: pending})
			if err == io.EOF {
				return res
			}
			if err != nil {
				res.End, res.Err = classify(err)
				return res
			}
			body, berr := io.ReadAll(resp.Body)
			if berr != nil {
				res.End, res.Err = classify(berr)
				return res
			}
			reason := strings.TrimPrefix(resp.Status, fmt.Sprintf("%03d", resp.StatusCode))
			reason = strings.TrimPrefix(reason, " ")
			up := resp.StatusCode == 101 ||
				(pending == "CONNECT" && resp.StatusCode/100 == 2)
			if resp.StatusCode >= 200 {
				pending = "GET"
			}
			m = message{
				Start: map[string]interface{}{
					"reason": hx(reason), "status": resp.StatusCode,
					"ver": fmt.Sprintf("%d.%d", resp.ProtoMajor, resp.ProtoMinor)},
				Headers: fields(resp.Header), Body: hex.EncodeToString(body),
				Trailers: fields(resp.Trailer), Upgrade: up,
			}
		}
		res.Msgs = append(res.Msgs, m)
		if m.Upgrade {
			// A tunnel ends HTTP reading; net/http has no such concept, so this
			// follows the rule llhttp and this library use.
			res.End, res.Err = "clean", ""
			return res
		}
	}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println("go net/http " + runtime.Version())
		return
	}
	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for {
		line, err := in.ReadString('\n')
		line = strings.TrimRight(line, "\n")
		if line != "" {
			f := strings.Split(line, "\t")
			data, derr := hex.DecodeString(f[4])
			if derr != nil {
				fmt.Fprintln(os.Stderr, "bad hex")
				os.Exit(2)
			}
			r := run(f[1] == "req", f[2], data, f[3] == "byte")
			j, _ := json.Marshal(r)
			fmt.Fprintf(out, "%s\t%s\t%s\n", f[0], f[3], j)
		}
		if err != nil {
			return
		}
	}
}
