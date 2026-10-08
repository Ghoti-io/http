// SPDX-License-Identifier: LGPL-3.0-only
//
// Copyright (C) 2026 Corey Pennycuff
//
// This file is part of Ghoti.io HTTP.
//
// Ghoti.io HTTP is free software: you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License version 3 as
// published by the Free Software Foundation.
//
// Ghoti.io HTTP is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
// License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// The Go side of the Extended CONNECT interoperability check: golang.org/x/net/http2
// as a server that echoes a tunnel, and as a client that opens one.
//
// Both speak HTTP/2 over this process's stdin and stdout (prior knowledge, no
// TLS), so a harness can connect them to this library's probe with two pipes.
// Extended CONNECT is off by default in x/net (Issue #71128); the harness sets
// GODEBUG=http2xconnect=1, which is Go's own switch for it.
//
//	server         for every CONNECT with a :protocol, answer 200 and echo the
//	               request body to the response body, flushing as it goes.
//	client N       open one Extended CONNECT (:protocol websocket), write N octets
//	               of a fixed pattern in pieces, end the request body, read the
//	               response body to its end, and exit 0 only if it is the same N
//	               octets and the stream ended cleanly.
//	--version      print the x/net version.
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"time"

	"golang.org/x/net/http2"
)

type stdioConn struct{}

func (stdioConn) Read(p []byte) (int, error)         { return os.Stdin.Read(p) }
func (stdioConn) Write(p []byte) (int, error)        { return os.Stdout.Write(p) }
func (stdioConn) Close() error                       { return nil }
func (stdioConn) LocalAddr() net.Addr                { return addr{} }
func (stdioConn) RemoteAddr() net.Addr               { return addr{} }
func (stdioConn) SetDeadline(time.Time) error        { return nil }
func (stdioConn) SetReadDeadline(time.Time) error    { return nil }
func (stdioConn) SetWriteDeadline(time.Time) error   { return nil }

type addr struct{}

func (addr) Network() string { return "stdio" }
func (addr) String() string  { return "stdio" }

func pattern(n int) []byte {
	b := make([]byte, n)
	x := uint32(12345)
	for i := range b {
		x = x*1103515245 + 12345
		b[i] = byte(x >> 16)
	}
	return b
}

func version() string {
	v := "?"
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "golang.org/x/net" {
				v = d.Version
			}
		}
	}
	return "x/net/http2 " + v + " tunnel (" + runtime.Version() + ")"
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println(version())
		return
	}
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: server | client N | --version")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "server":
		srv := &http2.Server{}
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "CONNECT" || r.Header.Get(":protocol") == "" {
				http.Error(w, "an Extended CONNECT is the only thing served", 400)
				return
			}
			w.WriteHeader(200)
			fl := w.(http.Flusher)
			fl.Flush()
			buf := make([]byte, 4096)
			for {
				n, err := r.Body.Read(buf)
				if n > 0 {
					if _, werr := w.Write(buf[:n]); werr != nil {
						return
					}
					fl.Flush()
				}
				if err != nil {
					return
				}
			}
		})
		srv.ServeConn(stdioConn{}, &http2.ServeConnOpts{Handler: h})
	case "client":
		n, _ := strconv.Atoi(os.Args[2])
		t := &http2.Transport{AllowHTTP: true}
		cc, err := t.NewClientConn(stdioConn{})
		if err != nil {
			fmt.Fprintln(os.Stderr, "client conn:", err)
			os.Exit(1)
		}
		want := pattern(n)
		pr, pw := io.Pipe()
		go func() {
			for off := 0; off < len(want); {
				k := 7919
				if off+k > len(want) {
					k = len(want) - off
				}
				pw.Write(want[off : off+k])
				off += k
			}
			pw.Close()
		}()
		req, _ := http.NewRequestWithContext(context.Background(), "CONNECT", "http://server.example.com/chat", pr)
		req.Header.Set(":protocol", "websocket")
		res, err := cc.RoundTrip(req)
		if err != nil {
			fmt.Fprintln(os.Stderr, "round trip:", err)
			os.Exit(1)
		}
		if res.StatusCode != 200 {
			fmt.Fprintln(os.Stderr, "status", res.StatusCode)
			os.Exit(1)
		}
		got, err := io.ReadAll(res.Body)
		if err != nil || !bytes.Equal(got, want) {
			fmt.Fprintf(os.Stderr, "echo differs: %d of %d octets, err %v\n", len(got), len(want), err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "echo of %d octets matched\n", n)
	}
}
