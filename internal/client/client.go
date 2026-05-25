// Copyright 2026 cloudygreybeard
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package client implements the longsocks proxy client that tunnels
// connections through WebSockets to a longsocks server.
package client

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/armon/go-socks5"
	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"

	"github.com/cloudygreybeard/longsocks/internal/backoff"
	"github.com/cloudygreybeard/longsocks/internal/mux"
)

// Config holds the client configuration.
type Config struct {
	Addr             string
	ServerURL        string
	Token            string
	Logger           *slog.Logger
	MaxRetryCount    int
	MaxRetryInterval time.Duration
	Fingerprint      string
	TLSCert          string
	TLSKey           string
	Mux              bool
}

// tcpAddrConn wraps a net.Conn to return *net.TCPAddr from RemoteAddr()
// and LocalAddr(). The go-socks5 library performs a type assertion to
// *net.TCPAddr in handleConnect, and websocket.NetConn returns a non-TCP
// address type, causing a runtime panic without this wrapper.
type tcpAddrConn struct {
	net.Conn
	remote *net.TCPAddr
}

func (c *tcpAddrConn) RemoteAddr() net.Addr { return c.remote }
func (c *tcpAddrConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

// ListenAndServe starts the local SOCKS5 proxy that tunnels each connection
// through a WebSocket to the longsocks server.
func ListenAndServe(cfg Config) error {
	if cfg.Mux {
		return listenAndServeMux(cfg)
	}

	serverURL, err := url.Parse(cfg.ServerURL)
	if err != nil {
		return fmt.Errorf("parsing server URL: %w", err)
	}

	dialer := makeDialer(serverURL, cfg)

	conf := &socks5.Config{Dial: dialer}
	srv, err := socks5.New(conf)
	if err != nil {
		return fmt.Errorf("creating SOCKS5 server: %w", err)
	}

	cfg.Logger.Info("client starting", "addr", cfg.Addr, "server", cfg.ServerURL)
	return srv.ListenAndServe("tcp", cfg.Addr)
}

// ListenAndServeUDP starts a SOCKS5 proxy with UDP ASSOCIATE support.
// TCP connections are handled identically to ListenAndServe. UDP
// datagrams are relayed through a WebSocket to the server's /connect-udp
// endpoint.
func ListenAndServeUDP(cfg Config) error {
	serverURL, err := url.Parse(cfg.ServerURL)
	if err != nil {
		return fmt.Errorf("parsing server URL: %w", err)
	}

	udpRelay, err := NewUDPRelay(serverURL, cfg)
	if err != nil {
		return fmt.Errorf("creating UDP relay: %w", err)
	}
	defer udpRelay.Close()

	go udpRelay.Run()

	dialer := makeDialer(serverURL, cfg)

	conf := &socks5.Config{Dial: dialer}
	srv, err := socks5.New(conf)
	if err != nil {
		return fmt.Errorf("creating SOCKS5 server: %w", err)
	}

	cfg.Logger.Info("client starting (socks5-udp)", "addr", cfg.Addr, "server", cfg.ServerURL,
		"udp_relay", udpRelay.LocalAddr().String())
	return srv.ListenAndServe("tcp", cfg.Addr)
}

func listenAndServeMux(cfg Config) error {
	serverURL, err := url.Parse(cfg.ServerURL)
	if err != nil {
		return fmt.Errorf("parsing server URL: %w", err)
	}

	md := &muxDialer{cfg: cfg, url: serverURL}

	conf := &socks5.Config{Dial: md.dial}
	srv, err := socks5.New(conf)
	if err != nil {
		return fmt.Errorf("creating SOCKS5 server: %w", err)
	}

	cfg.Logger.Info("client starting (mux)", "addr", cfg.Addr, "server", cfg.ServerURL)
	return srv.ListenAndServe("tcp", cfg.Addr)
}

type muxDialer struct {
	mu      sync.Mutex
	session *yamux.Session
	cfg     Config
	url     *url.URL
}

func (d *muxDialer) getSession(ctx context.Context) (*yamux.Session, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.session != nil && !d.session.IsClosed() {
		return d.session, nil
	}

	session, err := dialMuxSession(ctx, d.url, d.cfg)
	if err != nil {
		return nil, err
	}
	d.session = session
	d.cfg.Logger.Info("mux session established")
	return session, nil
}

func (d *muxDialer) dial(ctx context.Context, _, addr string) (net.Conn, error) {
	session, err := d.getSession(ctx)
	if err != nil {
		return nil, err
	}

	stream, err := session.Open()
	if err != nil {
		d.mu.Lock()
		d.session = nil
		d.mu.Unlock()
		return nil, fmt.Errorf("open stream: %w", err)
	}
	if err := mux.WriteHeader(stream, mux.CmdConnect, addr); err != nil {
		_ = stream.Close()
		return nil, err
	}
	return wrapConn(stream, addr), nil
}

func makeDialer(serverURL *url.URL, cfg Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, _, addr string) (net.Conn, error) {
		connectURL := *serverURL
		if connectURL.Scheme == "wss" {
			connectURL.Scheme = "wss"
		} else {
			connectURL.Scheme = "ws"
		}
		connectURL.Path = "/connect"
		q := connectURL.Query()
		q.Set("target", addr)
		connectURL.RawQuery = q.Encode()

		bo := backoff.New(cfg.MaxRetryCount, cfg.MaxRetryInterval)
		for {
			wsConn, err := dialWebSocket(ctx, connectURL.String(), cfg)
			if err == nil {
				netConn := websocket.NetConn(ctx, wsConn, websocket.MessageBinary)
				return wrapConn(netConn, addr), nil
			}

			delay, ok := bo.Next()
			if !ok {
				cfg.Logger.Error("dial failed, retries exhausted",
					"target", addr, "error", err)
				return nil, fmt.Errorf("websocket dial: %w", err)
			}
			cfg.Logger.Warn("dial failed, retrying",
				"target", addr, "error", err, "delay", delay)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
}

func wrapConn(conn net.Conn, addr string) net.Conn {
	host, portStr, _ := net.SplitHostPort(addr)
	remoteIP := net.IPv4(0, 0, 0, 0)
	if resolved := net.ParseIP(host); resolved != nil {
		remoteIP = resolved
	} else if addrs, err := net.LookupHost(host); err == nil && len(addrs) > 0 {
		if ip := net.ParseIP(addrs[0]); ip != nil {
			remoteIP = ip
		}
	}
	port, _ := strconv.Atoi(portStr)
	return &tcpAddrConn{
		Conn:   conn,
		remote: &net.TCPAddr{IP: remoteIP, Port: port},
	}
}
