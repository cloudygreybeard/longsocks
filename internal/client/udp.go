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

package client

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/cloudygreybeard/longsocks/internal/backoff"
)

// UDPRelay manages a WebSocket connection for relaying UDP datagrams
// between the local SOCKS5 UDP client and the longsocks server.
type UDPRelay struct {
	serverURL *url.URL
	cfg       Config

	mu         sync.Mutex
	udpConn    *net.UDPConn
	wsConn     *websocket.Conn
	clientAddr *net.UDPAddr
}

// NewUDPRelay creates a UDP relay that listens locally and forwards
// datagrams to the longsocks server over a WebSocket.
func NewUDPRelay(serverURL *url.URL, cfg Config) (*UDPRelay, error) {
	udpAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen UDP: %w", err)
	}

	connectURL := *serverURL
	if connectURL.Scheme == "wss" || connectURL.Scheme == "https" {
		connectURL.Scheme = "wss"
	} else {
		connectURL.Scheme = "ws"
	}
	connectURL.Path = "/connect-udp"

	bo := backoff.New(cfg.MaxRetryCount, cfg.MaxRetryInterval)
	var wsConn *websocket.Conn
	for {
		wsConn, err = dialWebSocket(context.Background(), connectURL.String(), cfg)
		if err == nil {
			break
		}
		delay, ok := bo.Next()
		if !ok {
			_ = udpConn.Close()
			return nil, fmt.Errorf("max retries exceeded: %w", err)
		}
		cfg.Logger.Warn("udp relay dial failed, retrying",
			"error", err, "delay", delay)
		time.Sleep(delay)
	}

	r := &UDPRelay{
		serverURL: serverURL,
		cfg:       cfg,
		udpConn:   udpConn,
		wsConn:    wsConn,
	}

	go r.readFromServer()

	return r, nil
}

// LocalAddr returns the local UDP address clients should send datagrams to.
func (r *UDPRelay) LocalAddr() *net.UDPAddr {
	return r.udpConn.LocalAddr().(*net.UDPAddr)
}

// Run reads UDP datagrams from the local listener and forwards them to
// the server over WebSocket. It blocks until the connection is closed.
func (r *UDPRelay) Run() {
	buf := make([]byte, 65535)
	for {
		n, addr, err := r.udpConn.ReadFromUDP(buf)
		if err != nil {
			break
		}

		r.mu.Lock()
		r.clientAddr = addr
		r.mu.Unlock()

		if err := r.wsConn.Write(context.Background(), websocket.MessageBinary, buf[:n]); err != nil {
			r.cfg.Logger.Error("websocket write failed", "error", err)
			break
		}
	}
}

func (r *UDPRelay) readFromServer() {
	ctx := context.Background()
	for {
		_, msg, err := r.wsConn.Read(ctx)
		if err != nil {
			break
		}

		r.mu.Lock()
		addr := r.clientAddr
		r.mu.Unlock()

		if addr == nil {
			continue
		}

		_, _ = r.udpConn.WriteToUDP(msg, addr)
	}
}

// Close shuts down the relay.
func (r *UDPRelay) Close() {
	_ = r.wsConn.CloseNow()
	_ = r.udpConn.Close()
}
