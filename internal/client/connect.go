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
	"net/http"
	"net/url"
	"time"

	"github.com/coder/websocket"

	"github.com/cloudygreybeard/longsocks/internal/backoff"
	"github.com/cloudygreybeard/longsocks/internal/relay"
)

// ListenAndServeConnect starts a local HTTP CONNECT proxy that tunnels
// each connection through a WebSocket to the longsocks server.
func ListenAndServeConnect(cfg Config) error {
	serverURL, err := url.Parse(cfg.ServerURL)
	if err != nil {
		return fmt.Errorf("parsing server URL: %w", err)
	}

	handler := &connectProxy{
		serverURL: serverURL,
		cfg:       cfg,
	}

	cfg.Logger.Info("connect proxy starting", "addr", cfg.Addr, "server", cfg.ServerURL)
	return http.ListenAndServe(cfg.Addr, handler)
}

type connectProxy struct {
	serverURL *url.URL
	cfg       Config
}

func (p *connectProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	http.Error(w, "only CONNECT method is supported", http.StatusMethodNotAllowed)
}

func (p *connectProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	if target == "" {
		http.Error(w, "missing target host", http.StatusBadRequest)
		return
	}

	wsConn, err := p.dialServer(r.Context(), target)
	if err != nil {
		p.cfg.Logger.Error("websocket dial failed", "target", target, "error", err)
		http.Error(w, "tunnel dial failed", http.StatusBadGateway)
		return
	}

	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		p.cfg.Logger.Error("hijack not supported")
		_ = wsConn.CloseNow()
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		p.cfg.Logger.Error("hijack failed", "error", err)
		_ = wsConn.CloseNow()
		return
	}

	netConn := websocket.NetConn(context.Background(), wsConn, websocket.MessageBinary)
	relay.Relay(clientConn, netConn)
}

func (p *connectProxy) dialServer(ctx context.Context, target string) (*websocket.Conn, error) {
	connectURL := *p.serverURL
	if connectURL.Scheme == "wss" || connectURL.Scheme == "https" {
		connectURL.Scheme = "wss"
	} else {
		connectURL.Scheme = "ws"
	}
	connectURL.Path = "/connect"
	q := connectURL.Query()
	q.Set("target", target)
	connectURL.RawQuery = q.Encode()

	bo := backoff.New(p.cfg.MaxRetryCount, p.cfg.MaxRetryInterval)
	for {
		wsConn, err := dialWebSocket(ctx, connectURL.String(), p.cfg)
		if err == nil {
			return wsConn, nil
		}
		delay, ok := bo.Next()
		if !ok {
			return nil, fmt.Errorf("max retries exceeded: %w", err)
		}
		p.cfg.Logger.Warn("dial failed, retrying",
			"target", target, "error", err, "delay", delay)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}
