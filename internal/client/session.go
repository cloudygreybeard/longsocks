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
	"net/url"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"

	"github.com/cloudygreybeard/longsocks/internal/backoff"
)

// dialMuxSession establishes a yamux session over WebSocket with retry.
func dialMuxSession(ctx context.Context, serverURL *url.URL, cfg Config) (*yamux.Session, error) {
	bo := backoff.New(cfg.MaxRetryCount, cfg.MaxRetryInterval)
	for {
		session, err := tryDialMux(ctx, serverURL, cfg)
		if err == nil {
			return session, nil
		}
		delay, ok := bo.Next()
		if !ok {
			return nil, fmt.Errorf("max retries exceeded: %w", err)
		}
		cfg.Logger.Warn("mux dial failed, retrying",
			"error", err, "delay", delay)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func tryDialMux(ctx context.Context, serverURL *url.URL, cfg Config) (*yamux.Session, error) {
	connectURL := *serverURL
	switch connectURL.Scheme {
	case "wss", "https":
		connectURL.Scheme = "wss"
	default:
		connectURL.Scheme = "ws"
	}
	connectURL.Path = "/mux"

	wsConn, err := dialWebSocket(ctx, connectURL.String(), cfg)
	if err != nil {
		return nil, fmt.Errorf("websocket dial: %w", err)
	}

	// Use Background context: the session must outlive the caller's context
	// (e.g. a single SOCKS5 connection) since it is shared across all streams.
	netConn := websocket.NetConn(context.Background(), wsConn, websocket.MessageBinary)
	session, err := yamux.Client(netConn, nil)
	if err != nil {
		_ = wsConn.CloseNow()
		return nil, fmt.Errorf("yamux client: %w", err)
	}
	return session, nil
}
