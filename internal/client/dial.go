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
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/coder/websocket"
)

func buildDialOptions(cfg Config) *websocket.DialOptions {
	opts := &websocket.DialOptions{}
	if cfg.Token != "" {
		opts.HTTPHeader = http.Header{
			"Authorization": []string{"Bearer " + cfg.Token},
		}
	}
	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err == nil {
			opts.HTTPClient = &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						Certificates: []tls.Certificate{cert},
						MinVersion:   tls.VersionTLS12,
					},
				},
			}
		}
	}
	return opts
}

func dialWebSocket(ctx context.Context, rawURL string, cfg Config) (*websocket.Conn, error) {
	opts := buildDialOptions(cfg)
	wsConn, resp, err := websocket.Dial(ctx, rawURL, opts)
	if err != nil {
		return nil, err
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if cfg.Fingerprint != "" && resp != nil {
		fp := resp.Header.Get("X-Longsocks-Fingerprint")
		if fp != cfg.Fingerprint {
			_ = wsConn.CloseNow()
			return nil, fmt.Errorf(
				"server fingerprint mismatch: got %q, want %q",
				fp, cfg.Fingerprint,
			)
		}
	}
	return wsConn, nil
}
