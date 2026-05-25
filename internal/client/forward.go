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

	"github.com/hashicorp/yamux"

	"github.com/cloudygreybeard/longsocks/internal/mux"
	"github.com/cloudygreybeard/longsocks/internal/relay"
)

// PortForward describes a port forwarding specification.
type PortForward struct {
	Bind    string // Listen address (client for forward, server for reverse)
	Target  string // Connect address (server for forward, client for reverse)
	Reverse bool
}

// Forward establishes a multiplexed session and manages port forwarding.
// It reconnects automatically when the session is lost.
func Forward(cfg Config, forwards, reverses []PortForward) error {
	serverURL, err := url.Parse(cfg.ServerURL)
	if err != nil {
		return fmt.Errorf("parsing server URL: %w", err)
	}

	reverseLookup := make(map[string]string)
	for _, r := range reverses {
		reverseLookup[r.Bind] = r.Target
	}

	ctx := context.Background()

	for {
		session, err := dialMuxSession(ctx, serverURL, cfg)
		if err != nil {
			return err
		}
		cfg.Logger.Info("mux session established", "server", cfg.ServerURL)

		errCh := make(chan error, 1)
		var wg sync.WaitGroup

		for _, fwd := range forwards {
			wg.Add(1)
			go func(f PortForward) {
				defer wg.Done()
				if err := runForwardListener(session, f, cfg); err != nil {
					cfg.Logger.Error("forward listener stopped",
						"bind", f.Bind, "target", f.Target, "error", err)
				}
			}(fwd)
		}

		for _, rev := range reverses {
			if err := registerReverseBind(session, rev.Bind); err != nil {
				cfg.Logger.Error("reverse bind failed",
					"bind", rev.Bind, "error", err)
			} else {
				cfg.Logger.Info("reverse registered",
					"server_bind", rev.Bind, "local_target", rev.Target)
			}
		}

		if len(reverses) > 0 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				acceptReverseStreams(session, reverseLookup, cfg)
			}()
		}

		go func() {
			<-session.CloseChan()
			errCh <- fmt.Errorf("session closed")
		}()

		<-errCh
		cfg.Logger.Warn("session lost, reconnecting")
		_ = session.Close()
		wg.Wait()
	}
}

func runForwardListener(session *yamux.Session, fwd PortForward, cfg Config) error {
	ln, err := net.Listen("tcp", fwd.Bind)
	if err != nil {
		return fmt.Errorf("listen %s: %w", fwd.Bind, err)
	}
	defer func() { _ = ln.Close() }()

	cfg.Logger.Info("forwarding", "bind", ln.Addr(), "target", fwd.Target)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go forwardConn(session, conn, fwd.Target, cfg)
	}
}

func forwardConn(session *yamux.Session, local net.Conn, target string, cfg Config) {
	stream, err := session.Open()
	if err != nil {
		cfg.Logger.Error("open stream", "error", err)
		_ = local.Close()
		return
	}
	if err := mux.WriteHeader(stream, mux.CmdConnect, target); err != nil {
		cfg.Logger.Error("write connect header", "error", err)
		_ = stream.Close()
		_ = local.Close()
		return
	}
	relay.Relay(local, stream)
}

func registerReverseBind(session *yamux.Session, bindAddr string) error {
	stream, err := session.Open()
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	if err := mux.WriteHeader(stream, mux.CmdReverseBind, bindAddr); err != nil {
		_ = stream.Close()
		return fmt.Errorf("write header: %w", err)
	}
	return nil
}

func acceptReverseStreams(session *yamux.Session, lookup map[string]string, cfg Config) {
	for {
		stream, err := session.Accept()
		if err != nil {
			return
		}
		cmd, bindAddr, err := mux.ReadHeader(stream)
		if err != nil || cmd != mux.CmdReverseConn {
			_ = stream.Close()
			continue
		}
		localTarget, ok := lookup[bindAddr]
		if !ok {
			cfg.Logger.Warn("unknown reverse bind", "bind", bindAddr)
			_ = stream.Close()
			continue
		}
		go handleLocalReverseConn(stream, localTarget, cfg)
	}
}

func handleLocalReverseConn(stream net.Conn, localTarget string, cfg Config) {
	local, err := net.DialTimeout("tcp", localTarget, 10*time.Second)
	if err != nil {
		cfg.Logger.Error("reverse dial local", "target", localTarget, "error", err)
		_ = stream.Close()
		return
	}
	relay.Relay(stream, local)
}
