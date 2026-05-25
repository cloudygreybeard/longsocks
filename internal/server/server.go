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

// Package server implements the longsocks WebSocket relay server.
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
	"golang.org/x/crypto/acme/autocert"

	"github.com/cloudygreybeard/longsocks/internal/audit"
	"github.com/cloudygreybeard/longsocks/internal/auth"
	"github.com/cloudygreybeard/longsocks/internal/mux"
	"github.com/cloudygreybeard/longsocks/internal/relay"
)

// Config holds the server configuration.
type Config struct {
	Addr      string
	AuthChain *auth.AuthChain
	Logger    *slog.Logger
	Stats     *audit.StatsAggregator
	Modes     []string

	TLSCert   string
	TLSKey    string
	TLSAuto   bool
	TLSDomain string
	TLSCA     string

	Reverse     bool
	Fingerprint string
}

// ListenAndServe starts the WebSocket relay server.
func ListenAndServe(cfg Config) error {
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/healthz", healthzHandler)

	modes := cfg.Modes
	if len(modes) == 0 {
		modes = []string{"socks5"}
	}

	fp := fingerprintMiddleware(cfg.Fingerprint)

	for _, mode := range modes {
		switch mode {
		case "socks5", "socks5-udp":
			httpMux.HandleFunc("/connect", fp(connectHandler(cfg)))
		case "connect":
			httpMux.HandleFunc("/connect-http", connectHTTPHandler(cfg))
		}
	}

	for _, mode := range modes {
		if mode == "socks5-udp" {
			httpMux.HandleFunc("/connect-udp", fp(connectUDPHandler(cfg)))
			break
		}
	}

	httpMux.HandleFunc("/mux", fp(muxHandler(cfg)))

	cfg.Logger.Info("server starting",
		"addr", cfg.Addr,
		"modes", strings.Join(modes, ","),
		"reverse", cfg.Reverse)

	if cfg.Fingerprint != "" {
		cfg.Logger.Info("server fingerprint", "fingerprint", cfg.Fingerprint)
	}

	mtlsCfg := buildMTLSConfig(cfg)

	if cfg.TLSAuto {
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.TLSDomain),
			Cache:      autocert.DirCache(".longsocks-certs"),
		}
		tlsCfg := m.TLSConfig()
		if mtlsCfg != nil {
			tlsCfg.ClientAuth = mtlsCfg.ClientAuth
			tlsCfg.ClientCAs = mtlsCfg.ClientCAs
		}
		srv := &http.Server{
			Addr:      cfg.Addr,
			Handler:   httpMux,
			TLSConfig: tlsCfg,
		}
		cfg.Logger.Info("TLS autocert enabled", "domain", cfg.TLSDomain)
		return srv.ListenAndServeTLS("", "")
	}

	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if mtlsCfg != nil {
			tlsCfg.ClientAuth = mtlsCfg.ClientAuth
			tlsCfg.ClientCAs = mtlsCfg.ClientCAs
		}
		srv := &http.Server{
			Addr:      cfg.Addr,
			Handler:   httpMux,
			TLSConfig: tlsCfg,
		}
		cfg.Logger.Info("TLS enabled", "cert", cfg.TLSCert)
		return srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
	}

	return http.ListenAndServe(cfg.Addr, httpMux)
}

func buildMTLSConfig(cfg Config) *tls.Config {
	if cfg.TLSCA == "" {
		return nil
	}
	caPool, err := auth.LoadCACertPool(cfg.TLSCA)
	if err != nil {
		cfg.Logger.Error("loading CA certificate", "error", err)
		return nil
	}
	cfg.Logger.Info("mTLS enabled", "ca", cfg.TLSCA)
	return &tls.Config{
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  caPool,
		MinVersion: tls.VersionTLS12,
	}
}

func fingerprintMiddleware(fp string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		if fp == "" {
			return next
		}
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Longsocks-Fingerprint", fp)
			next(w, r)
		}
	}
}

func healthzHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func authenticateRequest(cfg Config, w http.ResponseWriter, r *http.Request) (tokenName string, ok bool) {
	if identity := auth.MTLSIdentity(r); identity != "" {
		return identity, true
	}

	sourceIP := r.RemoteAddr
	if cfg.AuthChain != nil && cfg.AuthChain.Enabled() {
		bearer := extractBearer(r)
		if bearer == "" {
			audit.LogAuthFailure(cfg.Logger, sourceIP)
			http.Error(w, "missing authorization", http.StatusUnauthorized)
			return "", false
		}
		identity, err := cfg.AuthChain.Authenticate(bearer)
		if err != nil {
			audit.LogAuthFailure(cfg.Logger, sourceIP)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return "", false
		}
		return identity, true
	}
	return "", true
}

// ---------------------------------------------------------------------------
// Per-connection handlers (backward compatible)
// ---------------------------------------------------------------------------

func connectHandler(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenName, ok := authenticateRequest(cfg, w, r)
		if !ok {
			return
		}

		target := r.URL.Query().Get("target")
		if target == "" {
			http.Error(w, "missing target parameter", http.StatusBadRequest)
			return
		}

		if err := validateTarget(target); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		wsConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: true,
		})
		if err != nil {
			cfg.Logger.Error("websocket accept failed", "error", err)
			return
		}

		tcpConn, err := net.DialTimeout("tcp", target, 10*time.Second)
		if err != nil {
			cfg.Logger.Error("tcp dial failed", "target", target, "error", err)
			_ = wsConn.Close(websocket.StatusInternalError, "dial failed")
			return
		}

		audit.LogOpen(cfg.Logger, tokenName, r.RemoteAddr, target)
		if cfg.Stats != nil {
			cfg.Stats.ConnectionOpened()
		}

		start := time.Now()
		wsNetConn := websocket.NetConn(context.Background(), wsConn, websocket.MessageBinary)
		tx, rx := relay.Relay(wsNetConn, tcpConn)
		duration := time.Since(start)

		audit.LogClose(cfg.Logger, tokenName, target, duration, tx, rx)
		if cfg.Stats != nil {
			cfg.Stats.ConnectionClosed(tx, rx)
		}
	}
}

func connectHTTPHandler(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT method required", http.StatusMethodNotAllowed)
			return
		}

		tokenName, ok := authenticateRequest(cfg, w, r)
		if !ok {
			return
		}

		target := r.Host
		if target == "" {
			target = r.URL.Host
		}
		if target == "" {
			http.Error(w, "missing target host", http.StatusBadRequest)
			return
		}

		if err := validateTarget(target); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		tcpConn, err := net.DialTimeout("tcp", target, 10*time.Second)
		if err != nil {
			cfg.Logger.Error("tcp dial failed", "target", target, "error", err)
			http.Error(w, "dial failed", http.StatusBadGateway)
			return
		}

		w.WriteHeader(http.StatusOK)

		hijacker, ok := w.(http.Hijacker)
		if !ok {
			cfg.Logger.Error("hijack not supported")
			_ = tcpConn.Close()
			return
		}

		clientConn, _, err := hijacker.Hijack()
		if err != nil {
			cfg.Logger.Error("hijack failed", "error", err)
			_ = tcpConn.Close()
			return
		}

		audit.LogOpen(cfg.Logger, tokenName, r.RemoteAddr, target)
		if cfg.Stats != nil {
			cfg.Stats.ConnectionOpened()
		}

		start := time.Now()
		tx, rx := relay.Relay(clientConn, tcpConn)
		duration := time.Since(start)

		audit.LogClose(cfg.Logger, tokenName, target, duration, tx, rx)
		if cfg.Stats != nil {
			cfg.Stats.ConnectionClosed(tx, rx)
		}
	}
}

func connectUDPHandler(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenName, ok := authenticateRequest(cfg, w, r)
		if !ok {
			return
		}

		wsConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: true,
		})
		if err != nil {
			cfg.Logger.Error("websocket accept failed", "error", err)
			return
		}
		defer func() { _ = wsConn.Close(websocket.StatusNormalClosure, "done") }()

		ctx := context.Background()

		audit.LogOpen(cfg.Logger, tokenName, r.RemoteAddr, "udp-relay")
		if cfg.Stats != nil {
			cfg.Stats.ConnectionOpened()
		}
		start := time.Now()
		var totalTx, totalRx int64

		for {
			_, msg, err := wsConn.Read(ctx)
			if err != nil {
				break
			}

			target, payload, err := parseUDPFrame(msg)
			if err != nil {
				cfg.Logger.Error("invalid udp frame", "error", err)
				continue
			}

			if err := validateTarget(target); err != nil {
				cfg.Logger.Warn("udp target blocked", "target", target)
				continue
			}

			udpAddr, err := net.ResolveUDPAddr("udp", target)
			if err != nil {
				continue
			}

			conn, err := net.DialUDP("udp", nil, udpAddr)
			if err != nil {
				continue
			}

			_, err = conn.Write(payload)
			if err != nil {
				_ = conn.Close()
				continue
			}
			totalTx += int64(len(payload))

			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			buf := make([]byte, 65535)
			n, _, err := conn.ReadFromUDP(buf)
			_ = conn.Close()
			if err != nil {
				continue
			}
			totalRx += int64(n)

			reply := buildUDPFrame(target, buf[:n])
			if err := wsConn.Write(ctx, websocket.MessageBinary, reply); err != nil {
				break
			}
		}

		duration := time.Since(start)
		audit.LogClose(cfg.Logger, tokenName, "udp-relay", duration, totalTx, totalRx)
		if cfg.Stats != nil {
			cfg.Stats.ConnectionClosed(totalTx, totalRx)
		}
	}
}

// ---------------------------------------------------------------------------
// Multiplexed session handler
// ---------------------------------------------------------------------------

func muxHandler(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenName, ok := authenticateRequest(cfg, w, r)
		if !ok {
			return
		}

		wsConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: true,
		})
		if err != nil {
			cfg.Logger.Error("websocket accept failed", "error", err)
			return
		}

		netConn := websocket.NetConn(context.Background(), wsConn, websocket.MessageBinary)
		session, err := yamux.Server(netConn, nil)
		if err != nil {
			cfg.Logger.Error("yamux session failed", "error", err)
			_ = wsConn.CloseNow()
			return
		}
		defer func() { _ = session.Close() }()

		cfg.Logger.Info("mux session established",
			"identity", tokenName, "remote", r.RemoteAddr)

		var reverseListeners []net.Listener
		defer func() {
			for _, ln := range reverseListeners {
				_ = ln.Close()
			}
		}()

		for {
			stream, err := session.Accept()
			if err != nil {
				break
			}

			cmd, addr, err := mux.ReadHeader(stream)
			if err != nil {
				cfg.Logger.Error("invalid stream header", "error", err)
				_ = stream.Close()
				continue
			}

			switch cmd {
			case mux.CmdConnect:
				go handleMuxConnect(cfg, stream, tokenName, r.RemoteAddr, addr)
			case mux.CmdReverseBind:
				if !cfg.Reverse {
					cfg.Logger.Warn("reverse tunneling not enabled, rejecting")
					_ = stream.Close()
					continue
				}
				ln, err := handleReverseBind(cfg, session, tokenName, addr)
				if err != nil {
					cfg.Logger.Error("reverse bind failed",
						"addr", addr, "error", err)
					_ = stream.Close()
					continue
				}
				reverseListeners = append(reverseListeners, ln)
			default:
				cfg.Logger.Error("unknown stream command", "cmd", cmd)
				_ = stream.Close()
			}
		}
	}
}

func handleMuxConnect(cfg Config, stream net.Conn, tokenName, remoteAddr, target string) {
	defer func() { _ = stream.Close() }()

	if err := validateTarget(target); err != nil {
		cfg.Logger.Warn("target blocked", "target", target, "error", err)
		return
	}

	tcpConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		cfg.Logger.Error("tcp dial failed", "target", target, "error", err)
		return
	}

	audit.LogOpen(cfg.Logger, tokenName, remoteAddr, target)
	if cfg.Stats != nil {
		cfg.Stats.ConnectionOpened()
	}

	start := time.Now()
	tx, rx := relay.Relay(stream, tcpConn)
	duration := time.Since(start)

	audit.LogClose(cfg.Logger, tokenName, target, duration, tx, rx)
	if cfg.Stats != nil {
		cfg.Stats.ConnectionClosed(tx, rx)
	}
}

func handleReverseBind(cfg Config, session *yamux.Session, tokenName, bindAddr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return nil, err
	}
	cfg.Logger.Info("reverse listener started",
		"bind", ln.Addr().String(), "identity", tokenName)

	go func() {
		defer func() { _ = ln.Close() }()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleReverseConn(cfg, session, conn, tokenName, bindAddr)
		}
	}()

	return ln, nil
}

func handleReverseConn(cfg Config, session *yamux.Session, conn net.Conn, tokenName, bindAddr string) {
	stream, err := session.Open()
	if err != nil {
		cfg.Logger.Error("open reverse stream failed", "error", err)
		_ = conn.Close()
		return
	}

	if err := mux.WriteHeader(stream, mux.CmdReverseConn, bindAddr); err != nil {
		cfg.Logger.Error("write reverse header failed", "error", err)
		_ = stream.Close()
		_ = conn.Close()
		return
	}

	audit.LogOpen(cfg.Logger, tokenName, conn.RemoteAddr().String(), "reverse:"+bindAddr)
	if cfg.Stats != nil {
		cfg.Stats.ConnectionOpened()
	}

	start := time.Now()
	tx, rx := relay.Relay(stream, conn)
	duration := time.Since(start)

	audit.LogClose(cfg.Logger, tokenName, "reverse:"+bindAddr, duration, tx, rx)
	if cfg.Stats != nil {
		cfg.Stats.ConnectionClosed(tx, rx)
	}
}

// ---------------------------------------------------------------------------
// UDP framing helpers
// ---------------------------------------------------------------------------

func parseUDPFrame(data []byte) (target string, payload []byte, err error) {
	if len(data) < 7 {
		return "", nil, fmt.Errorf("frame too short")
	}

	atyp := data[3]
	var host string
	var addrEnd int

	switch atyp {
	case 0x01: // IPv4
		if len(data) < 10 {
			return "", nil, fmt.Errorf("frame too short for IPv4")
		}
		host = net.IP(data[4:8]).String()
		addrEnd = 8
	case 0x03: // Domain
		dlen := int(data[4])
		if len(data) < 5+dlen+2 {
			return "", nil, fmt.Errorf("frame too short for domain")
		}
		host = string(data[5 : 5+dlen])
		addrEnd = 5 + dlen
	case 0x04: // IPv6
		if len(data) < 22 {
			return "", nil, fmt.Errorf("frame too short for IPv6")
		}
		host = net.IP(data[4:20]).String()
		addrEnd = 20
	default:
		return "", nil, fmt.Errorf("unknown address type: %d", atyp)
	}

	if len(data) < addrEnd+2 {
		return "", nil, fmt.Errorf("frame too short for port")
	}

	port := int(data[addrEnd])<<8 | int(data[addrEnd+1])
	target = fmt.Sprintf("%s:%d", host, port)
	payload = data[addrEnd+2:]
	return target, payload, nil
}

func buildUDPFrame(target string, payload []byte) []byte {
	host, portStr, _ := net.SplitHostPort(target)
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	ip := net.ParseIP(host)
	var frame []byte

	frame = append(frame, 0, 0, 0)

	if ip4 := ip.To4(); ip4 != nil {
		frame = append(frame, 0x01)
		frame = append(frame, ip4...)
	} else if ip != nil {
		frame = append(frame, 0x04)
		frame = append(frame, ip.To16()...)
	} else {
		frame = append(frame, 0x03)
		frame = append(frame, byte(len(host)))
		frame = append(frame, []byte(host)...)
	}

	frame = append(frame, byte(port>>8), byte(port&0xff))
	frame = append(frame, payload...)
	return frame
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

func extractBearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(h, "Bearer ")
}

func validateTarget(target string) error {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}

	ip := net.ParseIP(host)
	if ip != nil {
		if ip.IsLoopback() || ip.IsUnspecified() {
			return fmt.Errorf("target %s is not allowed", target)
		}
	}

	blocked := []string{"localhost", "127.0.0.1", "::1", "0.0.0.0"}
	for _, b := range blocked {
		if strings.EqualFold(host, b) {
			return fmt.Errorf("target %s is not allowed", target)
		}
	}

	if ip == nil {
		addrs, err := net.LookupHost(host)
		if err == nil {
			for _, a := range addrs {
				resolved := net.ParseIP(a)
				if resolved != nil && (resolved.IsLoopback() || resolved.IsUnspecified()) {
					return fmt.Errorf("target %s resolves to loopback", target)
				}
			}
		}
	}

	return nil
}
