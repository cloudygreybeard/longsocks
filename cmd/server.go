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

package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cloudygreybeard/longsocks/internal/audit"
	"github.com/cloudygreybeard/longsocks/internal/auth"
	"github.com/cloudygreybeard/longsocks/internal/fingerprint"
	"github.com/cloudygreybeard/longsocks/internal/server"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the WebSocket relay server",
	Long:  `Start a server that accepts WebSocket connections on /connect and relays them to TCP targets.`,
	RunE:  runServer,
}

func init() {
	f := serverCmd.Flags()
	f.String("addr", ":8080", "Address to bind the WebSocket relay server")
	f.String("token", "", "Single static bearer token (or LONGSOCKS_TOKEN env)")
	f.String("tokens-dir", "", "Directory of token files for multi-user static auth")
	f.String("jwt-key", "", "Path to HMAC secret or PEM public key for JWT verification")
	f.String("jwt-revoke-file", "", "Path to file of revoked sub/jti values")
	f.String("oidc-issuer", "", "OIDC issuer URL for external IdP validation")
	f.String("oidc-audience", "longsocks", "Expected aud claim for OIDC tokens")
	f.String("oidc-claim-name", "sub", "OIDC claim to use as identity")
	f.String("audit-log", "", "Path to write audit events as JSON lines")
	f.String("metrics-addr", "", "Address to expose Prometheus metrics (e.g. :9090)")
	f.Duration("stats-interval", 0, "Interval for periodic aggregate stats (0 disables)")

	f.StringSlice("modes", []string{"socks5"}, "Enabled proxy modes (socks5, socks5-udp, connect)")
	f.String("tls-cert", "", "Path to TLS certificate PEM file")
	f.String("tls-key", "", "Path to TLS private key PEM file")
	f.Bool("tls-auto", false, "Enable automatic TLS via Let's Encrypt (ACME)")
	f.String("tls-domain", "", "Domain for ACME certificate (required with --tls-auto)")
	f.String("tls-ca", "", "Path to CA certificate PEM for mutual TLS client verification")

	f.Bool("reverse", false, "Allow clients to create reverse tunnels")
	f.String("keyfile", "", "Path to Ed25519 seed file for server identity (generated if empty)")

	rootCmd.AddCommand(serverCmd)
}

func runServer(cmd *cobra.Command, _ []string) error {
	addr, _ := cmd.Flags().GetString("addr")
	tokenFlag, _ := cmd.Flags().GetString("token")
	tokensDir, _ := cmd.Flags().GetString("tokens-dir")
	jwtKey, _ := cmd.Flags().GetString("jwt-key")
	jwtRevokeFile, _ := cmd.Flags().GetString("jwt-revoke-file")
	oidcIssuer, _ := cmd.Flags().GetString("oidc-issuer")
	oidcAudience, _ := cmd.Flags().GetString("oidc-audience")
	oidcClaimName, _ := cmd.Flags().GetString("oidc-claim-name")
	auditLog, _ := cmd.Flags().GetString("audit-log")
	metricsAddr, _ := cmd.Flags().GetString("metrics-addr")
	statsInterval, _ := cmd.Flags().GetDuration("stats-interval")
	modes, _ := cmd.Flags().GetStringSlice("modes")
	tlsCert, _ := cmd.Flags().GetString("tls-cert")
	tlsKey, _ := cmd.Flags().GetString("tls-key")
	tlsAuto, _ := cmd.Flags().GetBool("tls-auto")
	tlsDomain, _ := cmd.Flags().GetString("tls-domain")
	tlsCA, _ := cmd.Flags().GetString("tls-ca")
	reverse, _ := cmd.Flags().GetBool("reverse")
	keyFile, _ := cmd.Flags().GetString("keyfile")

	if tokenFlag != "" && tokensDir != "" {
		return fmt.Errorf("--token and --tokens-dir are mutually exclusive")
	}

	if tlsAuto && tlsDomain == "" {
		return fmt.Errorf("--tls-domain is required when --tls-auto is enabled")
	}

	if (tlsCert == "") != (tlsKey == "") {
		return fmt.Errorf("--tls-cert and --tls-key must both be specified")
	}

	validModes := map[string]bool{"socks5": true, "socks5-udp": true, "connect": true}
	for _, m := range modes {
		if !validModes[strings.TrimSpace(m)] {
			return fmt.Errorf("unknown mode: %s (valid: socks5, socks5-udp, connect)", m)
		}
	}

	if tokenFlag == "" {
		tokenFlag = os.Getenv("LONGSOCKS_TOKEN")
	}

	var handlers []slog.Handler
	handlers = append(handlers, slog.NewJSONHandler(os.Stderr, nil))

	if auditLog != "" {
		f, err := os.OpenFile(auditLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("opening audit log: %w", err)
		}
		defer func() { _ = f.Close() }()
		handlers = append(handlers, slog.NewJSONHandler(f, nil))
	}

	var metrics *audit.Metrics
	if metricsAddr != "" {
		metrics = audit.NewMetrics()
		handlers = append(handlers, audit.NewMetricsHandler(metrics))
		go func() {
			if err := audit.StartMetricsServer(metricsAddr); err != nil {
				fmt.Fprintf(os.Stderr, "metrics server error: %v\n", err)
			}
		}()
	}

	logger := slog.New(audit.NewFanOutHandler(handlers...))

	var stats *audit.StatsAggregator
	if statsInterval > 0 {
		stats = audit.NewStatsAggregator(logger)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go stats.Run(ctx, statsInterval)
	}

	var authenticators []auth.Authenticator

	if tokenFlag != "" {
		authenticators = append(authenticators, auth.NewStaticToken(tokenFlag))
	}
	if tokensDir != "" {
		sa, err := auth.NewStaticDir(tokensDir)
		if err != nil {
			return fmt.Errorf("loading tokens directory: %w", err)
		}
		defer sa.Stop()
		authenticators = append(authenticators, sa)
	}
	if jwtKey != "" {
		ja, err := auth.NewJWTAuthenticator(jwtKey, jwtRevokeFile)
		if err != nil {
			return fmt.Errorf("initializing JWT auth: %w", err)
		}
		defer ja.Stop()
		authenticators = append(authenticators, ja)
	}
	if oidcIssuer != "" {
		oa, err := auth.NewOIDCAuthenticator(oidcIssuer, oidcAudience, oidcClaimName)
		if err != nil {
			return fmt.Errorf("initializing OIDC auth: %w", err)
		}
		defer oa.Stop()
		authenticators = append(authenticators, oa)
	}

	var chain *auth.AuthChain
	if len(authenticators) > 0 {
		chain = auth.NewAuthChain(authenticators...)
	}

	if chain != nil && chain.Enabled() {
		logger.Info("authentication enabled", "layers", len(authenticators))
	} else {
		logger.Info("authentication disabled, server is open")
	}

	pub, _, err := fingerprint.LoadOrGenerate(keyFile)
	if err != nil {
		return fmt.Errorf("loading server key: %w", err)
	}
	fp := fingerprint.Compute(pub)
	if keyFile != "" {
		logger.Info("server fingerprint", "fingerprint", fp, "keyfile", keyFile)
	} else {
		logger.Info("server fingerprint (ephemeral)", "fingerprint", fp)
	}

	cfg := server.Config{
		Addr:        addr,
		AuthChain:   chain,
		Logger:      logger,
		Stats:       stats,
		Modes:       modes,
		TLSCert:     tlsCert,
		TLSKey:      tlsKey,
		TLSAuto:     tlsAuto,
		TLSDomain:   tlsDomain,
		TLSCA:       tlsCA,
		Reverse:     reverse,
		Fingerprint: fp,
	}

	return server.ListenAndServe(cfg)
}
