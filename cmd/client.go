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
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/cloudygreybeard/longsocks/internal/client"
)

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Start the local proxy client",
	Long:  `Start a local proxy that tunnels connections through a WebSocket to a longsocks server.`,
	RunE:  runClient,
}

func init() {
	f := clientCmd.Flags()
	f.String("addr", "127.0.0.1:1080", "Address to bind the local proxy")
	f.String("server", "", "WebSocket server URL (e.g. wss://ROUTE_HOSTNAME)")
	f.String("token", "", "Bearer token for server auth (or LONGSOCKS_TOKEN env)")
	f.String("mode", "socks5", "Proxy mode: socks5, socks5-udp, connect")
	f.Bool("mux", false, "Use multiplexed session (single WebSocket)")
	f.String("fingerprint", "", "Expected server fingerprint for verification")
	f.String("tls-cert", "", "Client TLS certificate for mutual TLS")
	f.String("tls-key", "", "Client TLS private key for mutual TLS")
	f.Int("max-retry-count", 0, "Max retry attempts per connection (0 = unlimited)")
	f.Duration("max-retry-interval", 5*time.Minute, "Max delay between retries")

	must(clientCmd.MarkFlagRequired("server"))

	rootCmd.AddCommand(clientCmd)
}

func runClient(cmd *cobra.Command, _ []string) error {
	addr, _ := cmd.Flags().GetString("addr")
	serverURL, _ := cmd.Flags().GetString("server")
	token, _ := cmd.Flags().GetString("token")
	mode, _ := cmd.Flags().GetString("mode")
	useMux, _ := cmd.Flags().GetBool("mux")
	fp, _ := cmd.Flags().GetString("fingerprint")
	tlsCert, _ := cmd.Flags().GetString("tls-cert")
	tlsKey, _ := cmd.Flags().GetString("tls-key")
	maxRetry, _ := cmd.Flags().GetInt("max-retry-count")
	maxInterval, _ := cmd.Flags().GetDuration("max-retry-interval")

	if token == "" {
		token = os.Getenv("LONGSOCKS_TOKEN")
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	cfg := client.Config{
		Addr:             addr,
		ServerURL:        serverURL,
		Token:            token,
		Logger:           logger,
		Mux:              useMux,
		Fingerprint:      fp,
		TLSCert:          tlsCert,
		TLSKey:           tlsKey,
		MaxRetryCount:    maxRetry,
		MaxRetryInterval: maxInterval,
	}

	switch mode {
	case "socks5":
		return client.ListenAndServe(cfg)
	case "socks5-udp":
		return client.ListenAndServeUDP(cfg)
	case "connect":
		return client.ListenAndServeConnect(cfg)
	default:
		return fmt.Errorf("unknown mode: %s (valid: socks5, socks5-udp, connect)", mode)
	}
}
