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
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/cloudygreybeard/longsocks/internal/client"
)

var forwardCmd = &cobra.Command{
	Use:   "forward [flags] SPEC [SPEC ...]",
	Short: "Forward ports through a longsocks server",
	Long: `Forward local ports to remote targets through a multiplexed
longsocks connection.

Each SPEC is a port forwarding rule:

  [bind_host:]bind_port:target_host:target_port    Forward
  R:[bind_host:]bind_port:target_host:target_port   Reverse

Examples:
  longsocks forward --server wss://HOST --token T 3000:db.internal:5432
  longsocks forward --server wss://HOST --token T R:8080:localhost:3000`,
	Args: cobra.MinimumNArgs(1),
	RunE: runForward,
}

func init() {
	f := forwardCmd.Flags()
	f.String("server", "", "WebSocket server URL")
	f.String("token", "", "Bearer token (or LONGSOCKS_TOKEN env)")
	f.String("fingerprint", "", "Expected server fingerprint")
	f.String("tls-cert", "", "Client TLS certificate for mutual TLS")
	f.String("tls-key", "", "Client TLS private key for mutual TLS")
	f.Int("max-retry-count", 0, "Max reconnection attempts (0 = unlimited)")
	f.Duration("max-retry-interval", 5*time.Minute, "Max delay between retries")

	must(forwardCmd.MarkFlagRequired("server"))
	rootCmd.AddCommand(forwardCmd)
}

func runForward(cmd *cobra.Command, args []string) error {
	serverURL, _ := cmd.Flags().GetString("server")
	token, _ := cmd.Flags().GetString("token")
	fp, _ := cmd.Flags().GetString("fingerprint")
	tlsCert, _ := cmd.Flags().GetString("tls-cert")
	tlsKey, _ := cmd.Flags().GetString("tls-key")
	maxRetry, _ := cmd.Flags().GetInt("max-retry-count")
	maxInterval, _ := cmd.Flags().GetDuration("max-retry-interval")

	if token == "" {
		token = os.Getenv("LONGSOCKS_TOKEN")
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	var forwards, reverses []client.PortForward
	for _, arg := range args {
		pf, err := parseForwardSpec(arg)
		if err != nil {
			return err
		}
		if pf.Reverse {
			reverses = append(reverses, pf)
		} else {
			forwards = append(forwards, pf)
		}
	}

	cfg := client.Config{
		ServerURL:        serverURL,
		Token:            token,
		Logger:           logger,
		Fingerprint:      fp,
		TLSCert:          tlsCert,
		TLSKey:           tlsKey,
		MaxRetryCount:    maxRetry,
		MaxRetryInterval: maxInterval,
	}
	return client.Forward(cfg, forwards, reverses)
}

func parseForwardSpec(spec string) (client.PortForward, error) {
	reverse := false
	if strings.HasPrefix(spec, "R:") {
		reverse = true
		spec = strings.TrimPrefix(spec, "R:")
	}

	parts := strings.Split(spec, ":")
	var bind, target string

	switch len(parts) {
	case 3:
		bind = "127.0.0.1:" + parts[0]
		target = parts[1] + ":" + parts[2]
	case 4:
		bind = parts[0] + ":" + parts[1]
		target = parts[2] + ":" + parts[3]
	default:
		return client.PortForward{}, fmt.Errorf(
			"invalid spec %q: expected [host:]port:host:port", spec)
	}

	return client.PortForward{
		Bind:    bind,
		Target:  target,
		Reverse: reverse,
	}, nil
}
