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
	"github.com/spf13/cobra"
)

// Version information set via ldflags at build time.
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "longsocks",
	Short: "Authenticated proxy tunneled over WebSockets",
	Long: `Authenticated proxy tunneled over WebSockets. Provides SOCKS5,
HTTP CONNECT, and multiplexed tunnel access with identity-aware access
control and structured audit logging. Operates in userspace on
unprivileged ports and works through any HTTP infrastructure.

Subcommands:
  server   - WebSocket relay that accepts connections and dials targets
  client   - local proxy that tunnels through a longsocks server
  forward  - forward or reverse-forward ports through a longsocks server
  token    - JWT issuance and verification for authentication`,
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}
