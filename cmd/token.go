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
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/cloudygreybeard/longsocks/internal/auth"
)

var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "JWT token management",
	Long:  `Issue and verify JWT tokens for longsocks authentication.`,
}

var tokenIssueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issue a new JWT token",
	Long:  `Issue a signed JWT token for use with longsocks client authentication.`,
	RunE:  runTokenIssue,
}

var tokenVerifyCmd = &cobra.Command{
	Use:   "verify [token]",
	Short: "Verify a JWT token",
	Long:  `Verify and display the claims of a JWT token.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runTokenVerify,
}

func init() {
	issueFlags := tokenIssueCmd.Flags()
	issueFlags.String("name", "", "Identity name for the token (sub claim)")
	issueFlags.String("expires", "", "Token lifetime (e.g. 24h, 30d)")
	issueFlags.String("key", "", "Path to HMAC secret or PEM private key for signing")
	issueFlags.String("algorithm", "hs256", "Signing algorithm: hs256, rs256, or es256")

	must(tokenIssueCmd.MarkFlagRequired("name"))
	must(tokenIssueCmd.MarkFlagRequired("expires"))
	must(tokenIssueCmd.MarkFlagRequired("key"))

	verifyFlags := tokenVerifyCmd.Flags()
	verifyFlags.String("key", "", "Path to HMAC secret or PEM public key for verification")

	must(tokenVerifyCmd.MarkFlagRequired("key"))

	tokenCmd.AddCommand(tokenIssueCmd)
	tokenCmd.AddCommand(tokenVerifyCmd)
	rootCmd.AddCommand(tokenCmd)
}

func runTokenIssue(cmd *cobra.Command, _ []string) error {
	name, _ := cmd.Flags().GetString("name")
	expiresStr, _ := cmd.Flags().GetString("expires")
	keyPath, _ := cmd.Flags().GetString("key")
	algorithm, _ := cmd.Flags().GetString("algorithm")

	expires, err := parseDuration(expiresStr)
	if err != nil {
		return fmt.Errorf("parsing expiry: %w", err)
	}

	token, err := auth.IssueToken(keyPath, name, expires, algorithm)
	if err != nil {
		return fmt.Errorf("issuing token: %w", err)
	}

	fmt.Println(token)
	return nil
}

func runTokenVerify(cmd *cobra.Command, args []string) error {
	keyPath, _ := cmd.Flags().GetString("key")
	tokenStr := args[0]

	claims, err := auth.VerifyToken(keyPath, tokenStr)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	for k, v := range claims {
		switch k {
		case "iat", "exp":
			if ts, ok := v.(float64); ok {
				t := time.Unix(int64(ts), 0)
				fmt.Printf("  %s: %v (%s)\n", k, v, t.Format(time.RFC3339))
				continue
			}
		}
		fmt.Printf("  %s: %v\n", k, v)
	}
	return nil
}

// parseDuration extends time.ParseDuration with support for "d" (days).
func parseDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		s = strings.TrimSuffix(s, "d")
		var days int
		if _, err := fmt.Sscanf(s, "%d", &days); err != nil {
			return 0, fmt.Errorf("invalid day duration: %s", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// must panics if err is non-nil. Used for flag registration that cannot
// fail unless there is a programming error.
func must(err error) {
	if err != nil {
		panic(err)
	}
}
