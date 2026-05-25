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

// Package fingerprint provides Ed25519 key management and fingerprint
// computation for server identity verification.
package fingerprint

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
)

// Generate creates a new Ed25519 key pair.
func Generate() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating key: %w", err)
	}
	return pub, priv, nil
}

// LoadOrGenerate loads a private key seed from path, or generates a new
// key pair if path is empty.
func LoadOrGenerate(path string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if path == "" {
		return Generate()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("reading key file: %w", err)
	}
	if len(data) != ed25519.SeedSize {
		return nil, nil, fmt.Errorf(
			"key file must be %d bytes (ed25519 seed), got %d",
			ed25519.SeedSize, len(data),
		)
	}
	priv := ed25519.NewKeyFromSeed(data)
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv, nil
}

// Compute returns the base64-encoded SHA-256 fingerprint of a public key.
func Compute(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return base64.StdEncoding.EncodeToString(h[:])
}
