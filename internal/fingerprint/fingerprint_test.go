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

package fingerprint

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerate(t *testing.T) {
	pub, priv, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("public key size = %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("private key size = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
}

func TestCompute_Deterministic(t *testing.T) {
	pub, _, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	fp1 := Compute(pub)
	fp2 := Compute(pub)
	if fp1 != fp2 {
		t.Errorf("fingerprint not deterministic: %q != %q", fp1, fp2)
	}
}

func TestCompute_IsBase64SHA256(t *testing.T) {
	pub, _, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	fp := Compute(pub)
	decoded, err := base64.StdEncoding.DecodeString(fp)
	if err != nil {
		t.Fatalf("fingerprint is not valid base64: %v", err)
	}
	if len(decoded) != 32 {
		t.Errorf("decoded length = %d, want 32 (SHA-256)", len(decoded))
	}
}

func TestCompute_DifferentKeys(t *testing.T) {
	pub1, _, _ := Generate()
	pub2, _, _ := Generate()
	if Compute(pub1) == Compute(pub2) {
		t.Error("different keys should produce different fingerprints")
	}
}

func TestLoadOrGenerate_EmptyPath(t *testing.T) {
	pub, priv, err := LoadOrGenerate("")
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("public key size = %d", len(pub))
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("private key size = %d", len(priv))
	}
}

func TestLoadOrGenerate_ValidKeyFile(t *testing.T) {
	_, priv, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	seed := priv.Seed()

	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, seed, 0600); err != nil {
		t.Fatal(err)
	}

	pub, priv2, err := LoadOrGenerate(path)
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}

	if Compute(pub) != Compute(priv2.Public().(ed25519.PublicKey)) {
		t.Error("public key mismatch")
	}
	if Compute(pub) != Compute(priv.Public().(ed25519.PublicKey)) {
		t.Error("loaded key differs from original")
	}
}

func TestLoadOrGenerate_WrongSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad")
	if err := os.WriteFile(path, []byte("tooshort"), 0600); err != nil {
		t.Fatal(err)
	}
	_, _, err := LoadOrGenerate(path)
	if err == nil {
		t.Fatal("expected error for wrong-size key file")
	}
}

func TestLoadOrGenerate_MissingFile(t *testing.T) {
	_, _, err := LoadOrGenerate("/nonexistent/path/key")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
