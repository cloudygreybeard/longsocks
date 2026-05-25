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

package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func generateSelfSignedPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestMTLSIdentity_NilTLS(t *testing.T) {
	r := &http.Request{}
	if id := MTLSIdentity(r); id != "" {
		t.Errorf("expected empty, got %q", id)
	}
}

func TestMTLSIdentity_NoPeerCerts(t *testing.T) {
	r := &http.Request{TLS: &tls.ConnectionState{}}
	if id := MTLSIdentity(r); id != "" {
		t.Errorf("expected empty, got %q", id)
	}
}

func TestMTLSIdentity_CommonName(t *testing.T) {
	r := &http.Request{
		TLS: &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{
				{Subject: pkix.Name{CommonName: "ci-runner"}},
			},
		},
	}
	if id := MTLSIdentity(r); id != "mtls:ci-runner" {
		t.Errorf("expected mtls:ci-runner, got %q", id)
	}
}

func TestMTLSIdentity_DNSName(t *testing.T) {
	r := &http.Request{
		TLS: &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{
				{DNSNames: []string{"client.example.com"}},
			},
		},
	}
	if id := MTLSIdentity(r); id != "mtls:client.example.com" {
		t.Errorf("expected mtls:client.example.com, got %q", id)
	}
}

func TestMTLSIdentity_FallbackSubject(t *testing.T) {
	r := &http.Request{
		TLS: &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{
				{Subject: pkix.Name{Organization: []string{"Acme"}}},
			},
		},
	}
	id := MTLSIdentity(r)
	if id == "" || id == "mtls:" {
		t.Errorf("expected non-empty fallback identity, got %q", id)
	}
}

func TestLoadCACertPool_Valid(t *testing.T) {
	pem := generateSelfSignedPEM(t)

	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem, 0600); err != nil {
		t.Fatal(err)
	}

	pool, err := LoadCACertPool(path)
	if err != nil {
		t.Fatalf("LoadCACertPool: %v", err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
}

func TestLoadCACertPool_InvalidPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(path, []byte("not a cert"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadCACertPool(path)
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestLoadCACertPool_MissingFile(t *testing.T) {
	_, err := LoadCACertPool("/nonexistent/ca.pem")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
