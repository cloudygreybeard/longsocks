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
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
)

// MTLSIdentity extracts the client identity from a verified TLS peer
// certificate. Returns empty string if no client certificate is present.
func MTLSIdentity(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	cert := r.TLS.PeerCertificates[0]
	if cert.Subject.CommonName != "" {
		return "mtls:" + cert.Subject.CommonName
	}
	if len(cert.DNSNames) > 0 {
		return "mtls:" + cert.DNSNames[0]
	}
	return "mtls:" + cert.Subject.String()
}

// LoadCACertPool loads a PEM-encoded CA certificate bundle for client
// certificate verification.
func LoadCACertPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading CA certificate: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("no valid certificates in %s", path)
	}
	return pool, nil
}
