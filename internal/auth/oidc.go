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
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// OIDCAuthenticator validates bearer tokens as JWTs from an external
// OIDC identity provider.
type OIDCAuthenticator struct {
	issuer    string
	audience  string
	claimName string

	mu     sync.RWMutex
	jwks   map[string]interface{} // kid -> public key
	stopCh chan struct{}
}

type oidcDiscovery struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// NewOIDCAuthenticator creates an authenticator that validates JWTs using
// OIDC discovery and JWKS. It fetches keys on startup and refreshes them
// hourly.
func NewOIDCAuthenticator(issuer, audience, claimName string) (*OIDCAuthenticator, error) {
	a := &OIDCAuthenticator{
		issuer:    strings.TrimRight(issuer, "/"),
		audience:  audience,
		claimName: claimName,
		jwks:      make(map[string]interface{}),
		stopCh:    make(chan struct{}),
	}
	if err := a.refreshJWKS(); err != nil {
		return nil, fmt.Errorf("OIDC discovery: %w", err)
	}
	go a.watchLoop()
	return a, nil
}

func (a *OIDCAuthenticator) refreshJWKS() error {
	disc, err := fetchDiscovery(a.issuer)
	if err != nil {
		return err
	}
	keys, err := fetchJWKS(disc.JWKSURI)
	if err != nil {
		return err
	}

	jwks := make(map[string]interface{})
	for _, k := range keys.Keys {
		pub, err := parseJWK(k)
		if err != nil {
			continue
		}
		jwks[k.Kid] = pub
	}

	a.mu.Lock()
	a.jwks = jwks
	a.mu.Unlock()
	return nil
}

func fetchDiscovery(issuer string) (*oidcDiscovery, error) {
	resp, err := http.Get(issuer + "/.well-known/openid-configuration") //nolint:noctx
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery returned %d", resp.StatusCode)
	}
	var disc oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		return nil, err
	}
	return &disc, nil
}

func fetchJWKS(uri string) (*jwksResponse, error) {
	resp, err := http.Get(uri) //nolint:noctx
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS fetch returned %d", resp.StatusCode)
	}
	var keys jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return nil, err
	}
	return &keys, nil
}

func parseJWK(k jwkKey) (interface{}, error) {
	switch k.Kty {
	case "RSA":
		return parseRSAJWK(k)
	case "EC":
		return parseECJWK(k)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", k.Kty)
	}
}

func parseRSAJWK(k jwkKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

func parseECJWK(k jwkKey) (*ecdsa.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, err
	}

	curve, err := curveFromName(k.Crv)
	if err != nil {
		return nil, err
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

func curveFromName(name string) (ellipticCurve, error) {
	switch name {
	case "P-256":
		return ellipticP256(), nil
	case "P-384":
		return ellipticP384(), nil
	case "P-521":
		return ellipticP521(), nil
	default:
		return nil, fmt.Errorf("unsupported curve: %s", name)
	}
}

func (a *OIDCAuthenticator) watchLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := a.refreshJWKS(); err != nil {
				slog.Default().Error("refreshing JWKS", "error", err)
			}
		case <-a.stopCh:
			return
		}
	}
}

// Stop halts the background JWKS refresh loop.
func (a *OIDCAuthenticator) Stop() {
	close(a.stopCh)
}

// Authenticate parses the token as a JWT, verifies against the cached JWKS,
// and checks issuer, audience, and expiry.
func (a *OIDCAuthenticator) Authenticate(tokenStr string) (string, error) {
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, a.keyFuncFromJWKS)
	if err != nil || !token.Valid {
		if refreshErr := a.refreshJWKS(); refreshErr == nil {
			token, err = jwt.ParseWithClaims(tokenStr, claims, a.keyFuncFromJWKS)
		}
		if err != nil || !token.Valid {
			return "", ErrUnauthorized
		}
	}

	iss, _ := claims.GetIssuer()
	if iss != a.issuer {
		return "", ErrUnauthorized
	}

	aud, _ := claims.GetAudience()
	if !containsString(aud, a.audience) {
		return "", ErrUnauthorized
	}

	identity, ok := claims[a.claimName].(string)
	if !ok || identity == "" {
		return "", ErrUnauthorized
	}

	return identity, nil
}

func (a *OIDCAuthenticator) keyFuncFromJWKS(t *jwt.Token) (interface{}, error) {
	kid, ok := t.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("missing kid in token header")
	}

	a.mu.RLock()
	key, exists := a.jwks[kid]
	a.mu.RUnlock()
	if !exists {
		return nil, fmt.Errorf("unknown kid: %s", kid)
	}
	return key, nil
}

func containsString(ss []string, target string) bool {
	for _, s := range ss {
		if s == target {
			return true
		}
	}
	return false
}
