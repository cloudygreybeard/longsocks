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
	"bufio"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTAuthenticator validates bearer tokens as JWTs signed by the
// built-in longsocks issuer.
type JWTAuthenticator struct {
	keyFunc jwt.Keyfunc

	revokeFile string
	revokeMu   sync.RWMutex
	revoked    map[string]struct{}
	stopCh     chan struct{}
}

// NewJWTAuthenticator creates an authenticator that verifies JWTs against
// the given key file. The key is auto-detected as HMAC secret or PEM
// public/private key.
func NewJWTAuthenticator(keyPath, revokeFile string) (*JWTAuthenticator, error) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading JWT key: %w", err)
	}

	keyFunc, err := buildKeyFunc(keyData)
	if err != nil {
		return nil, err
	}

	a := &JWTAuthenticator{
		keyFunc:    keyFunc,
		revokeFile: revokeFile,
		revoked:    make(map[string]struct{}),
		stopCh:     make(chan struct{}),
	}

	if revokeFile != "" {
		if err := a.loadRevocations(); err != nil {
			return nil, fmt.Errorf("loading revocation file: %w", err)
		}
		go a.watchRevocations()
	}

	return a, nil
}

func buildKeyFunc(keyData []byte) (jwt.Keyfunc, error) {
	block, _ := pem.Decode(keyData)
	if block == nil {
		secret := []byte(strings.TrimSpace(string(keyData)))
		return func(_ *jwt.Token) (interface{}, error) {
			return secret, nil
		}, nil
	}

	if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return rsaKeyFunc(key), nil
	}
	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		switch k := key.(type) {
		case *rsa.PublicKey:
			return rsaKeyFunc(k), nil
		case *ecdsa.PublicKey:
			return ecdsaKeyFunc(k), nil
		}
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return rsaKeyFunc(&key.PublicKey), nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch k := key.(type) {
		case *rsa.PrivateKey:
			return rsaKeyFunc(&k.PublicKey), nil
		case *ecdsa.PrivateKey:
			return ecdsaKeyFunc(&k.PublicKey), nil
		}
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return ecdsaKeyFunc(&key.PublicKey), nil
	}

	return nil, fmt.Errorf("unsupported PEM key type: %s", block.Type)
}

func rsaKeyFunc(pub *rsa.PublicKey) jwt.Keyfunc {
	return func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return pub, nil
	}
}

func ecdsaKeyFunc(pub *ecdsa.PublicKey) jwt.Keyfunc {
	return func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return pub, nil
	}
}

func (a *JWTAuthenticator) loadRevocations() error {
	f, err := os.Open(a.revokeFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer func() { _ = f.Close() }()

	revoked := make(map[string]struct{})
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			revoked[line] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	a.revokeMu.Lock()
	a.revoked = revoked
	a.revokeMu.Unlock()
	return nil
}

func (a *JWTAuthenticator) watchRevocations() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := a.loadRevocations(); err != nil {
				slog.Default().Error("reloading revocation file", "error", err)
			}
		case <-a.stopCh:
			return
		}
	}
}

// Stop halts the background revocation file watcher.
func (a *JWTAuthenticator) Stop() {
	close(a.stopCh)
}

// Authenticate parses the token as a JWT, verifies the signature, checks
// expiry, issuer, and revocation status. Returns the sub claim as identity.
func (a *JWTAuthenticator) Authenticate(tokenStr string) (string, error) {
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, a.keyFunc,
		jwt.WithValidMethods([]string{"HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}),
	)
	if err != nil || !token.Valid {
		return "", ErrUnauthorized
	}

	iss, _ := claims.GetIssuer()
	if iss != "longsocks" {
		return "", ErrUnauthorized
	}

	sub, _ := claims.GetSubject()
	if sub == "" {
		return "", ErrUnauthorized
	}

	if a.revokeFile != "" {
		a.revokeMu.RLock()
		_, subRevoked := a.revoked[sub]
		jti, _ := claims["jti"].(string)
		_, jtiRevoked := a.revoked[jti]
		a.revokeMu.RUnlock()
		if subRevoked || (jti != "" && jtiRevoked) {
			return "", ErrUnauthorized
		}
	}

	return sub, nil
}
