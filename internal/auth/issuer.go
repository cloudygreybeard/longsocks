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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// IssueToken creates a signed JWT for the given identity. The algorithm
// parameter selects the signing method: hs256, rs256, or es256.
func IssueToken(keyPath, name string, expires time.Duration, algorithm string) (string, error) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("reading signing key: %w", err)
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"sub": name,
		"iss": "longsocks",
		"iat": now.Unix(),
		"exp": now.Add(expires).Unix(),
		"jti": uuid.NewString(),
	}

	var signingMethod jwt.SigningMethod
	var signingKey interface{}

	switch strings.ToLower(algorithm) {
	case "hs256", "":
		signingMethod = jwt.SigningMethodHS256
		signingKey = []byte(strings.TrimSpace(string(keyData)))
	case "rs256":
		signingMethod = jwt.SigningMethodRS256
		key, err := parseRSAPrivateKey(keyData)
		if err != nil {
			return "", err
		}
		signingKey = key
	case "es256":
		signingMethod = jwt.SigningMethodES256
		key, err := parseECPrivateKey(keyData)
		if err != nil {
			return "", err
		}
		signingKey = key
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	token := jwt.NewWithClaims(signingMethod, claims)
	return token.SignedString(signingKey)
}

func parseRSAPrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in key file")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, fmt.Errorf("PKCS8 key is not RSA")
	}
	return nil, fmt.Errorf("unable to parse RSA private key")
}

func parseECPrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in key file")
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if ecKey, ok := key.(*ecdsa.PrivateKey); ok {
			return ecKey, nil
		}
		return nil, fmt.Errorf("PKCS8 key is not ECDSA")
	}
	return nil, fmt.Errorf("unable to parse ECDSA private key")
}

// VerifyToken parses and validates a JWT, returning the claims as a map.
func VerifyToken(keyPath, tokenStr string) (jwt.MapClaims, error) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading key: %w", err)
	}

	keyFunc, err := buildKeyFunc(keyData)
	if err != nil {
		return nil, err
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, keyFunc,
		jwt.WithValidMethods([]string{"HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}),
	)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("token validation failed")
	}
	return claims, nil
}

// ellipticCurve is an alias to avoid importing crypto/elliptic in oidc.go.
type ellipticCurve = elliptic.Curve

func ellipticP256() elliptic.Curve { return elliptic.P256() }
func ellipticP384() elliptic.Curve { return elliptic.P384() }
func ellipticP521() elliptic.Curve { return elliptic.P521() }
