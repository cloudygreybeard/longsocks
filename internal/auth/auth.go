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

// Package auth provides a layered authentication chain for bearer tokens.
// It supports static tokens, built-in JWT, and external OIDC validation.
package auth

import "errors"

// ErrUnauthorized is returned when no authenticator accepts the token.
var ErrUnauthorized = errors.New("unauthorized")

// Authenticator validates a bearer token and returns an identity string.
type Authenticator interface {
	Authenticate(token string) (identity string, err error)
}

// AuthChain tries authenticators in order; the first success wins.
type AuthChain struct {
	authenticators []Authenticator
}

// NewAuthChain creates a chain from the given authenticators.
func NewAuthChain(authenticators ...Authenticator) *AuthChain {
	return &AuthChain{authenticators: authenticators}
}

// Authenticate tries each authenticator in order. Returns the identity from
// the first one that succeeds, or ErrUnauthorized if all fail.
func (c *AuthChain) Authenticate(token string) (string, error) {
	for _, a := range c.authenticators {
		if identity, err := a.Authenticate(token); err == nil {
			return identity, nil
		}
	}
	return "", ErrUnauthorized
}

// Enabled returns true if the chain has at least one authenticator.
func (c *AuthChain) Enabled() bool {
	return len(c.authenticators) > 0
}
