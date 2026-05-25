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
	"crypto/subtle"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// StaticAuthenticator validates bearer tokens against a fixed set of
// name->value pairs. It supports single-token mode and directory-based
// multi-user mode with periodic hot-reloading.
type StaticAuthenticator struct {
	mu     sync.RWMutex
	tokens map[string]string // token value -> token name

	dir    string
	stopCh chan struct{}
}

// NewStaticToken creates an authenticator for a single static token.
// The identity for audit logs is "anonymous".
func NewStaticToken(token string) *StaticAuthenticator {
	return &StaticAuthenticator{
		tokens: map[string]string{token: "anonymous"},
	}
}

// NewStaticDir creates an authenticator that loads tokens from a directory.
// Each filename is the token name; each file's trimmed content is the token
// value. The directory is rescanned every 30 seconds.
func NewStaticDir(dir string) (*StaticAuthenticator, error) {
	s := &StaticAuthenticator{
		dir:    dir,
		stopCh: make(chan struct{}),
	}
	if err := s.reload(); err != nil {
		return nil, fmt.Errorf("loading tokens directory: %w", err)
	}
	go s.watchLoop()
	return s, nil
}

func (s *StaticAuthenticator) reload() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	tokens := make(map[string]string)
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.dir, e.Name()))
		if err != nil {
			return fmt.Errorf("reading token file %s: %w", e.Name(), err)
		}
		val := strings.TrimSpace(string(data))
		if val != "" {
			tokens[val] = e.Name()
		}
	}
	s.mu.Lock()
	s.tokens = tokens
	s.mu.Unlock()
	return nil
}

func (s *StaticAuthenticator) watchLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := s.reload(); err != nil {
				slog.Default().Error("reloading tokens directory", "error", err)
			}
		case <-s.stopCh:
			return
		}
	}
}

// Stop halts the background directory watcher.
func (s *StaticAuthenticator) Stop() {
	if s.stopCh != nil {
		close(s.stopCh)
	}
}

// Authenticate checks the token against all loaded entries using
// constant-time comparison. Returns the token name on success.
func (s *StaticAuthenticator) Authenticate(token string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var matched string
	for val, name := range s.tokens {
		if subtle.ConstantTimeCompare([]byte(token), []byte(val)) == 1 {
			matched = name
		}
	}
	if matched != "" {
		return matched, nil
	}
	return "", ErrUnauthorized
}
