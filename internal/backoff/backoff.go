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

// Package backoff implements exponential backoff with jitter.
package backoff

import (
	"math"
	"math/rand/v2"
	"time"
)

// Backoff tracks retry state for exponential backoff with jitter.
type Backoff struct {
	attempt     int
	maxRetries  int
	maxInterval time.Duration
}

// New creates a Backoff. A maxRetries of 0 means unlimited.
func New(maxRetries int, maxInterval time.Duration) *Backoff {
	if maxInterval <= 0 {
		maxInterval = 5 * time.Minute
	}
	return &Backoff{
		maxRetries:  maxRetries,
		maxInterval: maxInterval,
	}
}

// Next returns the next backoff delay and whether retrying is permitted.
func (b *Backoff) Next() (time.Duration, bool) {
	if b.maxRetries > 0 && b.attempt >= b.maxRetries {
		return 0, false
	}
	delay := float64(time.Second) * math.Pow(2, float64(b.attempt))
	if delay > float64(b.maxInterval) {
		delay = float64(b.maxInterval)
	}
	jitter := 0.5 + rand.Float64()
	delay *= jitter
	b.attempt++
	return time.Duration(delay), true
}

// Reset restarts the backoff counter after a successful operation.
func (b *Backoff) Reset() {
	b.attempt = 0
}
