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

package backoff

import (
	"testing"
	"time"
)

func TestNew_DefaultMaxInterval(t *testing.T) {
	b := New(0, 0)
	if b.maxInterval != 5*time.Minute {
		t.Errorf("expected default maxInterval 5m, got %v", b.maxInterval)
	}
}

func TestNew_CustomMaxInterval(t *testing.T) {
	b := New(3, 30*time.Second)
	if b.maxInterval != 30*time.Second {
		t.Errorf("expected maxInterval 30s, got %v", b.maxInterval)
	}
	if b.maxRetries != 3 {
		t.Errorf("expected maxRetries 3, got %d", b.maxRetries)
	}
}

func TestNext_IncreasingDelays(t *testing.T) {
	b := New(0, 5*time.Minute)
	var prev time.Duration
	for i := 0; i < 5; i++ {
		d, ok := b.Next()
		if !ok {
			t.Fatalf("attempt %d: expected ok=true", i)
		}
		if i > 0 && d < prev/2 {
			t.Errorf("attempt %d: delay %v should generally increase (prev %v)", i, d, prev)
		}
		prev = d
	}
}

func TestNext_RespectsMaxInterval(t *testing.T) {
	max := 2 * time.Second
	b := New(0, max)

	// Advance enough attempts to hit the cap.
	for i := 0; i < 20; i++ {
		b.Next()
	}
	d, ok := b.Next()
	if !ok {
		t.Fatal("expected ok=true")
	}
	// With jitter range [0.5, 1.5), the delay should never exceed 1.5 * max.
	if d > time.Duration(float64(max)*1.5) {
		t.Errorf("delay %v exceeds 1.5 * maxInterval %v", d, max)
	}
}

func TestNext_MaxRetries(t *testing.T) {
	b := New(3, time.Second)
	for i := 0; i < 3; i++ {
		_, ok := b.Next()
		if !ok {
			t.Fatalf("attempt %d: expected ok=true", i)
		}
	}
	_, ok := b.Next()
	if ok {
		t.Error("expected ok=false after exhausting retries")
	}
}

func TestNext_UnlimitedRetries(t *testing.T) {
	b := New(0, time.Second)
	for i := 0; i < 100; i++ {
		_, ok := b.Next()
		if !ok {
			t.Fatalf("attempt %d: expected unlimited retries", i)
		}
	}
}

func TestReset(t *testing.T) {
	b := New(2, time.Second)
	b.Next()
	b.Next()

	_, ok := b.Next()
	if ok {
		t.Fatal("expected ok=false after 2 retries")
	}

	b.Reset()
	_, ok = b.Next()
	if !ok {
		t.Fatal("expected ok=true after Reset()")
	}
}

func TestNext_JitterRange(t *testing.T) {
	b := New(0, time.Hour)
	d, _ := b.Next()

	// Attempt 0: base delay = 1s, jitter in [0.5, 1.5), so delay in [0.5s, 1.5s).
	if d < 500*time.Millisecond || d >= 1500*time.Millisecond {
		t.Errorf("first delay %v outside expected jitter range [0.5s, 1.5s)", d)
	}
}
