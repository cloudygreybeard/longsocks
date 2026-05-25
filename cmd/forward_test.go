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

package cmd

import (
	"testing"
)

func TestParseForwardSpec(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		bind    string
		target  string
		reverse bool
		wantErr bool
	}{
		{
			name:   "3-part forward",
			spec:   "3000:db.internal:5432",
			bind:   "127.0.0.1:3000",
			target: "db.internal:5432",
		},
		{
			name:   "4-part forward",
			spec:   "0.0.0.0:3000:db.internal:5432",
			bind:   "0.0.0.0:3000",
			target: "db.internal:5432",
		},
		{
			name:    "3-part reverse",
			spec:    "R:8080:localhost:3000",
			bind:    "127.0.0.1:8080",
			target:  "localhost:3000",
			reverse: true,
		},
		{
			name:    "4-part reverse",
			spec:    "R:0.0.0.0:8080:localhost:3000",
			bind:    "0.0.0.0:8080",
			target:  "localhost:3000",
			reverse: true,
		},
		{
			name:    "too few parts",
			spec:    "8080:localhost",
			wantErr: true,
		},
		{
			name:    "too many parts",
			spec:    "a:b:c:d:e",
			wantErr: true,
		},
		{
			name:    "empty string",
			spec:    "",
			wantErr: true,
		},
		{
			name:    "reverse too few parts",
			spec:    "R:8080",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pf, err := parseForwardSpec(tc.spec)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if pf.Bind != tc.bind {
				t.Errorf("Bind = %q, want %q", pf.Bind, tc.bind)
			}
			if pf.Target != tc.target {
				t.Errorf("Target = %q, want %q", pf.Target, tc.target)
			}
			if pf.Reverse != tc.reverse {
				t.Errorf("Reverse = %v, want %v", pf.Reverse, tc.reverse)
			}
		})
	}
}
