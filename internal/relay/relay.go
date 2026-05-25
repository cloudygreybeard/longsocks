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

// Package relay provides bidirectional data copy between two connections
// with byte counting for audit purposes.
package relay

import (
	"io"
	"sync"
	"sync/atomic"
)

type countingWriter struct {
	w io.Writer
	n atomic.Int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n.Add(int64(n))
	return n, err
}

// Relay copies data bidirectionally between a and b until one side
// reaches EOF or an error. It returns the number of bytes written to
// a (tx) and to b (rx).
func Relay(a, b io.ReadWriteCloser) (tx, rx int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	cw := &countingWriter{w: a}
	cr := &countingWriter{w: b}
	cp := func(dst *countingWriter, src io.ReadCloser) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if c, ok := dst.w.(io.Closer); ok {
			_ = c.Close()
		}
	}
	go cp(cw, b)
	go cp(cr, a)
	wg.Wait()
	return cw.n.Load(), cr.n.Load()
}
