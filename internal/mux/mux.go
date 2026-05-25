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

// Package mux defines the stream multiplexing protocol for longsocks.
//
// Each yamux stream begins with a command header:
//
//	[1 byte cmd] [2 bytes addr length, big-endian] [N bytes addr]
//
// After the header, the stream carries raw bidirectional data.
package mux

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Stream command bytes.
const (
	CmdConnect     byte = 0x01 // Client -> server: dial target
	CmdReverseBind byte = 0x02 // Client -> server: register reverse listener
	CmdReverseConn byte = 0x03 // Server -> client: incoming reverse connection
)

// WriteHeader writes a stream command header.
func WriteHeader(w io.Writer, cmd byte, addr string) error {
	buf := make([]byte, 3+len(addr))
	buf[0] = cmd
	binary.BigEndian.PutUint16(buf[1:3], uint16(len(addr)))
	copy(buf[3:], addr)
	_, err := w.Write(buf)
	return err
}

// ReadHeader reads a stream command header.
func ReadHeader(r io.Reader) (cmd byte, addr string, err error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, "", fmt.Errorf("reading stream header: %w", err)
	}
	addrLen := binary.BigEndian.Uint16(hdr[1:3])
	if addrLen > 4096 {
		return 0, "", fmt.Errorf("address length %d exceeds maximum", addrLen)
	}
	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(r, addrBuf); err != nil {
		return 0, "", fmt.Errorf("reading stream address: %w", err)
	}
	return hdr[0], string(addrBuf), nil
}
