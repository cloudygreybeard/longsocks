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

package mux

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestWriteHeaderReadHeader_Roundtrip(t *testing.T) {
	tests := []struct {
		name string
		cmd  byte
		addr string
	}{
		{"connect", CmdConnect, "httpbin.org:80"},
		{"reverse-bind", CmdReverseBind, "0.0.0.0:3000"},
		{"reverse-conn", CmdReverseConn, "192.168.1.1:443"},
		{"empty-addr", CmdConnect, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteHeader(&buf, tc.cmd, tc.addr); err != nil {
				t.Fatalf("WriteHeader: %v", err)
			}

			cmd, addr, err := ReadHeader(&buf)
			if err != nil {
				t.Fatalf("ReadHeader: %v", err)
			}
			if cmd != tc.cmd {
				t.Errorf("cmd = %d, want %d", cmd, tc.cmd)
			}
			if addr != tc.addr {
				t.Errorf("addr = %q, want %q", addr, tc.addr)
			}
		})
	}
}

func TestWriteHeader_Format(t *testing.T) {
	var buf bytes.Buffer
	addr := "host:80"
	if err := WriteHeader(&buf, CmdConnect, addr); err != nil {
		t.Fatal(err)
	}

	b := buf.Bytes()
	if len(b) != 3+len(addr) {
		t.Fatalf("length = %d, want %d", len(b), 3+len(addr))
	}
	if b[0] != CmdConnect {
		t.Errorf("cmd byte = %d, want %d", b[0], CmdConnect)
	}
	addrLen := binary.BigEndian.Uint16(b[1:3])
	if int(addrLen) != len(addr) {
		t.Errorf("addr length = %d, want %d", addrLen, len(addr))
	}
	if string(b[3:]) != addr {
		t.Errorf("addr = %q, want %q", string(b[3:]), addr)
	}
}

func TestReadHeader_AddressLengthLimit(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(CmdConnect)
	_ = binary.Write(&buf, binary.BigEndian, uint16(4097))
	buf.WriteString(strings.Repeat("x", 4097))

	_, _, err := ReadHeader(&buf)
	if err == nil {
		t.Fatal("expected error for oversized address")
	}
	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestReadHeader_Truncated(t *testing.T) {
	// Only 2 bytes when 3 are needed for the header.
	buf := bytes.NewReader([]byte{0x01, 0x00})
	_, _, err := ReadHeader(buf)
	if err == nil {
		t.Fatal("expected error for truncated header")
	}
}

func TestReadHeader_TruncatedAddress(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(CmdConnect)
	_ = binary.Write(&buf, binary.BigEndian, uint16(10))
	buf.WriteString("short")

	_, _, err := ReadHeader(&buf)
	if err == nil {
		t.Fatal("expected error for truncated address")
	}
}

func TestCommandConstants(t *testing.T) {
	if CmdConnect != 0x01 {
		t.Errorf("CmdConnect = %d, want 1", CmdConnect)
	}
	if CmdReverseBind != 0x02 {
		t.Errorf("CmdReverseBind = %d, want 2", CmdReverseBind)
	}
	if CmdReverseConn != 0x03 {
		t.Errorf("CmdReverseConn = %d, want 3", CmdReverseConn)
	}
}
