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

// Package audit provides structured logging with fan-out to multiple
// destinations, Prometheus metrics, and periodic stats aggregation.
package audit

import (
	"context"
	"log/slog"
	"time"
)

// FanOutHandler dispatches every log record to all wrapped handlers.
type FanOutHandler struct {
	handlers []slog.Handler
}

// NewFanOutHandler creates a handler that fans out to all given handlers.
func NewFanOutHandler(handlers ...slog.Handler) *FanOutHandler {
	return &FanOutHandler{handlers: handlers}
}

// Enabled returns true if any child handler is enabled for the given level.
func (f *FanOutHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range f.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

// Handle dispatches the record to all child handlers. Errors from
// individual handlers are intentionally ignored to avoid one failing
// sink blocking the others.
func (f *FanOutHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, h := range f.handlers {
		if h.Enabled(ctx, r.Level) {
			_ = h.Handle(ctx, r)
		}
	}
	return nil
}

// WithAttrs returns a new FanOutHandler with the given attributes added.
func (f *FanOutHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	handlers := make([]slog.Handler, len(f.handlers))
	for i, h := range f.handlers {
		handlers[i] = h.WithAttrs(attrs)
	}
	return &FanOutHandler{handlers: handlers}
}

// WithGroup returns a new FanOutHandler with the given group name.
func (f *FanOutHandler) WithGroup(name string) slog.Handler {
	handlers := make([]slog.Handler, len(f.handlers))
	for i, h := range f.handlers {
		handlers[i] = h.WithGroup(name)
	}
	return &FanOutHandler{handlers: handlers}
}

// LogOpen logs a connection.open event.
func LogOpen(logger *slog.Logger, tokenName, sourceIP, target string) {
	logger.Info("connection.open",
		"token", tokenName,
		"source", sourceIP,
		"target", target,
	)
}

// LogClose logs a connection.close event with transfer statistics.
func LogClose(logger *slog.Logger, tokenName, target string, duration time.Duration, bytesTx, bytesRx int64) {
	logger.Info("connection.close",
		"token", tokenName,
		"target", target,
		"duration_ms", duration.Milliseconds(),
		"bytes_tx", bytesTx,
		"bytes_rx", bytesRx,
	)
}

// LogAuthFailure logs an auth.failure event.
func LogAuthFailure(logger *slog.Logger, sourceIP string) {
	logger.Warn("auth.failure", "source", sourceIP)
}
