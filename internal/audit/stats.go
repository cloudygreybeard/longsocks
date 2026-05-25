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

package audit

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// StatsAggregator tracks connection and byte counters for periodic
// summary logging.
type StatsAggregator struct {
	activeConns atomic.Int64
	totalConns  atomic.Int64
	bytesTx     atomic.Int64
	bytesRx     atomic.Int64
	logger      *slog.Logger
}

// NewStatsAggregator creates a new aggregator that logs to the given logger.
func NewStatsAggregator(logger *slog.Logger) *StatsAggregator {
	return &StatsAggregator{logger: logger}
}

// ConnectionOpened increments active and total connection counters.
func (s *StatsAggregator) ConnectionOpened() {
	s.activeConns.Add(1)
	s.totalConns.Add(1)
}

// ConnectionClosed decrements the active counter and adds byte counts.
func (s *StatsAggregator) ConnectionClosed(tx, rx int64) {
	s.activeConns.Add(-1)
	s.bytesTx.Add(tx)
	s.bytesRx.Add(rx)
}

// Run logs periodic stats summaries at the given interval until the
// context is cancelled. A zero interval disables the loop.
func (s *StatsAggregator) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.logger.Info("stats.periodic",
				"active_connections", s.activeConns.Load(),
				"total_connections", s.totalConns.Load(),
				"bytes_tx_total", s.bytesTx.Load(),
				"bytes_rx_total", s.bytesRx.Load(),
			)
		case <-ctx.Done():
			return
		}
	}
}
