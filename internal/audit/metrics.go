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
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds the Prometheus collectors for longsocks.
type Metrics struct {
	ConnectionsTotal   *prometheus.CounterVec
	ConnectionsActive  *prometheus.GaugeVec
	BytesTransmitted   *prometheus.CounterVec
	AuthFailuresTotal  prometheus.Counter
	ConnectionDuration *prometheus.HistogramVec
}

// NewMetrics registers and returns the Prometheus metrics.
func NewMetrics() *Metrics {
	m := &Metrics{
		ConnectionsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "longsocks_connections_total",
			Help: "Total connections served.",
		}, []string{"token_name"}),
		ConnectionsActive: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "longsocks_connections_active",
			Help: "Currently active connections.",
		}, []string{"token_name"}),
		BytesTransmitted: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "longsocks_bytes_transmitted_total",
			Help: "Total bytes transferred.",
		}, []string{"token_name", "direction"}),
		AuthFailuresTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "longsocks_auth_failures_total",
			Help: "Total authentication failures.",
		}),
		ConnectionDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "longsocks_connection_duration_seconds",
			Help:    "Connection duration distribution.",
			Buckets: prometheus.ExponentialBuckets(0.1, 2, 15),
		}, []string{"token_name"}),
	}
	prometheus.MustRegister(
		m.ConnectionsTotal,
		m.ConnectionsActive,
		m.BytesTransmitted,
		m.AuthFailuresTotal,
		m.ConnectionDuration,
	)
	return m
}

// MetricsHandler is a slog.Handler that updates Prometheus counters
// from audit log events.
type MetricsHandler struct {
	metrics *Metrics
}

// NewMetricsHandler creates a slog handler backed by Prometheus metrics.
func NewMetricsHandler(m *Metrics) *MetricsHandler {
	return &MetricsHandler{metrics: m}
}

// Enabled returns true for Info and above.
func (h *MetricsHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelInfo
}

// Handle extracts audit event fields and updates the relevant counters.
func (h *MetricsHandler) Handle(_ context.Context, r slog.Record) error {
	var tokenName, direction string
	var bytesTx, bytesRx int64
	var durationMS int64

	r.Attrs(func(a slog.Attr) bool {
		switch a.Key {
		case "token":
			tokenName = a.Value.String()
		case "direction":
			direction = a.Value.String()
		case "bytes_tx":
			bytesTx = a.Value.Int64()
		case "bytes_rx":
			bytesRx = a.Value.Int64()
		case "duration_ms":
			durationMS = a.Value.Int64()
		}
		return true
	})

	switch r.Message {
	case "connection.open":
		if tokenName == "" {
			tokenName = "unknown"
		}
		h.metrics.ConnectionsTotal.WithLabelValues(tokenName).Inc()
		h.metrics.ConnectionsActive.WithLabelValues(tokenName).Inc()
	case "connection.close":
		if tokenName == "" {
			tokenName = "unknown"
		}
		h.metrics.ConnectionsActive.WithLabelValues(tokenName).Dec()
		h.metrics.BytesTransmitted.WithLabelValues(tokenName, "tx").Add(float64(bytesTx))
		h.metrics.BytesTransmitted.WithLabelValues(tokenName, "rx").Add(float64(bytesRx))
		h.metrics.ConnectionDuration.WithLabelValues(tokenName).Observe(float64(durationMS) / 1000.0)
	case "auth.failure":
		h.metrics.AuthFailuresTotal.Inc()
	}

	_ = direction
	return nil
}

// WithAttrs returns the handler unchanged (metrics don't use attrs).
func (h *MetricsHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }

// WithGroup returns the handler unchanged (metrics don't use groups).
func (h *MetricsHandler) WithGroup(_ string) slog.Handler { return h }

// StartMetricsServer starts an HTTP server exposing /metrics on the given
// address. It blocks until the server returns an error.
func StartMetricsServer(addr string) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	return http.ListenAndServe(addr, mux)
}
