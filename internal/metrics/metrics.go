// Package metrics provides Prometheus instrumentation for the callout service
// and an optional HTTP endpoint that exposes it.
//
// A *Metrics value owns a private registry (no global state). All record methods
// are nil-safe, so callers can hold a nil *Metrics when metrics are disabled and
// instrument unconditionally.
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const namespace = "nats_oidc_callout"

// Denial reasons — low-cardinality label values for authorization_denials_total.
const (
	ReasonNoToken            = "no_token"
	ReasonVerificationFailed = "verification_failed"
	ReasonPolicyNoMatch      = "policy_no_match"
	ReasonSigningFailed      = "signing_failed"
)

// Metrics holds the collectors and the registry they are registered on.
type Metrics struct {
	registry *prometheus.Registry
	requests *prometheus.CounterVec // label: result (allowed|denied)
	denials  *prometheus.CounterVec // label: reason
	duration prometheus.Histogram
}

// New creates a Metrics with its own registry, also registering the standard Go
// runtime and process collectors.
func New() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		registry: reg,
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "authorization_requests_total",
			Help:      "Total authorization requests handled, by result.",
		}, []string{"result"}),
		denials: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "authorization_denials_total",
			Help:      "Total denied authorization requests, by reason.",
		}, []string{"reason"}),
		duration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "authorization_duration_seconds",
			Help:      "Authorization request handling latency in seconds.",
			Buckets:   prometheus.DefBuckets,
		}),
	}
	reg.MustRegister(m.requests, m.denials, m.duration)
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	// Initialize the result series so they are exported at 0 before any traffic.
	m.requests.WithLabelValues("allowed")
	m.requests.WithLabelValues("denied")
	return m
}

// Handler returns the HTTP handler that serves this registry in the Prometheus
// text exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// Registry returns the underlying registry (used by tests to gather).
func (m *Metrics) Registry() *prometheus.Registry { return m.registry }

// RecordAllowed records a successful authorization. Nil-safe.
func (m *Metrics) RecordAllowed(d time.Duration) {
	if m == nil {
		return
	}
	m.requests.WithLabelValues("allowed").Inc()
	m.duration.Observe(d.Seconds())
}

// RecordDenied records a denied authorization with the given reason. Nil-safe.
func (m *Metrics) RecordDenied(reason string, d time.Duration) {
	if m == nil {
		return
	}
	m.requests.WithLabelValues("denied").Inc()
	m.denials.WithLabelValues(reason).Inc()
	m.duration.Observe(d.Seconds())
}
