package authz

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// PromMetrics implementa Metrics com Prometheus.
type PromMetrics struct {
	requests *prometheus.CounterVec
	latency  *prometheus.HistogramVec
}

// NewPromMetrics registra os coletores em reg.
func NewPromMetrics(reg prometheus.Registerer) *PromMetrics {
	m := &PromMetrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ocsp_authz_requests_total",
			Help: "Decisões do ext_authz por resultado.",
		}, []string{"result"}),
		latency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "ocsp_authz_decision_seconds",
			Help:    "Latência da decisão (inclui a ida ao responder OCSP quando não há cache).",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
		}, []string{"result"}),
	}
	reg.MustRegister(m.requests, m.latency)
	return m
}

// Observe registra uma decisão.
func (m *PromMetrics) Observe(result string, dur time.Duration) {
	m.requests.WithLabelValues(result).Inc()
	m.latency.WithLabelValues(result).Observe(dur.Seconds())
}
