// Package metrics owns the Prometheus collectors and the /metrics HTTP handler.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// collectors holds every metric exposed by pproxy. All counters/gauges are
// pre-registered with a private registry so tests and the main binary share
// identical labels.
type collectors struct {
	registry *prometheus.Registry

	ActiveConnections  *prometheus.GaugeVec
	UpstreamHealthy    *prometheus.GaugeVec
	RequestsTotal      *prometheus.CounterVec
	RequestDuration    *prometheus.HistogramVec
	BytesTransferred   *prometheus.CounterVec
	HealthCheckTotal   *prometheus.CounterVec
	HealthCheckLatency *prometheus.HistogramVec
	UpstreamFailures   *prometheus.CounterVec
}

// c is the package-private singleton of collectors.
var c = newCollectors()

// newCollectors builds the metric set against a private registry.
func newCollectors() *collectors {
	r := prometheus.NewRegistry()

	mkGauge := func(name, help string, labels []string) *prometheus.GaugeVec {
		g := prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "pproxy",
			Name:      name,
			Help:      help,
		}, labels)
		r.MustRegister(g)
		return g
	}
	mkCounter := func(name, help string, labels []string) *prometheus.CounterVec {
		c := prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "pproxy",
			Name:      name,
			Help:      help,
		}, labels)
		r.MustRegister(c)
		return c
	}
	mkHist := func(name, help string, labels []string) *prometheus.HistogramVec {
		h := prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "pproxy",
			Name:      name,
			Help:      help,
		}, labels)
		r.MustRegister(h)
		return h
	}

	return &collectors{
		registry: r,
		ActiveConnections: mkGauge("active_connections",
			"Number of in-flight client connections per listener.", []string{"protocol", "listener"}),
		UpstreamHealthy: mkGauge("upstream_healthy",
			"1 if the upstream is currently considered healthy, 0 otherwise.", []string{"upstream", "type"}),
		RequestsTotal: mkCounter("requests_total",
			"Total client requests handled, partitioned by outcome.", []string{"protocol", "upstream", "outcome"}),
		RequestDuration: mkHist("request_duration_seconds",
			"End-to-end request duration in seconds.", []string{"protocol", "upstream"}),
		BytesTransferred: mkCounter("bytes_transferred_total",
			"Bytes proxied between client and upstream.", []string{"protocol", "upstream", "direction"}),
		HealthCheckTotal: mkCounter("health_check_total",
			"Health probe outcomes per upstream.", []string{"upstream", "type", "outcome"}),
		HealthCheckLatency: mkHist("health_check_duration_seconds",
			"Duration of an individual health probe.", []string{"upstream", "type"}),
		UpstreamFailures: mkCounter("upstream_failures_total",
			"Request-time upstream failures (dial/handshake).", []string{"upstream", "phase"}),
	}
}

// Handler returns an http.Handler that serves the metrics in the Prometheus
// text exposition format.
func Handler() http.Handler {
	return promhttp.HandlerFor(c.registry, promhttp.HandlerOpts{Registry: c.registry})
}

// Registry exposes the underlying registry so callers can register custom
// metrics under the same instance.
func Registry() *prometheus.Registry {
	return c.registry
}

// ActiveConnections is the per-listener in-flight connection gauge.
func ActiveConnections() *prometheus.GaugeVec { return c.ActiveConnections }

// UpstreamHealthy is the per-upstream health gauge.
func UpstreamHealthy() *prometheus.GaugeVec { return c.UpstreamHealthy }

// RequestsTotal counts handled requests partitioned by outcome.
func RequestsTotal() *prometheus.CounterVec { return c.RequestsTotal }

// RequestDuration measures end-to-end request duration.
func RequestDuration() *prometheus.HistogramVec { return c.RequestDuration }

// BytesTransferred counts bytes flowing in each direction.
func BytesTransferred() *prometheus.CounterVec { return c.BytesTransferred }

// HealthCheckTotal counts health probe outcomes.
func HealthCheckTotal() *prometheus.CounterVec { return c.HealthCheckTotal }

// HealthCheckLatency measures individual health probe latency.
func HealthCheckLatency() *prometheus.HistogramVec { return c.HealthCheckLatency }

// UpstreamFailures counts request-time upstream failures.
func UpstreamFailures() *prometheus.CounterVec { return c.UpstreamFailures }
