// Package metrics registers the business, RED and provider metrics defined in
// docs/architecture.md §6. Every label is low cardinality: no user, session or
// request identifiers are ever used as label values.
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Provider name used on external-call metrics.
const ProviderResend = "resend"

// Metrics holds every instrument exported by the service.
type Metrics struct {
	Registrations      *prometheus.CounterVec
	EmailVerifications *prometheus.CounterVec
	Logins             *prometheus.CounterVec
	PasswordResets     *prometheus.CounterVec
	ActiveSessions     prometheus.Gauge
	EmailsSent         *prometheus.CounterVec

	HTTPRequests        *prometheus.CounterVec
	HTTPRequestDuration *prometheus.HistogramVec

	ExternalCallDuration *prometheus.HistogramVec
	ExternalCallErrors   *prometheus.CounterVec
}

// New builds and registers the metrics on reg. Already-registered collectors
// are tolerated so tests can create isolated registries repeatedly.
func New(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		Registrations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "identity_registrations_total",
			Help: "Registration attempts by result.",
		}, []string{"result"}),
		EmailVerifications: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "identity_email_verifications_total",
			Help: "Email verification attempts by result.",
		}, []string{"result"}),
		Logins: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "identity_logins_total",
			Help: "Sign-in attempts by result.",
		}, []string{"result"}),
		PasswordResets: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "identity_password_resets_total",
			Help: "Password reset operations by stage and result.",
		}, []string{"stage", "result"}),
		ActiveSessions: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "identity_active_sessions",
			Help: "Number of sessions that are not revoked.",
		}),
		EmailsSent: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "identity_emails_sent_total",
			Help: "Transactional emails by kind and result.",
		}, []string{"kind", "result"}),
		HTTPRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "HTTP requests by route, method and status class.",
		}, []string{"route", "method", "status_class"}),
		HTTPRequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request latency by route and method.",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5},
		}, []string{"route", "method"}),
		ExternalCallDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "external_call_duration_seconds",
			Help:    "Latency of calls to external providers.",
			Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		}, []string{"provider", "operation"}),
		ExternalCallErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "external_call_errors_total",
			Help: "Failed calls to external providers by error class.",
		}, []string{"provider", "operation", "error_class"}),
	}

	for _, collector := range []prometheus.Collector{
		m.Registrations, m.EmailVerifications, m.Logins, m.PasswordResets,
		m.ActiveSessions, m.EmailsSent, m.HTTPRequests, m.HTTPRequestDuration,
		m.ExternalCallDuration, m.ExternalCallErrors,
	} {
		if err := reg.Register(collector); err != nil {
			if _, already := err.(prometheus.AlreadyRegisteredError); !already {
				// Registration failures are programming errors; surface them during
				// startup wiring rather than panicking in a request path.
				panic(err)
			}
		}
	}
	return m
}

// ObserveRequest records one HTTP request for the RED metrics.
func (m *Metrics) ObserveRequest(route, method string, status int, duration time.Duration) {
	if m == nil {
		return
	}
	if route == "" {
		route = "unmatched"
	}
	m.HTTPRequests.WithLabelValues(route, method, StatusClass(status)).Inc()
	m.HTTPRequestDuration.WithLabelValues(route, method).Observe(duration.Seconds())
}

// ObserveExternalCall records the latency and outcome of a provider call.
func (m *Metrics) ObserveExternalCall(provider, operation string, duration time.Duration, err error) {
	if m == nil {
		return
	}
	m.ExternalCallDuration.WithLabelValues(provider, operation).Observe(duration.Seconds())
	if err != nil {
		m.ExternalCallErrors.WithLabelValues(provider, operation, ErrorClass(err)).Inc()
	}
}

// RecordRegistration increments the registration counter.
func (m *Metrics) RecordRegistration(result string) {
	if m == nil {
		return
	}
	m.Registrations.WithLabelValues(result).Inc()
}

// RecordEmailVerification increments the verification counter.
func (m *Metrics) RecordEmailVerification(result string) {
	if m == nil {
		return
	}
	m.EmailVerifications.WithLabelValues(result).Inc()
}

// RecordLogin increments the sign-in counter.
func (m *Metrics) RecordLogin(result string) {
	if m == nil {
		return
	}
	m.Logins.WithLabelValues(result).Inc()
}

// RecordPasswordReset increments the password-reset counter.
func (m *Metrics) RecordPasswordReset(stage, result string) {
	if m == nil {
		return
	}
	m.PasswordResets.WithLabelValues(stage, result).Inc()
}

// RecordEmail increments the outbound email counter.
func (m *Metrics) RecordEmail(kind, result string) {
	if m == nil {
		return
	}
	m.EmailsSent.WithLabelValues(kind, result).Inc()
}

// SetActiveSessions sets the active-session gauge.
func (m *Metrics) SetActiveSessions(count int64) {
	if m == nil {
		return
	}
	m.ActiveSessions.Set(float64(count))
}

// StatusClass maps an HTTP status to its class label value (2xx, 3xx, ...).
func StatusClass(status int) string {
	switch {
	case status >= 500:
		return "5xx"
	case status >= 400:
		return "4xx"
	case status >= 300:
		return "3xx"
	case status >= 200:
		return "2xx"
	default:
		return "1xx"
	}
}

// ErrorClass buckets an error into a low-cardinality label value.
func ErrorClass(err error) string {
	if err == nil {
		return "none"
	}
	if configured, ok := err.(interface{ ErrorClass() string }); ok {
		return configured.ErrorClass()
	}
	return "unknown"
}
