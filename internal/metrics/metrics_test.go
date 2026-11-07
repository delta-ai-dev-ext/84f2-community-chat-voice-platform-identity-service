package metrics

import (
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// gather returns all metric families from the registry keyed by name.
func gather(t *testing.T, registry *prometheus.Registry) map[string]*dto.MetricFamily {
	t.Helper()
	families, err := registry.Gather()
	require.NoError(t, err)
	out := make(map[string]*dto.MetricFamily, len(families))
	for _, family := range families {
		out[family.GetName()] = family
	}
	return out
}

// labelsOf flattens the labels of one metric sample.
func labelsOf(metric *dto.Metric) map[string]string {
	out := map[string]string{}
	for _, label := range metric.GetLabel() {
		out[label.GetName()] = label.GetValue()
	}
	return out
}

// classedError implements the ErrorClass interface.
type classedError string

func (e classedError) Error() string      { return string(e) }
func (e classedError) ErrorClass() string { return string(e) }

func TestNilMetricsAreSafe(t *testing.T) {
	t.Parallel()

	var m *Metrics
	m.RecordRegistration("success")
	m.RecordEmailVerification("success")
	m.RecordLogin("success")
	m.RecordPasswordReset("request", "accepted")
	m.RecordEmail("verification", "sent")
	m.ObserveRequest("/auth/login", "POST", 200, time.Millisecond)
	m.ObserveExternalCall("resend", "verification", time.Millisecond, nil)
	m.SetActiveSessions(3)
}

func TestRequestMetricsUseLowCardinalityLabels(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	m := New(registry)
	m.ObserveRequest("/auth/login", "POST", 200, 5*time.Millisecond)
	m.ObserveRequest("/auth/login", "POST", 401, 7*time.Millisecond)
	m.ObserveRequest("", "GET", 404, time.Millisecond)

	families := gather(t, registry)

	requests := families["http_requests_total"]
	require.NotNil(t, requests)
	require.Len(t, requests.GetMetric(), 3)

	var statuses []string
	for _, metric := range requests.GetMetric() {
		labels := labelsOf(metric)
		statuses = append(statuses, labels["status_class"])
		assert.NotEmpty(t, labels["route"])
		if labels["method"] == "POST" {
			assert.Equal(t, "/auth/login", labels["route"])
		}
	}
	assert.Contains(t, statuses, "2xx")
	assert.Contains(t, statuses, "4xx")

	// Unmatched paths collapse into a single low-cardinality route label.
	var unmatched bool
	for _, metric := range requests.GetMetric() {
		if labelsOf(metric)["route"] == "unmatched" {
			unmatched = true
		}
	}
	assert.True(t, unmatched)

	durations := families["http_request_duration_seconds"]
	require.NotNil(t, durations)
	var samples uint64
	for _, metric := range durations.GetMetric() {
		samples += metric.GetHistogram().GetSampleCount()
	}
	assert.Equal(t, uint64(3), samples)
}

func TestBusinessCounters(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	m := New(registry)
	m.RecordRegistration("success")
	m.RecordRegistration("success")
	m.RecordEmailVerification("expired")
	m.RecordLogin("invalid_credentials")
	m.RecordPasswordReset("confirm", "success")
	m.RecordEmail("verification", "sent")

	families := gather(t, registry)
	for _, name := range []string{
		"identity_registrations_total",
		"identity_email_verifications_total",
		"identity_logins_total",
		"identity_password_resets_total",
		"identity_emails_sent_total",
	} {
		require.Contains(t, families, name)
	}

	registration := families["identity_registrations_total"]
	require.Len(t, registration.GetMetric(), 1)
	assert.Equal(t, float64(2), registration.GetMetric()[0].GetCounter().GetValue())
	assert.Equal(t, "success", labelsOf(registration.GetMetric()[0])["result"])

	reset := families["identity_password_resets_total"]
	assert.Equal(t, "confirm", labelsOf(reset.GetMetric()[0])["stage"])
}

func TestExternalCallMetrics(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	m := New(registry)
	m.ObserveExternalCall("resend", "verification", 10*time.Millisecond, nil)
	m.ObserveExternalCall("resend", "verification", 20*time.Millisecond, classedError("rate_limited"))
	m.ObserveExternalCall("resend", "verification", 20*time.Millisecond, errors.New("mystery"))

	families := gather(t, registry)

	durations := families["external_call_duration_seconds"]
	require.NotNil(t, durations)
	assert.Equal(t, uint64(3), durations.GetMetric()[0].GetHistogram().GetSampleCount())
	assert.Equal(t, "resend", labelsOf(durations.GetMetric()[0])["provider"])

	errorsFamily := families["external_call_errors_total"]
	require.NotNil(t, errorsFamily)
	require.Len(t, errorsFamily.GetMetric(), 2)
	classes := map[string]bool{}
	for _, metric := range errorsFamily.GetMetric() {
		classes[labelsOf(metric)["error_class"]] = true
	}
	assert.True(t, classes["rate_limited"])
	assert.True(t, classes["unknown"])
	assert.False(t, classes["none"], "successful calls are not counted as errors")
}

func TestActiveSessionsGauge(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	m := New(registry)
	m.SetActiveSessions(42)

	families := gather(t, registry)
	gauge := families["identity_active_sessions"]
	require.NotNil(t, gauge)
	assert.Equal(t, float64(42), gauge.GetMetric()[0].GetGauge().GetValue())
}

func TestNewToleratesDuplicateRegistration(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	first := New(registry)
	second := New(registry)
	require.NotNil(t, first)
	require.NotNil(t, second, "a second construction on the same registry must not panic")

	// The first instance owns the registered collectors; recording through it
	// must still be visible exactly once.
	first.RecordRegistration("success")
	families := gather(t, registry)
	assert.Equal(t, float64(1), families["identity_registrations_total"].GetMetric()[0].GetCounter().GetValue())
}

func TestStatusClass(t *testing.T) {
	t.Parallel()

	cases := map[int]string{100: "1xx", 204: "2xx", 301: "3xx", 418: "4xx", 500: "5xx", 0: "1xx", 900: "5xx"}
	for status, want := range cases {
		assert.Equal(t, want, StatusClass(status), status)
	}
}

func TestErrorClass(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "none", ErrorClass(nil))
	assert.Equal(t, "unknown", ErrorClass(errors.New("mystery")))
	assert.Equal(t, "rate_limited", ErrorClass(classedError("rate_limited")))
}
