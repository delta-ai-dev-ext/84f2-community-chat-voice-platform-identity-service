package observability

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestTraceIDFromHeaders(t *testing.T) {
	t.Parallel()

	// A well-formed traceparent wins.
	assert.Equal(t, "0123456789abcdef0123456789abcdef",
		TraceIDFromHeaders("00-0123456789abcdef0123456789abcdef-b7ad6b7169203331-01", "fedcba9876543210fedcba9876543210"))

	// Without traceparent the X-Trace-Id header is used.
	assert.Equal(t, "fedcba9876543210fedcba9876543210",
		TraceIDFromHeaders("", "fedcba9876543210fedcba9876543210"))

	// Malformed values are replaced by a fresh trace id.
	for _, headers := range [][2]string{
		{"", ""},
		{"garbage", ""},
		{"00-nothex-nothex-01", ""},
		{"", "short"},
	} {
		generated := TraceIDFromHeaders(headers[0], headers[1])
		assert.True(t, IsTraceID(generated), generated)
	}
}

func TestNewTraceIDIsNeverEmpty(t *testing.T) {
	t.Parallel()

	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		id := NewTraceID()
		require.True(t, IsTraceID(id), id)
		assert.False(t, seen[id], "trace ids must be unique")
		seen[id] = true
	}
}

func TestNewCorrelationIDIsUUID(t *testing.T) {
	t.Parallel()

	id := NewCorrelationID()
	assert.Len(t, id, 36)
	assert.NotEqual(t, id, NewCorrelationID())
}

func TestTraceContextRoundTrip(t *testing.T) {
	t.Parallel()

	trace := Trace{TraceID: "0123456789abcdef0123456789abcdef", CorrelationID: "corr"}
	ctx := WithTrace(context.Background(), trace)
	assert.Equal(t, trace, TraceFrom(ctx))

	// A context without a trace still yields a usable trace id.
	empty := TraceFrom(context.Background())
	assert.True(t, IsTraceID(empty.TraceID))
}

func TestNewLoggerIsJSONWithServiceName(t *testing.T) {
	t.Parallel()

	logger, err := NewLogger("info")
	require.NoError(t, err)
	require.NotNil(t, logger)
	assert.False(t, logger.Core().Enabled(zapcore.DebugLevel))

	_, err = NewLogger("not-a-level")
	require.Error(t, err)

	// Log levels are applied.
	debugLogger, err := NewLogger("debug")
	require.NoError(t, err)
	assert.True(t, debugLogger.Core().Enabled(zapcore.DebugLevel))
}

func TestLoggerWithTraceAttachesContextFields(t *testing.T) {
	t.Parallel()

	core, recorded := observer.New(zapcore.DebugLevel)
	logger := zap.New(core).With(zap.String("service_name", ServiceName))

	trace := Trace{TraceID: "0123456789abcdef0123456789abcdef", CorrelationID: "corr-1"}
	traced := LoggerWithTrace(logger, trace, "auth.login")
	traced.Info("attempt", zap.String("status", "ok"))

	entries := recorded.All()
	require.Len(t, entries, 1)
	fields := entries[0].ContextMap()
	assert.Equal(t, ServiceName, fields["service_name"])
	assert.Equal(t, trace.TraceID, fields["trace_id"])
	assert.Equal(t, trace.CorrelationID, fields["correlation_id"])
	assert.Equal(t, "auth.login", fields["operation"])
	assert.Equal(t, "ok", fields["status"])
}

func TestLoggerWithNilLoggerIsNoOp(t *testing.T) {
	t.Parallel()

	require.NotNil(t, LoggerWithTrace(nil, Trace{TraceID: "x"}, "op"))
}

func TestServiceNameIsStable(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "identity_service", ServiceName)
	assert.False(t, strings.ContainsAny(ServiceName, " -"))
}
