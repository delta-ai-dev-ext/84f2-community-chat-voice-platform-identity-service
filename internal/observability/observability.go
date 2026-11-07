// Package observability provides structured logging and trace propagation
// helpers shared by every layer of the service.
package observability

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"identity_service/internal/models"
)

// ServiceName is the value of the service_name log field.
const ServiceName = "identity_service"

// Trace carries the identifiers that tie logs, spans and events together.
type Trace struct {
	TraceID       string
	CorrelationID string
}

type traceKey struct{}

var fallbackCounter atomic.Uint64

// NewTraceID returns a 32 lowercase hex character trace id. It uses a
// cryptographic source and falls back to a time/counter-based value so the
// identifier is never empty.
func NewTraceID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		now := uint64(time.Now().UnixNano())
		counter := fallbackCounter.Add(1)
		binary.BigEndian.PutUint64(b[0:8], now)
		binary.BigEndian.PutUint64(b[8:16], counter)
	}
	return hex.EncodeToString(b[:])
}

// IsTraceID reports whether value is a valid 32 lowercase hex trace id.
func IsTraceID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

// NewCorrelationID returns a fresh UUID used to group one business flow.
func NewCorrelationID() string {
	id, err := models.NewUUID()
	if err != nil {
		// A correlation id only needs to be unique; fall back to a trace id.
		return NewTraceID()
	}
	return id
}

// TraceIDFromHeaders extracts a trace id from a W3C traceparent header or the
// X-Trace-Id header, minting a new one when neither carries a usable value.
func TraceIDFromHeaders(traceparent, xTraceID string) string {
	if candidate := parseTraceparent(traceparent); candidate != "" {
		return candidate
	}
	if candidate := strings.ToLower(strings.TrimSpace(xTraceID)); IsTraceID(candidate) {
		return candidate
	}
	return NewTraceID()
}

func parseTraceparent(header string) string {
	parts := strings.Split(strings.TrimSpace(header), "-")
	if len(parts) < 4 {
		return ""
	}
	candidate := strings.ToLower(parts[1])
	if IsTraceID(candidate) && strings.Trim(candidate, "0") != "" {
		return candidate
	}
	return ""
}

// WithTrace stores the trace in the context.
func WithTrace(ctx context.Context, trace Trace) context.Context {
	return context.WithValue(ctx, traceKey{}, trace)
}

// TraceFrom returns the trace stored in the context, minting a complete one
// when absent so downstream code always has non-empty identifiers.
func TraceFrom(ctx context.Context) Trace {
	if trace, ok := ctx.Value(traceKey{}).(Trace); ok {
		if trace.TraceID != "" {
			return trace
		}
	}
	return Trace{TraceID: NewTraceID(), CorrelationID: NewCorrelationID()}
}

// NewLogger builds the structured JSON logger for the given level.
func NewLogger(level string) (*zap.Logger, error) {
	parsed := zap.NewProductionConfig()
	parsed.Encoding = "json"
	parsed.EncoderConfig.TimeKey = "timestamp"
	parsed.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	parsed.InitialFields = map[string]any{"service_name": ServiceName}

	lvl, err := zapcore.ParseLevel(strings.ToLower(strings.TrimSpace(level)))
	if err != nil {
		return nil, fmt.Errorf("observability: parse log level %q: %w", level, err)
	}
	parsed.Level = zap.NewAtomicLevelAt(lvl)
	logger, err := parsed.Build()
	if err != nil {
		return nil, fmt.Errorf("observability: build logger: %w", err)
	}
	return logger, nil
}

// LoggerWithTrace decorates a logger with the request trace fields.
func LoggerWithTrace(logger *zap.Logger, trace Trace, operation string) *zap.Logger {
	if logger == nil {
		return zap.NewNop()
	}
	return logger.With(
		zap.String("trace_id", trace.TraceID),
		zap.String("correlation_id", trace.CorrelationID),
		zap.String("operation", operation),
	)
}

// Hostname returns the host name used in the startup log, ignoring errors.
func Hostname() string {
	name, err := os.Hostname()
	if err != nil {
		return ""
	}
	return name
}
