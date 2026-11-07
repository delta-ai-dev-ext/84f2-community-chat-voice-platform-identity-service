package handler

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"identity_service/internal/models"
	"identity_service/internal/observability"
)

// Clock function indirection keeps latency measurement testable.
var nowFunc = time.Now

func since(started time.Time) time.Duration { return time.Since(started) }

// Context keys for the authenticated caller.
const (
	contextUserID    = "identity.user_id"
	contextSessionID = "identity.session_id"
	contextTraceID   = "identity.trace_id"
)

// traceMiddleware propagates the inbound trace id (traceparent or X-Trace-Id,
// minted when absent) into the request context, the response header and every
// log line.
func traceMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		request := c.Request
		trace := observability.Trace{
			TraceID: observability.TraceIDFromHeaders(
				request.Header.Get("traceparent"),
				request.Header.Get("X-Trace-Id"),
			),
			CorrelationID: observability.NewCorrelationID(),
		}
		c.Header("X-Trace-Id", trace.TraceID)
		c.Set(contextTraceID, trace.TraceID)
		c.Request = request.WithContext(observability.WithTrace(request.Context(), trace))
		c.Next()
	}
}

// recoveryMiddleware converts panics into the standard error shape.
func (h *handlers) recoveryMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if recovered := recover(); recovered != nil {
				trace := observability.TraceFrom(c.Request.Context())
				observability.LoggerWithTrace(h.logger, trace, c.FullPath()).
					Error("panic recovered", zap.Any("panic", recovered), zap.String("status", "error"))
				c.AbortWithStatusJSON(http.StatusInternalServerError, models.ErrorResponse{
					Error:  string(models.CodeInternalError),
					Detail: defaultDetail(models.CodeInternalError),
				})
			}
		}()
		c.Next()
	}
}

// authMiddleware validates the bearer access token and stores the caller's
// identity in the request context.
func (h *handlers) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := bearerToken(c.Request.Header.Get("Authorization"))
		if raw == "" {
			h.respondError(c, models.NewError(models.CodeUnauthorized, defaultDetail(models.CodeUnauthorized)))
			return
		}
		claims, err := h.tokens.Verify(c.Request.Context(), raw)
		if err != nil {
			h.respondError(c, models.NewError(models.CodeUnauthorized, defaultDetail(models.CodeUnauthorized)))
			return
		}
		c.Set(contextUserID, claims.UserID)
		c.Set(contextSessionID, claims.SessionID)
		c.Next()
	}
}

// bearerToken extracts the token from an Authorization header.
func bearerToken(header string) string {
	parts := strings.SplitN(strings.TrimSpace(header), " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

// callerUserID returns the authenticated user id.
func callerUserID(c *gin.Context) string {
	value, _ := c.Get(contextUserID)
	id, _ := value.(string)
	return id
}

// callerSessionID returns the authenticated session id (JWT sid claim).
func callerSessionID(c *gin.Context) string {
	value, _ := c.Get(contextSessionID)
	id, _ := value.(string)
	return id
}

// traceOf returns the trace of the request context.
func traceOf(ctx context.Context) observability.Trace { return observability.TraceFrom(ctx) }
