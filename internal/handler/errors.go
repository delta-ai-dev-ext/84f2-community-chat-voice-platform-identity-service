// Package handler exposes the identity service HTTP surface with gin. Handlers
// bind and validate requests, delegate to services and map domain errors to the
// platform error shape.
package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"identity_service/internal/metrics"
	"identity_service/internal/models"
	"identity_service/internal/observability"
)

// statusFor maps a domain error code to its HTTP status.
func statusFor(code models.ErrorCode) int {
	switch code {
	case models.CodeBadRequest:
		return http.StatusBadRequest
	case models.CodeValidationFailed:
		return http.StatusUnprocessableEntity
	case models.CodeUnauthorized, models.CodeInvalidCredentials, models.CodeInvalidRefreshToken, models.CodeSessionRevoked:
		return http.StatusUnauthorized
	case models.CodeEmailNotVerified:
		return http.StatusForbidden
	case models.CodeSessionNotFound, models.CodeUserNotFound:
		return http.StatusNotFound
	case models.CodeEmailAlreadyRegistered, models.CodeUsernameTaken, models.CodeAlreadyVerified:
		return http.StatusConflict
	case models.CodeLocked:
		return http.StatusTooManyRequests
	case models.CodeVerificationExpired, models.CodeVerificationUsed, models.CodeResetLinkExpired:
		return http.StatusGone
	case models.CodeEmailUnavailable, models.CodeServiceUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// defaultDetail is the fallback human-readable text per code.
func defaultDetail(code models.ErrorCode) string {
	switch code {
	case models.CodeEmailAlreadyRegistered:
		return "This email is already registered."
	case models.CodeUsernameTaken:
		return "This username is already taken."
	case models.CodeAlreadyVerified:
		return "This email is already verified."
	case models.CodeVerificationExpired:
		return "This verification link is no longer valid."
	case models.CodeVerificationUsed:
		return "This verification link was already used."
	case models.CodeInvalidCredentials:
		return "Email or password is incorrect."
	case models.CodeEmailNotVerified:
		return "Verify your email before signing in."
	case models.CodeLocked:
		return "Too many attempts. Try again later."
	case models.CodeInvalidRefreshToken:
		return "Sign in again."
	case models.CodeSessionRevoked:
		return "This session was revoked. Sign in again."
	case models.CodeResetLinkExpired:
		return "This reset link is no longer valid."
	case models.CodeSessionNotFound:
		return "No such active session."
	case models.CodeUserNotFound:
		return "No user with that username."
	case models.CodeUnauthorized:
		return "Sign in to continue."
	case models.CodeValidationFailed:
		return "One or more fields are invalid."
	case models.CodeBadRequest:
		return "The request body could not be parsed."
	case models.CodeEmailUnavailable:
		return "We couldn't send the email. Try again."
	case models.CodeServiceUnavailable:
		return "A critical dependency is not ready."
	default:
		return "Something went wrong. Try again."
	}
}

// respondError writes the standard error body for err. Internal failures are
// logged with their trace context and never exposed to the client.
func (h *handlers) respondError(c *gin.Context, err error) {
	code, detail := models.ErrorDetailOf(err)
	status := statusFor(code)
	if status >= http.StatusInternalServerError {
		trace := observability.TraceFrom(c.Request.Context())
		observability.LoggerWithTrace(h.logger, trace, c.FullPath()).
			Error("request failed",
				zap.Int("status", status),
				zap.String("error_code", string(code)),
				zap.Error(err),
			)
	}
	if detail == "" {
		detail = defaultDetail(code)
	}
	if code == models.CodeInternalError {
		detail = defaultDetail(models.CodeInternalError)
	}
	c.AbortWithStatusJSON(status, models.ErrorResponse{Error: string(code), Detail: detail})
}

// respondBadRequest writes a malformed-request error.
func (h *handlers) respondBadRequest(c *gin.Context, detail string) {
	if detail == "" {
		detail = defaultDetail(models.CodeBadRequest)
	}
	c.AbortWithStatusJSON(http.StatusBadRequest, models.ErrorResponse{
		Error:  string(models.CodeBadRequest),
		Detail: detail,
	})
}

// respondValidationFailed writes a validation error for a field-level problem.
func (h *handlers) respondValidationFailed(c *gin.Context, detail string) {
	if detail == "" {
		detail = defaultDetail(models.CodeValidationFailed)
	}
	c.AbortWithStatusJSON(http.StatusUnprocessableEntity, models.ErrorResponse{
		Error:  string(models.CodeValidationFailed),
		Detail: detail,
	})
}

// statusRecorder captures the response status for the RED metrics.
type statusRecorder struct {
	gin.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(data []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(data)
}

// metricsMiddleware records http_requests_total and http_request_duration_seconds.
func (h *handlers) metricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if h.metrics == nil {
			c.Next()
			return
		}
		started := nowFunc()
		recorder := &statusRecorder{ResponseWriter: c.Writer}
		c.Writer = recorder
		c.Next()
		status := recorder.status
		if status == 0 {
			status = c.Writer.Status()
		}
		h.metrics.ObserveRequest(c.FullPath(), c.Request.Method, status, since(started))
	}
}

var _ = metrics.StatusClass
