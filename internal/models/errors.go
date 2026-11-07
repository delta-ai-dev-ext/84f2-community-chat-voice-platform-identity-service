package models

import (
	"errors"
	"fmt"
)

// ErrorCode is the stable, machine-readable error identifier returned in the
// `error` field of every error response.
type ErrorCode string

// Error codes defined by docs/openapi_spec.yaml and docs/user_stories.md.
const (
	CodeBadRequest             ErrorCode = "bad_request"
	CodeUnauthorized           ErrorCode = "unauthorized"
	CodeValidationFailed       ErrorCode = "validation_failed"
	CodeInternalError          ErrorCode = "internal_error"
	CodeServiceUnavailable     ErrorCode = "service_unavailable"
	CodeEmailUnavailable       ErrorCode = "email_unavailable"
	CodeEmailAlreadyRegistered ErrorCode = "email_already_registered"
	CodeUsernameTaken          ErrorCode = "username_taken"
	CodeAlreadyVerified        ErrorCode = "already_verified"
	CodeVerificationExpired    ErrorCode = "verification_link_expired"
	CodeVerificationUsed       ErrorCode = "verification_link_used"
	CodeInvalidCredentials     ErrorCode = "invalid_credentials"
	CodeEmailNotVerified       ErrorCode = "email_not_verified"
	CodeLocked                 ErrorCode = "locked"
	CodeInvalidRefreshToken    ErrorCode = "invalid_refresh_token"
	CodeSessionRevoked         ErrorCode = "session_revoked"
	CodeResetLinkExpired       ErrorCode = "reset_link_expired"
	CodeSessionNotFound        ErrorCode = "session_not_found"
	CodeUserNotFound           ErrorCode = "user_not_found"
)

// Error is a domain error carrying the client-facing error code and detail.
// Handlers translate it into an HTTP status; the wrapped cause stays internal
// and is never sent to clients.
type Error struct {
	Code   ErrorCode
	Detail string
	cause  error
}

// NewError builds a domain error with a human-readable detail.
func NewError(code ErrorCode, detail string) *Error {
	return &Error{Code: code, Detail: detail}
}

// WrapError builds a domain error that keeps the internal cause for logging.
func WrapError(code ErrorCode, detail string, cause error) *Error {
	return &Error{Code: code, Detail: detail, cause: cause}
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Detail, e.cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Detail)
}

// Unwrap exposes the internal cause to errors.Is / errors.As.
func (e *Error) Unwrap() error { return e.cause }

// ErrorCodeOf extracts the code of a domain error, defaulting to
// CodeInternalError for anything else.
func ErrorCodeOf(err error) ErrorCode {
	var target *Error
	if errors.As(err, &target) {
		return target.Code
	}
	return CodeInternalError
}

// ErrorDetailOf extracts the client-facing detail of a domain error.
func ErrorDetailOf(err error) (ErrorCode, string) {
	var target *Error
	if errors.As(err, &target) {
		return target.Code, target.Detail
	}
	return CodeInternalError, ""
}

// ValidationErrorf builds a validation_failed error describing the first
// offending field.
func ValidationErrorf(format string, args ...any) *Error {
	return NewError(CodeValidationFailed, fmt.Sprintf(format, args...))
}
