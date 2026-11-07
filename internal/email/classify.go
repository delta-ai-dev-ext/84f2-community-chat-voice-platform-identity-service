package email

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"

	"github.com/resend/resend-go/v4"
)

// classify maps a Resend SDK error to a low-cardinality class and whether the
// send may be retried. Transient failures are rate limits (429), provider 5xx
// responses and transport errors.
func classify(err error) (class string, retryable bool) {
	var rateLimit *resend.RateLimitError
	if errors.As(err, &rateLimit) {
		return "rate_limited", true
	}

	var resendErr *resend.ResendError
	if errors.As(err, &resendErr) {
		switch {
		case resendErr.StatusCode == http.StatusTooManyRequests:
			return "rate_limited", true
		case resendErr.StatusCode >= http.StatusInternalServerError:
			return "server_error", true
		default:
			return "client_error", false
		}
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return "network_error", true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return "network_error", true
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "network_error", true
	}
	// Unknown failures are treated as transient: Resend sends are idempotent.
	return "unknown", true
}
