package email

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/resend/resend-go/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"identity_service/internal/metrics"
)

const resendEndpoint = "https://api.resend.com/emails"

// newTestAdapter builds an adapter wired to the httpmock transport.
func newTestAdapter(t *testing.T) (*Adapter, *metrics.Metrics, *prometheus.Registry) {
	t.Helper()

	registry := prometheus.NewRegistry()
	appMetrics := metrics.New(registry)

	cfg := AdapterConfig{
		APIKey:      "re_test_key",
		From:        "identity@example.com",
		AppBaseURL:  "https://app.example.com",
		MaxAttempts: 3,
		BaseDelay:   time.Millisecond,
		MaxDelay:    4 * time.Millisecond,
		Sleep:       func(context.Context, time.Duration) error { return nil },
	}

	client := resend.NewCustomClient(&http.Client{}, cfg.APIKey)
	return NewAdapter(client, cfg, appMetrics, nil), appMetrics, registry
}

func activateHTTPMock(t *testing.T) {
	t.Helper()
	httpmock.Activate()
	t.Cleanup(httpmock.DeactivateAndReset)
}

func TestSendVerificationUsesSDKWithTokenDerivedIdempotencyKey(t *testing.T) {
	activateHTTPMock(t)

	adapter, _, _ := newTestAdapter(t)
	var captured *http.Request
	httpmock.RegisterResponder(http.MethodPost, resendEndpoint,
		func(req *http.Request) (*http.Response, error) {
			captured = req
			return httpmock.NewJsonResponse(http.StatusOK, map[string]string{"id": "email-1"})
		})

	err := adapter.SendVerification(context.Background(), VerificationMessage{
		To:       "user@example.com",
		Username: "user",
		Token:    "raw-token",
		TokenID:  "token-id-1",
	})
	require.NoError(t, err)

	require.NotNil(t, captured)
	assert.Equal(t, "re_test_key", strings.TrimPrefix(captured.Header.Get("Authorization"), "Bearer "))
	assert.Equal(t, "verification:token-id-1", captured.Header.Get("Idempotency-Key"), "the key derives from the token id")
}

func TestSendPasswordResetAndChangedEmails(t *testing.T) {
	activateHTTPMock(t)

	adapter, _, _ := newTestAdapter(t)
	httpmock.RegisterResponder(http.MethodPost, resendEndpoint,
		httpmock.NewStringResponder(http.StatusOK, `{"id":"email-2"}`))

	require.NoError(t, adapter.SendPasswordReset(context.Background(), PasswordResetMessage{
		To: "user@example.com", Username: "user", Token: "reset-token", TokenID: "token-id-2",
	}))
	require.NoError(t, adapter.SendPasswordChanged(context.Background(), PasswordChangedMessage{
		To: "user@example.com", Username: "user", UserID: "user-1",
	}))
}

func TestIdempotencyKeyDerivesFromReference(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "verification:t1", idempotencyKey("verification", "t1"))
	assert.Equal(t, "password-reset:t2", idempotencyKey("password-reset", "t2"))
	assert.Equal(t, "password-changed:u1", idempotencyKey("password-changed", "u1"))
}

func TestAdapterRetriesRateLimitThenSucceeds(t *testing.T) {
	activateHTTPMock(t)

	adapter, appMetrics, registry := newTestAdapter(t)
	var mu sync.Mutex
	attempts := 0
	httpmock.RegisterResponder(http.MethodPost, resendEndpoint,
		func(req *http.Request) (*http.Response, error) {
			mu.Lock()
			defer mu.Unlock()
			attempts++
			if attempts < 3 {
				return httpmock.NewStringResponse(http.StatusTooManyRequests, `{"message":"rate limited"}`), nil
			}
			return httpmock.NewStringResponse(http.StatusOK, `{"id":"email-3"}`), nil
		})

	err := adapter.SendVerification(context.Background(), VerificationMessage{
		To: "user@example.com", Username: "user", Token: "t", TokenID: "id",
	})
	require.NoError(t, err)
	assert.Equal(t, 3, attempts)
	assert.NotNil(t, appMetrics)

	families, gatherErr := registry.Gather()
	require.NoError(t, gatherErr)
	var sawErrors bool
	for _, family := range families {
		if family.GetName() == "external_call_errors_total" {
			sawErrors = true
		}
	}
	assert.True(t, sawErrors, "failed attempts are counted")
}

func TestAdapterExhaustsRetriesOnServerErrors(t *testing.T) {
	activateHTTPMock(t)

	adapter, _, _ := newTestAdapter(t)
	httpmock.RegisterResponder(http.MethodPost, resendEndpoint,
		httpmock.NewStringResponder(http.StatusBadGateway, `{"message":"upstream down"}`))

	err := adapter.SendVerification(context.Background(), VerificationMessage{
		To: "user@example.com", Username: "user", Token: "t", TokenID: "id",
	})
	require.Error(t, err)

	var providerErr *ProviderError
	require.True(t, errors.As(err, &providerErr))
	assert.Equal(t, "server_error", providerErr.Class)
	assert.Equal(t, 3, providerErr.Attempts)
	assert.True(t, providerErr.Retryable)
	assert.Equal(t, "server_error", providerErr.ErrorClass())
}

func TestAdapterDoesNotRetryPermanentClientErrors(t *testing.T) {
	activateHTTPMock(t)

	adapter, _, _ := newTestAdapter(t)
	attempts := 0
	httpmock.RegisterResponder(http.MethodPost, resendEndpoint,
		func(req *http.Request) (*http.Response, error) {
			attempts++
			return httpmock.NewStringResponse(http.StatusUnprocessableEntity, `{"message":"invalid from"}`), nil
		})

	err := adapter.SendPasswordChanged(context.Background(), PasswordChangedMessage{
		To: "user@example.com", Username: "user", UserID: "user-1",
	})
	require.Error(t, err)
	assert.Equal(t, 1, attempts, "a 4xx is not retried")

	var providerErr *ProviderError
	require.True(t, errors.As(err, &providerErr))
	assert.Equal(t, "client_error", providerErr.Class)
	assert.False(t, providerErr.Retryable)
}

func TestAdapterStopsWhenContextIsCancelled(t *testing.T) {
	activateHTTPMock(t)

	adapter, _, _ := newTestAdapter(t)
	adapter.cfg.MaxAttempts = 5
	adapter.cfg.Sleep = func(ctx context.Context, d time.Duration) error { return ctx.Err() }
	httpmock.RegisterResponder(http.MethodPost, resendEndpoint,
		httpmock.NewStringResponder(http.StatusInternalServerError, `{"message":"boom"}`))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := adapter.SendVerification(ctx, VerificationMessage{To: "user@example.com", Token: "t", TokenID: "id"})
	require.Error(t, err)
}

func TestClassifyProviderErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		err       error
		class     string
		retryable bool
	}{
		{
			name:      "rate limit",
			err:       &resend.RateLimitError{Message: "slow down"},
			class:     "rate_limited",
			retryable: true,
		},
		{
			name:      "429 resend error",
			err:       &resend.ResendError{StatusCode: http.StatusTooManyRequests, Message: "slow down"},
			class:     "rate_limited",
			retryable: true,
		},
		{
			name:      "500 resend error",
			err:       &resend.ResendError{StatusCode: http.StatusInternalServerError, Message: "boom"},
			class:     "server_error",
			retryable: true,
		},
		{
			name:      "400 resend error",
			err:       &resend.ResendError{StatusCode: http.StatusBadRequest, Message: "bad"},
			class:     "client_error",
			retryable: false,
		},
		{
			name:      "unknown",
			err:       errors.New("mystery"),
			class:     "unknown",
			retryable: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			class, retryable := classify(tc.err)
			assert.Equal(t, tc.class, class)
			assert.Equal(t, tc.retryable, retryable)
		})
	}
}

func TestBackoffDoublesAndCaps(t *testing.T) {
	t.Parallel()

	adapter, _, _ := newTestAdapter(t)
	adapter.cfg.BaseDelay = 100 * time.Millisecond
	adapter.cfg.MaxDelay = 250 * time.Millisecond

	assert.Equal(t, 100*time.Millisecond, adapter.backoff(1))
	assert.Equal(t, 200*time.Millisecond, adapter.backoff(2))
	assert.Equal(t, 250*time.Millisecond, adapter.backoff(3))
	assert.Equal(t, 250*time.Millisecond, adapter.backoff(10))
}

func TestLinksEmbedEscapedTokens(t *testing.T) {
	t.Parallel()

	adapter, _, _ := newTestAdapter(t)
	assert.Equal(t,
		"https://app.example.com/verify-email?token=a%2Bb",
		adapter.link("/verify-email", "a+b"))
	assert.Equal(t,
		"https://app.example.com/reset-password?token=raw",
		adapter.link("/reset-password", "raw"))
}

func TestEscapePreventsHTMLInjection(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "&lt;script&gt;&amp;", escape("<script>&"))
}

func TestProviderErrorFormatting(t *testing.T) {
	t.Parallel()

	err := &ProviderError{Operation: "verification", Attempts: 2, Class: "server_error", Err: errors.New("boom")}
	assert.Contains(t, err.Error(), "verification")
	assert.Contains(t, err.Error(), "server_error")
	require.ErrorIs(t, err, err.Err)
}
