// Package email sends the service's transactional emails through Resend. The
// notifier interface keeps the rest of the service independent of the provider
// SDK and lets tests substitute fakes.
package email

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/resend/resend-go/v4"
	"go.uber.org/zap"

	"identity_service/internal/metrics"
)

// Kind identifies the transactional email being sent (metrics label value).
type Kind string

// Supported transactional email kinds.
const (
	KindVerification    Kind = "verification"
	KindPasswordReset   Kind = "password_reset"
	KindPasswordChanged Kind = "password_changed"
)

// VerificationMessage requests an email-verification email.
type VerificationMessage struct {
	// To is the recipient address.
	To string
	// Username is used to greet the recipient.
	Username string
	// Token is the raw single-use token embedded in the link only.
	Token string
	// TokenID is the verification-token id used to derive the idempotency key.
	TokenID string
}

// PasswordResetMessage requests a password-reset email.
type PasswordResetMessage struct {
	// To is the recipient address.
	To string
	// Username is used to greet the recipient.
	Username string
	// Token is the raw single-use token embedded in the link only.
	Token string
	// TokenID is the reset-token id used to derive the idempotency key.
	TokenID string
}

// PasswordChangedMessage requests the "password changed" confirmation email.
type PasswordChangedMessage struct {
	// To is the recipient address.
	To string
	// Username is used to greet the recipient.
	Username string
	// UserID scopes the idempotency key of the confirmation email.
	UserID string
}

// Notifier sends the service's transactional emails.
type Notifier interface {
	// SendVerification sends the email-verification link.
	SendVerification(ctx context.Context, msg VerificationMessage) error
	// SendPasswordReset sends the password-reset link.
	SendPasswordReset(ctx context.Context, msg PasswordResetMessage) error
	// SendPasswordChanged sends the confirmation that the password changed.
	SendPasswordChanged(ctx context.Context, msg PasswordChangedMessage) error
}

// AdapterConfig configures the Resend adapter.
type AdapterConfig struct {
	// APIKey is the Resend API key.
	APIKey string
	// From is the verified sender address.
	From string
	// AppBaseURL is the public base URL used to build links.
	AppBaseURL string
	// MaxAttempts bounds the retry loop (1 means no retry).
	MaxAttempts int
	// BaseDelay is the first back-off delay.
	BaseDelay time.Duration
	// MaxDelay caps the back-off delay.
	MaxDelay time.Duration
	// Sleep waits between attempts; injectable so tests never sleep.
	Sleep func(ctx context.Context, d time.Duration) error
}

// NewAdapterConfig returns production defaults for the given settings.
func NewAdapterConfig(apiKey, from, appBaseURL string) AdapterConfig {
	return AdapterConfig{
		APIKey:      apiKey,
		From:        from,
		AppBaseURL:  appBaseURL,
		MaxAttempts: 4,
		BaseDelay:   200 * time.Millisecond,
		MaxDelay:    2 * time.Second,
	}
}

// Adapter is the thin Resend implementation of Notifier: it builds the message,
// delegates the HTTP call to the official SDK and applies a bounded exponential
// back-off on transient provider failures.
type Adapter struct {
	client  *resend.Client
	cfg     AdapterConfig
	metrics *metrics.Metrics
	logger  *zap.Logger
}

// NewAdapter builds the Resend adapter.
func NewAdapter(client *resend.Client, cfg AdapterConfig, m *metrics.Metrics, logger *zap.Logger) *Adapter {
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 1
	}
	if cfg.Sleep == nil {
		cfg.Sleep = sleepContext
	}
	if client == nil {
		client = resend.NewClient(cfg.APIKey)
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Adapter{client: client, cfg: cfg, metrics: m, logger: logger}
}

// SendVerification implements Notifier.
func (a *Adapter) SendVerification(ctx context.Context, msg VerificationMessage) error {
	link := a.link("/verify-email", msg.Token)
	body := "<p>Hi " + escape(msg.Username) + ",</p>" +
		"<p>Confirm your email address to finish creating your account:</p>" +
		`<p><a href="` + escape(link) + `">Verify my email</a></p>` +
		"<p>This link expires in 24 hours. If you did not sign up, you can ignore this message.</p>"
	text := "Hi " + msg.Username + ",\n\nConfirm your email address: " + link +
		"\n\nThis link expires in 24 hours. If you did not sign up, you can ignore this message.\n"
	return a.send(ctx, KindVerification, idempotencyKey("verification", msg.TokenID),
		msg.To, "Verify your email address", body, text)
}

// SendPasswordReset implements Notifier.
func (a *Adapter) SendPasswordReset(ctx context.Context, msg PasswordResetMessage) error {
	link := a.link("/reset-password", msg.Token)
	body := "<p>Hi " + escape(msg.Username) + ",</p>" +
		"<p>Choose a new password for your account:</p>" +
		`<p><a href="` + escape(link) + `">Reset my password</a></p>` +
		"<p>This link expires in 1 hour. If you did not request a reset, you can ignore this message.</p>"
	text := "Hi " + msg.Username + ",\n\nChoose a new password: " + link +
		"\n\nThis link expires in 1 hour. If you did not request a reset, you can ignore this message.\n"
	return a.send(ctx, KindPasswordReset, idempotencyKey("password-reset", msg.TokenID),
		msg.To, "Reset your password", body, text)
}

// SendPasswordChanged implements Notifier.
func (a *Adapter) SendPasswordChanged(ctx context.Context, msg PasswordChangedMessage) error {
	body := "<p>Hi " + escape(msg.Username) + ",</p>" +
		"<p>Your password was changed and every active session was signed out.</p>" +
		"<p>If this was not you, request a password reset immediately.</p>"
	text := "Hi " + msg.Username + ",\n\nYour password was changed and every active session was signed out.\n" +
		"If this was not you, request a password reset immediately.\n"
	return a.send(ctx, KindPasswordChanged, idempotencyKey("password-changed", msg.UserID),
		msg.To, "Your password was changed", body, text)
}

// send performs one logical send with bounded retries.
func (a *Adapter) send(ctx context.Context, kind Kind, idempotencyKey, to, subject, html, text string) error {
	params := &resend.SendEmailRequest{
		From:    a.cfg.From,
		To:      []string{to},
		Subject: subject,
		Html:    html,
		Text:    text,
	}
	options := &resend.SendEmailOptions{IdempotencyKey: idempotencyKey}

	var lastErr error
	for attempt := 1; attempt <= a.cfg.MaxAttempts; attempt++ {
		started := time.Now()
		_, err := a.client.Emails.SendWithOptions(ctx, params, options)
		a.metrics.ObserveExternalCall(metrics.ProviderResend, string(kind), time.Since(started), err)
		if err == nil {
			a.metrics.RecordEmail(string(kind), "sent")
			a.logger.Info("email sent",
				zap.String("kind", string(kind)),
				zap.String("attempts", fmt.Sprint(attempt)),
				zap.String("status", "sent"),
			)
			return nil
		}

		lastErr = err
		class, retryable := classify(err)
		if !retryable || attempt == a.cfg.MaxAttempts || ctx.Err() != nil {
			a.metrics.RecordEmail(string(kind), "failed")
			a.logger.Error("email send failed",
				zap.String("kind", string(kind)),
				zap.String("error_class", class),
				zap.Int("attempts", attempt),
				zap.String("status", "failed"),
			)
			return &ProviderError{Operation: string(kind), Class: class, Attempts: attempt, Retryable: retryable, Err: err}
		}

		if sleepErr := a.cfg.Sleep(ctx, a.backoff(attempt)); sleepErr != nil {
			a.metrics.RecordEmail(string(kind), "failed")
			return &ProviderError{Operation: string(kind), Class: class, Attempts: attempt, Retryable: retryable, Err: errors.Join(err, sleepErr)}
		}
	}
	return &ProviderError{Operation: string(kind), Class: "unknown", Attempts: a.cfg.MaxAttempts, Err: lastErr}
}

func (a *Adapter) backoff(attempt int) time.Duration {
	delay := a.cfg.BaseDelay
	for i := 1; i < attempt; i++ {
		delay *= 2
		if delay >= a.cfg.MaxDelay {
			return a.cfg.MaxDelay
		}
	}
	return delay
}

func (a *Adapter) link(path, token string) string {
	base := strings.TrimSuffix(a.cfg.AppBaseURL, "/")
	return base + path + "?token=" + url.QueryEscape(token)
}

// idempotencyKey derives the Resend idempotency key from the token (or account)
// reference so an at-least-once retry cannot produce a duplicate email.
func idempotencyKey(prefix, reference string) string {
	return prefix + ":" + reference
}

func escape(value string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return replacer.Replace(value)
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// ProviderError is returned when a send fails after the bounded retries. Its
// class feeds the metrics label and lets callers distinguish transient from
// permanent failures.
type ProviderError struct {
	// Operation is the email kind that failed.
	Operation string
	// Class is one of rate_limited, server_error, client_error, network_error.
	Class string
	// Attempts is how many sends were attempted.
	Attempts int
	// Retryable reports whether the final failure was transient.
	Retryable bool
	// Err is the underlying provider error.
	Err error
}

// Error implements error.
func (e *ProviderError) Error() string {
	return fmt.Sprintf("email: %s send failed after %d attempt(s) [%s]: %v", e.Operation, e.Attempts, e.Class, e.Err)
}

// Unwrap exposes the provider error.
func (e *ProviderError) Unwrap() error { return e.Err }

// ErrorClass implements the metrics error-class contract.
func (e *ProviderError) ErrorClass() string { return e.Class }

var _ Notifier = (*Adapter)(nil)
