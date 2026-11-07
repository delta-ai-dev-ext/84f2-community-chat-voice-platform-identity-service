// Package service contains the business logic of the identity service:
// registration and verification, sign-in with throttling, rotating refresh
// tokens with reuse detection, password reset, profile lookups and signing-key
// management. It never imports gin and never writes SQL.
package service

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"unicode/utf8"

	"go.uber.org/zap"

	"identity_service/internal/clock"
	"identity_service/internal/config"
	"identity_service/internal/email"
	"identity_service/internal/events"
	"identity_service/internal/metrics"
	"identity_service/internal/models"
	"identity_service/internal/observability"
	"identity_service/internal/repository"
	"identity_service/internal/security"
)

// UsernamePattern is the allowed username alphabet.
var UsernamePattern = regexp.MustCompile(`^[a-z0-9_.-]+$`)

// Validation bounds from docs/openapi_spec.yaml.
const (
	MinUsernameLength    = 2
	MaxUsernameLength    = 32
	MaxDisplayNameLength = 64
	MinPasswordLength    = 10
	MaxPasswordLength    = 128
	MaxEmailLength       = 254
	MaxDeviceLabelLength = 100
	MaxBatchLookupIDs    = 100
)

// Deps are the collaborators of the identity service.
type Deps struct {
	// Repos is the repository set (PostgreSQL in production, mocks in tests).
	Repos repository.Repositories
	// Keys manages access-token signing keys.
	Keys *KeyManager
	// Tokens issues and verifies access tokens.
	Tokens *TokenIssuer
	// Notifier sends transactional email.
	Notifier email.Notifier
	// Clock is the injectable time source.
	Clock clock.Clock
	// Metrics records business counters (nil-safe).
	Metrics *metrics.Metrics
	// Logger is the structured logger.
	Logger *zap.Logger
	// Config carries the validated service configuration.
	Config *config.Config
	// Hasher hashes and verifies passwords.
	Hasher *security.Hasher
}

// Service implements the identity use cases.
type Service struct {
	repos    repository.Repositories
	keys     *KeyManager
	tokens   *TokenIssuer
	notifier email.Notifier
	clock    clock.Clock
	metrics  *metrics.Metrics
	logger   *zap.Logger
	cfg      *config.Config
	hasher   *security.Hasher
}

// NewService wires the identity service.
func NewService(deps Deps) (*Service, error) {
	switch {
	case deps.Repos.Users == nil:
		return nil, errors.New("service: user repository is required")
	case deps.Repos.Transactor == nil:
		return nil, errors.New("service: transactor is required")
	case deps.Keys == nil:
		return nil, errors.New("service: key manager is required")
	case deps.Clock == nil:
		return nil, errors.New("service: clock is required")
	case deps.Config == nil:
		return nil, errors.New("service: config is required")
	case deps.Hasher == nil:
		return nil, errors.New("service: hasher is required")
	}
	tokens := deps.Tokens
	if tokens == nil {
		tokens = NewTokenIssuer(deps.Keys, deps.Config.JWTIssuer, deps.Config.JWTAudience, deps.Config.AccessTokenTTL, deps.Clock)
	}
	logger := deps.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	notifier := deps.Notifier
	if notifier == nil {
		notifier = &noopNotifier{}
	}
	return &Service{
		repos:    deps.Repos,
		keys:     deps.Keys,
		tokens:   tokens,
		notifier: notifier,
		clock:    deps.Clock,
		metrics:  deps.Metrics,
		logger:   logger,
		cfg:      deps.Config,
		hasher:   deps.Hasher,
	}, nil
}

// noopNotifier is used when email delivery is not configured (tests only).
type noopNotifier struct{}

func (noopNotifier) SendVerification(context.Context, email.VerificationMessage) error {
	return nil
}

func (noopNotifier) SendPasswordReset(context.Context, email.PasswordResetMessage) error { return nil }

func (noopNotifier) SendPasswordChanged(context.Context, email.PasswordChangedMessage) error {
	return nil
}

// validateEmail checks and normalises an email address.
func validateEmail(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || len(trimmed) > MaxEmailLength {
		return "", models.ValidationErrorf("email must be a valid address of at most %d characters.", MaxEmailLength)
	}
	parsed, err := mail.ParseAddress(trimmed)
	if err != nil || parsed.Address != trimmed {
		return "", models.ValidationErrorf("email must be a valid address.")
	}
	return models.NormalizeEmail(trimmed), nil
}

// validateUsername checks and normalises a username.
func validateUsername(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) < MinUsernameLength || len(trimmed) > MaxUsernameLength {
		return "", models.ValidationErrorf("username must be between %d and %d characters.", MinUsernameLength, MaxUsernameLength)
	}
	normalized := models.NormalizeUsername(trimmed)
	if !UsernamePattern.MatchString(normalized) {
		return "", models.ValidationErrorf("username may only contain lowercase letters, digits, dots, dashes and underscores.")
	}
	return normalized, nil
}

// validateDisplayName checks a display name.
func validateDisplayName(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || utf8.RuneCountInString(trimmed) > MaxDisplayNameLength {
		return "", models.ValidationErrorf("display_name must be between 1 and %d characters.", MaxDisplayNameLength)
	}
	return trimmed, nil
}

// validatePassword checks the password strength policy.
func validatePassword(raw string) error {
	if len(raw) < MinPasswordLength || len(raw) > MaxPasswordLength {
		return models.ValidationErrorf("password must be between %d and %d characters.", MinPasswordLength, MaxPasswordLength)
	}
	return nil
}

// validateDeviceLabel normalises the optional device label.
func validateDeviceLabel(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if utf8.RuneCountInString(trimmed) > MaxDeviceLabelLength {
		return "", models.ValidationErrorf("device_label must be at most %d characters.", MaxDeviceLabelLength)
	}
	return trimmed, nil
}

// enqueueAccountChanged stores the EVT-001 message in the outbox inside the
// caller's transaction, so publication can never diverge from committed state.
func (s *Service) enqueueAccountChanged(ctx context.Context, user *models.User, change models.AccountChange) error {
	if s.repos.Outbox == nil {
		return nil
	}
	flow := events.FlowFromTrace(observability.TraceFrom(ctx))
	message, err := events.NewAccountChangedMessage(user, change, flow, s.clock.Now())
	if err != nil {
		return fmt.Errorf("service: build account event: %w", err)
	}
	envelope, err := events.MarshalEnvelope(message.Envelope)
	if err != nil {
		return err
	}
	payload, err := events.MarshalPayload(message.Payload)
	if err != nil {
		return err
	}
	recordID, err := models.NewUUID()
	if err != nil {
		return err
	}
	return s.repos.Outbox.Insert(ctx, &models.OutboxRecord{
		ID:        recordID,
		Topic:     s.cfg.KafkaTopicIdentityEvents,
		Key:       user.ID,
		Envelope:  envelope,
		Payload:   payload,
		CreatedAt: s.clock.Now(),
	})
}

// logFailure logs an internal failure with trace context, never with secrets.
func (s *Service) logFailure(ctx context.Context, operation string, err error) {
	trace := observability.TraceFrom(ctx)
	observability.LoggerWithTrace(s.logger, trace, operation).
		Error("operation failed", zap.String("status", "error"), zap.Error(err))
}

// TokenIssuer exposes the access-token issuer to the HTTP layer, which verifies
// bearer tokens on authenticated routes.
func (s *Service) TokenIssuer() *TokenIssuer { return s.tokens }
