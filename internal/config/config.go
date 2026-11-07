// Package config loads the identity_service configuration from the process
// environment and validates it at startup so the service fails fast on
// missing or malformed values.
package config

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Default values for optional configuration entries.
const (
	DefaultEnvironment              = "production"
	DefaultHTTPAddr                 = ":8080"
	DefaultKafkaTopicIdentityEvents = "identity_events"
	DefaultAccessTokenTTL           = 10 * time.Minute
	DefaultRefreshTokenTTL          = 720 * time.Hour
	DefaultEmailVerificationTTL     = 24 * time.Hour
	DefaultPasswordResetTTL         = 1 * time.Hour
	DefaultSigningKeyRotation       = 720 * time.Hour
	DefaultSigningKeyOverlap        = 1 * time.Hour
	DefaultLoginMaxFailures         = 5
	DefaultLoginSourceMaxFailures   = 20
	DefaultLoginWindow              = 15 * time.Minute
	DefaultLoginLockout             = 15 * time.Minute
	DefaultLogLevel                 = "info"
	DefaultShutdownTimeout          = 20 * time.Second
	DefaultOutboxPollInterval       = 1 * time.Second
	DefaultOutboxBatchSize          = 50
	DefaultRefreshCookieName        = "refresh_token"
	DefaultRefreshCookiePath        = "/auth"
)

// Config is the fully validated runtime configuration of the service.
type Config struct {
	// Environment is "production" or "development"; development loads .env.
	Environment string
	// HTTPAddr is the listen address of the HTTP server.
	HTTPAddr string

	DatabaseURL              string
	KafkaBrokers             []string
	KafkaTopicIdentityEvents string
	ResendAPIKey             string
	MailFrom                 string
	AppBaseURL               string
	JWTIssuer                string
	JWTAudience              string

	AccessTokenTTL            time.Duration
	RefreshTokenTTL           time.Duration
	EmailVerificationTokenTTL time.Duration
	PasswordResetTokenTTL     time.Duration

	SigningKeyRotationInterval time.Duration
	SigningKeyRotationOverlap  time.Duration

	LoginMaxFailures       int
	LoginSourceMaxFailures int
	LoginWindow            time.Duration
	LoginLockout           time.Duration

	LogLevel           string
	ShutdownTimeout    time.Duration
	OutboxPollInterval time.Duration
	OutboxBatchSize    int

	RefreshCookieName string
	RefreshCookiePath string
}

// IsDevelopment reports whether the service runs with development defaults
// (notably .env loading and human-friendly logs).
func (c *Config) IsDevelopment() bool {
	return strings.EqualFold(c.Environment, "development")
}

// Load reads the configuration using getenv and validates it. Every problem is
// reported at once so an operator can fix the whole environment in one pass.
func Load(getenv func(string) string) (*Config, error) {
	var problems []string
	fail := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	cfg := &Config{
		Environment:              stringOr(getenv, "SERVICE_ENV", DefaultEnvironment),
		HTTPAddr:                 stringOr(getenv, "HTTP_ADDR", DefaultHTTPAddr),
		DatabaseURL:              strings.TrimSpace(getenv("DATABASE_URL")),
		KafkaBrokers:             splitList(getenv("KAFKA_BROKERS")),
		KafkaTopicIdentityEvents: stringOr(getenv, "KAFKA_TOPIC_IDENTITY_EVENTS", DefaultKafkaTopicIdentityEvents),
		ResendAPIKey:             strings.TrimSpace(getenv("RESEND_API_KEY")),
		MailFrom:                 strings.TrimSpace(getenv("MAIL_FROM")),
		AppBaseURL:               strings.TrimSpace(getenv("APP_BASE_URL")),
		JWTIssuer:                strings.TrimSpace(getenv("JWT_ISSUER")),
		JWTAudience:              strings.TrimSpace(getenv("JWT_AUDIENCE")),
		LogLevel:                 stringOr(getenv, "SERVICE_LOG_LEVEL", DefaultLogLevel),
		RefreshCookieName:        stringOr(getenv, "REFRESH_COOKIE_NAME", DefaultRefreshCookieName),
		RefreshCookiePath:        stringOr(getenv, "REFRESH_COOKIE_PATH", DefaultRefreshCookiePath),
	}

	if cfg.DatabaseURL == "" {
		fail("DATABASE_URL is required")
	} else if err := validateURL(cfg.DatabaseURL, "postgres", "postgresql"); err != nil {
		fail("DATABASE_URL %v", err)
	}

	if len(cfg.KafkaBrokers) == 0 {
		fail("KAFKA_BROKERS is required")
	}
	if cfg.KafkaTopicIdentityEvents == "" {
		fail("KAFKA_TOPIC_IDENTITY_EVENTS is required")
	}
	if cfg.ResendAPIKey == "" {
		fail("RESEND_API_KEY is required")
	}
	if cfg.MailFrom == "" {
		fail("MAIL_FROM is required")
	} else if !strings.Contains(cfg.MailFrom, "@") {
		fail("MAIL_FROM must be an email address")
	}
	if cfg.AppBaseURL == "" {
		fail("APP_BASE_URL is required")
	} else if err := validateURL(cfg.AppBaseURL, "http", "https"); err != nil {
		fail("APP_BASE_URL %v", err)
	}
	if cfg.JWTIssuer == "" {
		fail("JWT_ISSUER is required")
	}
	if cfg.JWTAudience == "" {
		fail("JWT_AUDIENCE is required")
	}

	cfg.AccessTokenTTL = durationOr(getenv, "ACCESS_TOKEN_TTL", DefaultAccessTokenTTL, fail)
	cfg.RefreshTokenTTL = durationOr(getenv, "REFRESH_TOKEN_TTL", DefaultRefreshTokenTTL, fail)
	cfg.EmailVerificationTokenTTL = durationOr(getenv, "EMAIL_VERIFICATION_TOKEN_TTL", DefaultEmailVerificationTTL, fail)
	cfg.PasswordResetTokenTTL = durationOr(getenv, "PASSWORD_RESET_TOKEN_TTL", DefaultPasswordResetTTL, fail)
	cfg.SigningKeyRotationInterval = durationOr(getenv, "SIGNING_KEY_ROTATION_INTERVAL", DefaultSigningKeyRotation, fail)
	cfg.SigningKeyRotationOverlap = durationOr(getenv, "SIGNING_KEY_ROTATION_OVERLAP", DefaultSigningKeyOverlap, fail)
	cfg.LoginWindow = durationOr(getenv, "LOGIN_WINDOW", DefaultLoginWindow, fail)
	cfg.LoginLockout = durationOr(getenv, "LOGIN_LOCKOUT", DefaultLoginLockout, fail)
	cfg.ShutdownTimeout = durationOr(getenv, "SHUTDOWN_TIMEOUT", DefaultShutdownTimeout, fail)
	cfg.OutboxPollInterval = durationOr(getenv, "OUTBOX_POLL_INTERVAL", DefaultOutboxPollInterval, fail)

	cfg.LoginMaxFailures = intOr(getenv, "LOGIN_MAX_FAILURES", DefaultLoginMaxFailures, fail)
	cfg.LoginSourceMaxFailures = intOr(getenv, "LOGIN_SOURCE_MAX_FAILURES", DefaultLoginSourceMaxFailures, fail)
	cfg.OutboxBatchSize = intOr(getenv, "OUTBOX_BATCH_SIZE", DefaultOutboxBatchSize, fail)

	for _, item := range []struct {
		name  string
		value time.Duration
	}{
		{"ACCESS_TOKEN_TTL", cfg.AccessTokenTTL},
		{"REFRESH_TOKEN_TTL", cfg.RefreshTokenTTL},
		{"EMAIL_VERIFICATION_TOKEN_TTL", cfg.EmailVerificationTokenTTL},
		{"PASSWORD_RESET_TOKEN_TTL", cfg.PasswordResetTokenTTL},
		{"SIGNING_KEY_ROTATION_INTERVAL", cfg.SigningKeyRotationInterval},
		{"SIGNING_KEY_ROTATION_OVERLAP", cfg.SigningKeyRotationOverlap},
		{"LOGIN_WINDOW", cfg.LoginWindow},
		{"LOGIN_LOCKOUT", cfg.LoginLockout},
		{"SHUTDOWN_TIMEOUT", cfg.ShutdownTimeout},
		{"OUTBOX_POLL_INTERVAL", cfg.OutboxPollInterval},
	} {
		if item.value <= 0 {
			fail("%s must be greater than zero", item.name)
		}
	}

	for _, item := range []struct {
		name  string
		value int
	}{
		{"LOGIN_MAX_FAILURES", cfg.LoginMaxFailures},
		{"LOGIN_SOURCE_MAX_FAILURES", cfg.LoginSourceMaxFailures},
		{"OUTBOX_BATCH_SIZE", cfg.OutboxBatchSize},
	} {
		if item.value <= 0 {
			fail("%s must be greater than zero", item.name)
		}
	}

	if cfg.RefreshCookieName == "" {
		fail("REFRESH_COOKIE_NAME must not be empty")
	}
	if !strings.HasPrefix(cfg.RefreshCookiePath, "/") {
		fail("REFRESH_COOKIE_PATH must be absolute")
	}

	if len(problems) > 0 {
		return nil, fmt.Errorf("invalid configuration: %s", strings.Join(problems, "; "))
	}
	return cfg, nil
}

func stringOr(getenv func(string) string, key, fallback string) string {
	if v := strings.TrimSpace(getenv(key)); v != "" {
		return v
	}
	return fallback
}

func splitList(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func durationOr(getenv func(string) string, key string, fallback time.Duration, fail func(string, ...any)) time.Duration {
	raw := strings.TrimSpace(getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		fail("%s must be a valid duration (for example 15m): %v", key, err)
		return fallback
	}
	return value
}

func intOr(getenv func(string) string, key string, fallback int, fail func(string, ...any)) int {
	raw := strings.TrimSpace(getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		fail("%s must be an integer: %v", key, err)
		return fallback
	}
	return value
}

func validateURL(raw string, allowedSchemes ...string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("must be a valid URL: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("must include a scheme and host")
	}
	for _, scheme := range allowedSchemes {
		if parsed.Scheme == scheme {
			return nil
		}
	}
	return fmt.Errorf("must use one of the schemes %s", strings.Join(allowedSchemes, ","))
}
