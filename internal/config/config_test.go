package config

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validEnv() map[string]string {
	return map[string]string{
		"DATABASE_URL":                "postgres://identity:identity@localhost:5432/identity?sslmode=disable",
		"KAFKA_BROKERS":               "broker-1:9092, broker-2:9092",
		"KAFKA_TOPIC_IDENTITY_EVENTS": "identity_events",
		"RESEND_API_KEY":              "re_test_key",
		"MAIL_FROM":                   "identity@example.com",
		"APP_BASE_URL":                "https://app.example.com",
		"JWT_ISSUER":                  "identity_service",
		"JWT_AUDIENCE":                "community_platform",
	}
}

func lookup(env map[string]string) func(string) string {
	return func(key string) string { return env[key] }
}

func TestLoadAppliesDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := Load(lookup(validEnv()))
	require.NoError(t, err)

	assert.Equal(t, DefaultEnvironment, cfg.Environment)
	assert.False(t, cfg.IsDevelopment())
	assert.Equal(t, DefaultHTTPAddr, cfg.HTTPAddr)
	assert.Equal(t, []string{"broker-1:9092", "broker-2:9092"}, cfg.KafkaBrokers)
	assert.Equal(t, DefaultAccessTokenTTL, cfg.AccessTokenTTL)
	assert.Equal(t, DefaultRefreshTokenTTL, cfg.RefreshTokenTTL)
	assert.Equal(t, DefaultEmailVerificationTTL, cfg.EmailVerificationTokenTTL)
	assert.Equal(t, DefaultPasswordResetTTL, cfg.PasswordResetTokenTTL)
	assert.Equal(t, DefaultLoginMaxFailures, cfg.LoginMaxFailures)
	assert.Equal(t, DefaultLoginSourceMaxFailures, cfg.LoginSourceMaxFailures)
	assert.Equal(t, DefaultLoginWindow, cfg.LoginWindow)
	assert.Equal(t, DefaultLoginLockout, cfg.LoginLockout)
	assert.Equal(t, DefaultLogLevel, cfg.LogLevel)
	assert.Equal(t, DefaultShutdownTimeout, cfg.ShutdownTimeout)
	assert.Equal(t, DefaultRefreshCookieName, cfg.RefreshCookieName)
	assert.Equal(t, DefaultRefreshCookiePath, cfg.RefreshCookiePath)
}

func TestLoadOverridesFromEnvironment(t *testing.T) {
	t.Parallel()

	env := validEnv()
	env["SERVICE_ENV"] = "development"
	env["HTTP_ADDR"] = ":9090"
	env["ACCESS_TOKEN_TTL"] = "5m"
	env["LOGIN_MAX_FAILURES"] = "3"
	env["OUTBOX_BATCH_SIZE"] = "10"

	cfg, err := Load(lookup(env))
	require.NoError(t, err)

	assert.True(t, cfg.IsDevelopment())
	assert.Equal(t, ":9090", cfg.HTTPAddr)
	assert.Equal(t, 5*time.Minute, cfg.AccessTokenTTL)
	assert.Equal(t, 3, cfg.LoginMaxFailures)
	assert.Equal(t, 10, cfg.OutboxBatchSize)
}

func TestLoadReportsAllProblems(t *testing.T) {
	t.Parallel()

	env := map[string]string{
		"DATABASE_URL":       "mysql://wrong",
		"RESEND_API_KEY":     "",
		"MAIL_FROM":          "not-an-email",
		"APP_BASE_URL":       "/relative",
		"ACCESS_TOKEN_TTL":   "soon",
		"LOGIN_WINDOW":       "-5m",
		"LOGIN_MAX_FAILURES": "0",
	}

	_, err := Load(lookup(env))
	require.Error(t, err)

	msg := err.Error()
	for _, want := range []string{
		"DATABASE_URL",
		"KAFKA_BROKERS is required",
		"RESEND_API_KEY is required",
		"MAIL_FROM must be an email address",
		"APP_BASE_URL",
		"JWT_ISSUER is required",
		"JWT_AUDIENCE is required",
		"ACCESS_TOKEN_TTL must be a valid duration",
		"LOGIN_WINDOW must be greater than zero",
		"LOGIN_MAX_FAILURES must be greater than zero",
	} {
		assert.Contains(t, msg, want)
	}
	assert.True(t, strings.HasPrefix(msg, "invalid configuration: "))
}

func TestLoadRejectsMalformedIntegersAndCookieSettings(t *testing.T) {
	t.Parallel()

	env := validEnv()
	env["LOGIN_SOURCE_MAX_FAILURES"] = "many"
	env["REFRESH_COOKIE_PATH"] = "auth"

	_, err := Load(lookup(env))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "LOGIN_SOURCE_MAX_FAILURES must be an integer")
	assert.Contains(t, err.Error(), "REFRESH_COOKIE_PATH must be absolute")
}
