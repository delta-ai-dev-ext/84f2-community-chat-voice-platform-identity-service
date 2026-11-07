package service

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"identity_service/internal/clock"
	"identity_service/internal/config"
	"identity_service/internal/events"
	"identity_service/internal/models"
	"identity_service/internal/observability"
	"identity_service/internal/repository"
	"identity_service/internal/security"
	"identity_service/tests/fakes"
)

// testNow is the frozen clock used by service tests.
var testNow = time.Date(2026, 2, 11, 12, 0, 0, 0, time.UTC)

// testConfig returns a fully populated configuration for tests.
func testConfig() *config.Config {
	return &config.Config{
		Environment:                "test",
		HTTPAddr:                   ":0",
		KafkaTopicIdentityEvents:   "identity_events",
		JWTIssuer:                  "identity_service",
		JWTAudience:                "community_platform",
		AccessTokenTTL:             10 * time.Minute,
		RefreshTokenTTL:            720 * time.Hour,
		EmailVerificationTokenTTL:  24 * time.Hour,
		PasswordResetTokenTTL:      time.Hour,
		SigningKeyRotationInterval: 720 * time.Hour,
		SigningKeyRotationOverlap:  time.Hour,
		LoginMaxFailures:           3,
		LoginSourceMaxFailures:     5,
		LoginWindow:                15 * time.Minute,
		LoginLockout:               15 * time.Minute,
		RefreshCookieName:          "refresh_token",
		RefreshCookiePath:          "/auth",
	}
}

// keyFixture builds one RSA key pair set and reuses it across tests so the
// (expensive) key generation happens once per test binary.
var (
	keyFixtureOnce sync.Once
	keyFixture     *fakes.Store
	keyFixtureErr  error
)

func seedSigningKeys(t *testing.T, store *fakes.Store) {
	t.Helper()
	keyFixtureOnce.Do(func() {
		keyFixture = fakes.NewStore()
		manager := NewKeyManager(keyFixture.Repositories().SigningKeys, nil,
			clock.NewFixed(testNow.Add(-time.Hour)), 720*time.Hour, time.Hour, nil)
		keyFixtureErr = manager.EnsureKeys(context.Background())
	})
	require.NoError(t, keyFixtureErr)
	store.CopySigningKeysFrom(keyFixture)
}

// testEnv bundles the wired service and its doubles.
type testEnv struct {
	store      *fakes.Store
	notifier   *fakes.FakeNotifier
	publisher  *fakes.RecordingPublisher
	dispatcher *events.Dispatcher
	keys       *KeyManager
	tokens     *TokenIssuer
	service    *Service
	config     *config.Config
	clock      *clock.Fixed
	hasher     *security.Hasher
}

func (e *testEnv) now() time.Time { return e.clock.Now() }

// newTestEnv wires the service against in-memory repositories.
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	store := fakes.NewStore()
	seedSigningKeys(t, store)

	cfg := testConfig()
	clk := clock.NewFixed(testNow)
	logger := zap.NewNop()

	hasher, err := security.NewHasher(security.TestArgon2Params())
	require.NoError(t, err)

	repos := store.Repositories()
	keys := NewKeyManager(repos.SigningKeys, repos.Transactor, clk,
		cfg.SigningKeyRotationInterval, cfg.SigningKeyRotationOverlap, logger)
	require.NoError(t, keys.EnsureKeys(context.Background()))

	notifier := &fakes.FakeNotifier{}
	publisher := fakes.NewRecordingPublisher()

	svc, err := NewService(Deps{
		Repos:    repos,
		Keys:     keys,
		Notifier: notifier,
		Clock:    clk,
		Logger:   logger,
		Config:   cfg,
		Hasher:   hasher,
	})
	require.NoError(t, err)

	return &testEnv{
		store:      store,
		notifier:   notifier,
		publisher:  publisher,
		dispatcher: events.NewDispatcher(repos.Outbox, publisher, clk, logger, time.Second, 50),
		keys:       keys,
		tokens:     svc.TokenIssuer(),
		service:    svc,
		config:     cfg,
		clock:      clk,
		hasher:     hasher,
	}
}

// tracedContext returns a context carrying a known trace id.
func tracedContext() context.Context {
	return observability.WithTrace(context.Background(), observability.Trace{
		TraceID:       "0123456789abcdef0123456789abcdef",
		CorrelationID: "22222222-2222-4222-8222-222222222222",
	})
}

// mustUUID returns a fresh UUID or fails the test.
func mustUUID(t *testing.T) string {
	t.Helper()
	id, err := models.NewUUID()
	require.NoError(t, err)
	return id
}

// countingUsers wraps a user repository and counts batch lookups.
type countingUsers struct {
	repository.UserRepository
	calls *int
}

// GetByIDs counts the call before delegating.
func (c *countingUsers) GetByIDs(ctx context.Context, ids []string) ([]models.User, error) {
	*c.calls++
	return c.UserRepository.GetByIDs(ctx, ids)
}

// registerUser registers a user through the service and returns its id and the
// verification token that was emailed.
func (e *testEnv) registerUser(t *testing.T, emailAddr, username, password string) (string, string) {
	t.Helper()

	result, err := e.service.Register(tracedContext(), models.RegisterRequest{
		Email:       emailAddr,
		Username:    username,
		DisplayName: "Test User",
		Password:    password,
	}, "")
	require.NoError(t, err)

	tokens := e.store.VerificationTokens()
	require.NotEmpty(t, tokens)
	raw := ""
	for _, msg := range e.notifier.Verification {
		if msg.To == emailAddr {
			raw = msg.Token
		}
	}
	require.NotEmpty(t, raw, "verification email must have been sent")
	return result.UserID, raw
}

// verifiedUser registers and verifies a user.
func (e *testEnv) verifiedUser(t *testing.T, emailAddr, username, password string) string {
	t.Helper()
	userID, raw := e.registerUser(t, emailAddr, username, password)
	_, err := e.service.VerifyEmail(tracedContext(), raw)
	require.NoError(t, err)
	return userID
}
