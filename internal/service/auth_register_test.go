package service

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"identity_service/internal/models"
	"identity_service/internal/security"
)

const testPassword = "correct-horse-battery"

func TestRegisterCreatesUnverifiedAccount(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	result, err := env.service.Register(tracedContext(), models.RegisterRequest{
		Email:       "  New.User@Example.com ",
		Username:    "New_User",
		DisplayName: "New User",
		Password:    testPassword,
	}, "idem-key-1")
	require.NoError(t, err)

	assert.True(t, models.IsUUID(result.UserID))
	assert.True(t, result.VerificationPending)

	user := env.store.User(result.UserID)
	require.NotNil(t, user)
	assert.Equal(t, "new.user@example.com", user.Email)
	assert.Equal(t, "new_user", user.Username)
	assert.False(t, user.EmailVerified)
	assert.Equal(t, models.UserStatusActive, user.Status)
	assert.Equal(t, int64(1), user.AccountVersion)

	// Only the password hash is stored, never the plaintext.
	hash := env.store.CredentialHash(result.UserID)
	require.NotEmpty(t, hash)
	assert.NotEqual(t, testPassword, hash)
	ok, verifyErr := env.hasher.Verify(testPassword, hash)
	require.NoError(t, verifyErr)
	assert.True(t, ok)

	// Only the token hash is stored.
	tokens := env.store.VerificationTokens()
	require.Len(t, tokens, 1)
	require.Len(t, env.notifier.Verification, 1)
	sent := env.notifier.Verification[0]
	assert.NotEqual(t, sent.Token, tokens[0].TokenHash)
	assert.Equal(t, security.HashToken(sent.Token), tokens[0].TokenHash)
	assert.Equal(t, env.now().Add(24*60*60*1e9).Unix(), tokens[0].ExpiresAt.Unix())

	// Registration must not publish an account event (US-015).
	assert.Empty(t, env.store.Outbox())
}

func TestRegisterIsIdempotentPerKey(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	request := models.RegisterRequest{
		Email: "user@example.com", Username: "user", DisplayName: "User", Password: testPassword,
	}

	first, err := env.service.Register(tracedContext(), request, "retry-key")
	require.NoError(t, err)
	second, err := env.service.Register(tracedContext(), request, "retry-key")
	require.NoError(t, err)

	assert.Equal(t, first.UserID, second.UserID)
	assert.Len(t, env.store.VerificationTokens(), 1, "the replay must not mint a second token")
	assert.Equal(t, 1, env.notifier.VerificationCount())
}

func TestRegisterRejectsIdempotencyKeyReuseForDifferentAccount(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	_, err := env.service.Register(tracedContext(), models.RegisterRequest{
		Email: "one@example.com", Username: "one", DisplayName: "One", Password: testPassword,
	}, "shared-key")
	require.NoError(t, err)

	_, err = env.service.Register(tracedContext(), models.RegisterRequest{
		Email: "two@example.com", Username: "two", DisplayName: "Two", Password: testPassword,
	}, "shared-key")
	require.Error(t, err)
	assert.Equal(t, models.CodeBadRequest, models.ErrorCodeOf(err))
}

func TestRegisterDuplicateEmailAndUsername(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	env.registerUser(t, "taken@example.com", "taken", testPassword)

	_, err := env.service.Register(tracedContext(), models.RegisterRequest{
		Email: "Taken@Example.com", Username: "other", DisplayName: "Other", Password: testPassword,
	}, "")
	require.Error(t, err)
	assert.Equal(t, models.CodeEmailAlreadyRegistered, models.ErrorCodeOf(err))
	assert.Equal(t, 1, env.notifier.VerificationCount(), "no email may be sent for a duplicate")

	_, err = env.service.Register(tracedContext(), models.RegisterRequest{
		Email: "other@example.com", Username: "TAKEN", DisplayName: "Other", Password: testPassword,
	}, "")
	require.Error(t, err)
	assert.Equal(t, models.CodeUsernameTaken, models.ErrorCodeOf(err))
}

func TestRegisterValidation(t *testing.T) {
	t.Parallel()

	valid := models.RegisterRequest{
		Email: "user@example.com", Username: "user", DisplayName: "User", Password: testPassword,
	}
	cases := map[string]func(*models.RegisterRequest){
		"bad email":      func(r *models.RegisterRequest) { r.Email = "not-an-email" },
		"short username": func(r *models.RegisterRequest) { r.Username = "a" },
		"long username":  func(r *models.RegisterRequest) { r.Username = "abcdefghijklmnopqrstuvwxyz0123456" },
		"bad username":   func(r *models.RegisterRequest) { r.Username = "Has Space" },
		"empty display":  func(r *models.RegisterRequest) { r.DisplayName = "   " },
		"long display":   func(r *models.RegisterRequest) { r.DisplayName = longString(65) },
		"short password": func(r *models.RegisterRequest) { r.Password = "short" },
		"long password":  func(r *models.RegisterRequest) { r.Password = longString(129) },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			env := newTestEnv(t)
			req := valid
			mutate(&req)
			_, err := env.service.Register(tracedContext(), req, "")
			require.Error(t, err)
			assert.Equal(t, models.CodeValidationFailed, models.ErrorCodeOf(err))
			assert.Empty(t, env.store.Sessions())
		})
	}
}

func TestRegisterSucceedsWhenVerificationEmailFails(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	env.notifier.SetFailure(errors.New("resend is down"))

	result, err := env.service.Register(tracedContext(), models.RegisterRequest{
		Email: "user@example.com", Username: "user", DisplayName: "User", Password: testPassword,
	}, "")
	require.NoError(t, err, "a delivery failure must not fail the registration")
	assert.True(t, result.VerificationPending)
	require.NotNil(t, env.store.User(result.UserID))
}

func TestVerifyEmailPublishesAccountChangedEvent(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	userID, raw := env.registerUser(t, "user@example.com", "user", testPassword)

	response, err := env.service.VerifyEmail(tracedContext(), raw)
	require.NoError(t, err)
	assert.Equal(t, userID, response.UserID)
	assert.True(t, response.EmailVerified)

	user := env.store.User(userID)
	assert.True(t, user.EmailVerified)
	assert.Equal(t, int64(2), user.AccountVersion)

	records := env.store.Outbox()
	require.Len(t, records, 1)
	assert.Equal(t, "identity_events", records[0].Topic)
	assert.Equal(t, userID, records[0].Key)
	assert.Contains(t, string(records[0].Payload), `"change":"email_verified"`)
	assert.Contains(t, string(records[0].Payload), `"account_version":2`)

	var envelope map[string]any
	require.NoError(t, json.Unmarshal(records[0].Envelope, &envelope))
	assert.Equal(t, "0123456789abcdef0123456789abcdef", envelope["trace_id"])
	assert.Equal(t, "user_account_changed", envelope["event_type"])
	assert.Equal(t, "EVENT_CONTRACTS.md#user_account_changed-v1", envelope["schema_ref"])
}

func TestVerifyEmailRejectsExpiredToken(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	_, raw := env.registerUser(t, "user@example.com", "user", testPassword)

	env.clock.Advance(25 * 60 * 60 * 1e9)
	_, err := env.service.VerifyEmail(tracedContext(), raw)
	require.Error(t, err)
	assert.Equal(t, models.CodeVerificationExpired, models.ErrorCodeOf(err))
	assert.Empty(t, env.store.Outbox())
}

func TestVerifyEmailRejectsUsedToken(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	_, raw := env.registerUser(t, "user@example.com", "user", testPassword)
	_, err := env.service.VerifyEmail(tracedContext(), raw)
	require.NoError(t, err)

	_, err = env.service.VerifyEmail(tracedContext(), raw)
	require.Error(t, err)
	assert.Equal(t, models.CodeVerificationUsed, models.ErrorCodeOf(err))
}

func TestVerifyEmailRejectsAlreadyVerifiedAccount(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	userID, raw := env.registerUser(t, "user@example.com", "user", testPassword)
	_, err := env.service.VerifyEmail(tracedContext(), raw)
	require.NoError(t, err)

	tokenID, _, err := security.NewOpaqueToken()
	require.NoError(t, err)
	_ = tokenID
	fresh, freshHash, err := security.NewOpaqueToken()
	require.NoError(t, err)
	id := mustUUID(t)
	env.store.AddVerificationToken(&models.VerificationToken{
		ID:        id,
		UserID:    userID,
		TokenHash: freshHash,
		ExpiresAt: env.now().Add(24 * 60 * 60 * 1e9),
		CreatedAt: env.now(),
	})

	_, err = env.service.VerifyEmail(tracedContext(), fresh)
	require.Error(t, err)
	assert.Equal(t, models.CodeAlreadyVerified, models.ErrorCodeOf(err))
	assert.Len(t, env.store.Outbox(), 1, "no duplicate event for an already verified account")
}

func TestVerifyEmailRejectsUnknownAndEmptyToken(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	_, err := env.service.VerifyEmail(tracedContext(), "unknown-token")
	require.Error(t, err)
	assert.Equal(t, models.CodeVerificationExpired, models.ErrorCodeOf(err))

	_, err = env.service.VerifyEmail(tracedContext(), "   ")
	require.Error(t, err)
	assert.Equal(t, models.CodeValidationFailed, models.ErrorCodeOf(err))
}

func TestResendVerificationIsEnumerationSafe(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	require.NoError(t, env.service.ResendVerification(tracedContext(), "missing@example.com"))
	assert.Equal(t, 0, env.notifier.VerificationCount())

	env.verifiedUser(t, "verified@example.com", "verified", testPassword)
	before := env.notifier.VerificationCount()
	require.NoError(t, env.service.ResendVerification(tracedContext(), "verified@example.com"))
	assert.Equal(t, before, env.notifier.VerificationCount(), "verified accounts receive no resend")
}

func TestResendVerificationReplacesPendingToken(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	userID, first := env.registerUser(t, "user@example.com", "user", testPassword)

	require.NoError(t, env.service.ResendVerification(tracedContext(), "user@example.com"))
	require.Equal(t, 2, env.notifier.VerificationCount())
	second := env.notifier.Verification[1].Token
	require.NotEqual(t, first, second)

	// The first link is invalidated by the resend; the newest one works.
	_, err := env.service.VerifyEmail(tracedContext(), first)
	require.Error(t, err)
	assert.Equal(t, models.CodeVerificationUsed, models.ErrorCodeOf(err))

	response, err := env.service.VerifyEmail(tracedContext(), second)
	require.NoError(t, err)
	assert.Equal(t, userID, response.UserID)
}

func TestResendVerificationSurfacesProviderOutageWithoutConsumingTokens(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	_, raw := env.registerUser(t, "user@example.com", "user", testPassword)
	env.notifier.SetFailure(errors.New("resend unavailable"))

	err := env.service.ResendVerification(tracedContext(), "user@example.com")
	require.Error(t, err)
	assert.Equal(t, models.CodeEmailUnavailable, models.ErrorCodeOf(err))

	// The link the user already holds still works.
	_, err = env.service.VerifyEmail(tracedContext(), raw)
	require.NoError(t, err)
}

func TestRegisterValidationErrorsDoNotLeakInternals(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	_, err := env.service.Register(tracedContext(), models.RegisterRequest{Email: "x"}, "")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "sql")
}

func longString(n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = 'a'
	}
	return string(out)
}
