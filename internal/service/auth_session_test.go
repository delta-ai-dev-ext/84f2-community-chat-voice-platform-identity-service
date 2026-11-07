package service

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"identity_service/internal/models"
)

// login signs in a verified user and returns the result.
func (e *testEnv) login(t *testing.T, emailAddr, password string) *models.LoginResult {
	t.Helper()
	result, err := e.service.Login(tracedContext(), models.LoginRequest{
		Email:       emailAddr,
		Password:    password,
		DeviceLabel: "Test Browser",
	}, "203.0.113.10")
	require.NoError(t, err)
	return result
}

func TestLoginSucceedsForVerifiedAccount(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	userID := env.verifiedUser(t, "user@example.com", "user", testPassword)

	result := env.login(t, "User@Example.com", testPassword)
	assert.NotEmpty(t, result.AccessToken)
	assert.NotEmpty(t, result.RefreshToken)
	assert.Equal(t, int(10*time.Minute/time.Second), result.ExpiresIn)
	assert.Equal(t, userID, result.User.UserID)

	// The access token verifies against the published keys and carries the
	// documented claims.
	claims, err := env.tokens.Verify(tracedContext(), result.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, userID, claims.UserID)
	assert.NotEmpty(t, claims.SessionID)
	assert.True(t, claims.EmailVerified)
	assert.Equal(t, env.now().Add(10*time.Minute).Unix(), claims.ExpiresAt.Unix())

	parsed, _, err := jwt.NewParser().ParseUnverified(result.AccessToken, jwt.MapClaims{})
	require.NoError(t, err)
	assert.Equal(t, "identity_service", parsed.Claims.(jwt.MapClaims)["iss"])
	assert.Equal(t, []any{"community_platform"}, parsed.Claims.(jwt.MapClaims)["aud"])
	assert.NotEmpty(t, parsed.Header["kid"])

	// Session + refresh token rows are created; only the hash is stored.
	sessions := env.store.Sessions()
	require.Len(t, sessions, 1)
	assert.Equal(t, "Test Browser", sessions[0].DeviceLabel)
	refresh := env.store.RefreshTokens()
	require.Len(t, refresh, 1)
	assert.NotEqual(t, result.RefreshToken, refresh[0].TokenHash)
	assert.Equal(t, models.RefreshTokenActive, refresh[0].Status)
}

func TestLoginIsIndistinguishableForUnknownAccountAndWrongPassword(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	env.verifiedUser(t, "user@example.com", "user", testPassword)

	_, unknownErr := env.service.Login(tracedContext(), models.LoginRequest{
		Email: "nobody@example.com", Password: testPassword,
	}, "203.0.113.11")
	_, wrongErr := env.service.Login(tracedContext(), models.LoginRequest{
		Email: "user@example.com", Password: "wrong-password",
	}, "203.0.113.12")

	require.Error(t, unknownErr)
	require.Error(t, wrongErr)
	assert.Equal(t, models.CodeInvalidCredentials, models.ErrorCodeOf(unknownErr))
	assert.Equal(t, models.CodeInvalidCredentials, models.ErrorCodeOf(wrongErr))
	assert.Equal(t, unknownErr.Error(), wrongErr.Error(), "identical messages prevent enumeration")
	assert.Empty(t, env.store.Sessions())
}

func TestLoginRejectsUnverifiedAccount(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	env.registerUser(t, "user@example.com", "user", testPassword)

	_, err := env.service.Login(tracedContext(), models.LoginRequest{
		Email: "user@example.com", Password: testPassword,
	}, "203.0.113.10")
	require.Error(t, err)
	assert.Equal(t, models.CodeEmailNotVerified, models.ErrorCodeOf(err))
	assert.Empty(t, env.store.Sessions())
}

func TestLoginRejectsDeactivatedAccount(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	userID := env.verifiedUser(t, "user@example.com", "user", testPassword)
	user := env.store.User(userID)
	user.Status = models.UserStatusDeactivated

	_, err := env.service.Login(tracedContext(), models.LoginRequest{
		Email: "user@example.com", Password: testPassword,
	}, "203.0.113.10")
	require.Error(t, err)
	assert.Equal(t, models.CodeInvalidCredentials, models.ErrorCodeOf(err))
}

func TestLoginLocksAccountAfterRepeatedFailures(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	env.verifiedUser(t, "user@example.com", "user", testPassword)

	for i := 0; i < env.config.LoginMaxFailures; i++ {
		_, err := env.service.Login(tracedContext(), models.LoginRequest{
			Email: "user@example.com", Password: "wrong",
		}, "198.51.100.1")
		require.Error(t, err)
		assert.Equal(t, models.CodeInvalidCredentials, models.ErrorCodeOf(err))
	}

	// Even the correct password is rejected while the lockout holds.
	_, err := env.service.Login(tracedContext(), models.LoginRequest{
		Email: "user@example.com", Password: testPassword,
	}, "198.51.100.1")
	require.Error(t, err)
	assert.Equal(t, models.CodeLocked, models.ErrorCodeOf(err))

	locked := env.store.LoginAttempts()
	assert.Equal(t, models.LoginOutcomeLocked, locked[len(locked)-1].Outcome)

	// Once the lockout window expires, sign-in proceeds normally.
	env.clock.Advance(env.config.LoginLockout + time.Second)
	_, err = env.service.Login(tracedContext(), models.LoginRequest{
		Email: "user@example.com", Password: testPassword,
	}, "198.51.100.1")
	require.NoError(t, err)
}

func TestLoginLocksSourceAcrossAccounts(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	env.verifiedUser(t, "one@example.com", "one", testPassword)
	env.verifiedUser(t, "two@example.com", "two", testPassword)

	// Failures recorded for other accounts from the same source address.
	ctx := tracedContext()
	for i := 0; i < env.config.LoginSourceMaxFailures; i++ {
		require.NoError(t, env.store.Repositories().LoginAttempts.Record(ctx, &models.LoginAttempt{
			AccountKey:  fmt.Sprintf("ghost%d@example.com", i),
			SourceKey:   "192.0.2.55",
			Outcome:     models.LoginOutcomeFailure,
			AttemptedAt: env.now(),
		}))
	}

	// A different account from the same source is now locked too.
	_, err := env.service.Login(tracedContext(), models.LoginRequest{
		Email: "two@example.com", Password: testPassword,
	}, "192.0.2.55")
	require.Error(t, err)
	assert.Equal(t, models.CodeLocked, models.ErrorCodeOf(err))

	// A different source is unaffected.
	_, err = env.service.Login(tracedContext(), models.LoginRequest{
		Email: "two@example.com", Password: testPassword,
	}, "192.0.2.99")
	require.NoError(t, err)
}

func TestLoginSuccessResetsFailureWindow(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	env.verifiedUser(t, "user@example.com", "user", testPassword)

	_, err := env.service.Login(tracedContext(), models.LoginRequest{
		Email: "user@example.com", Password: "wrong",
	}, "198.51.100.2")
	require.Error(t, err)
	require.NotEmpty(t, env.store.LoginAttempts())

	env.login(t, "user@example.com", testPassword)

	for _, attempt := range env.store.LoginAttempts() {
		assert.NotEqual(t, models.LoginOutcomeFailure, attempt.Outcome, "failures are cleared after a success")
	}
}

func TestLoginValidatesInput(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	_, err := env.service.Login(tracedContext(), models.LoginRequest{Email: "bad", Password: "x"}, "1.1.1.1")
	require.Error(t, err)
	assert.Equal(t, models.CodeValidationFailed, models.ErrorCodeOf(err))

	_, err = env.service.Login(tracedContext(), models.LoginRequest{Email: "a@b.co", Password: ""}, "1.1.1.1")
	require.Error(t, err)
	assert.Equal(t, models.CodeValidationFailed, models.ErrorCodeOf(err))
}

func TestRefreshRotatesTokenWithinFamily(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	env.verifiedUser(t, "user@example.com", "user", testPassword)
	login := env.login(t, "user@example.com", testPassword)

	rotated, err := env.service.Refresh(tracedContext(), login.RefreshToken)
	require.NoError(t, err)
	assert.NotEqual(t, login.RefreshToken, rotated.RefreshToken)
	assert.NotEmpty(t, rotated.AccessToken)
	assert.Equal(t, login.User.UserID, rotated.User.UserID)

	tokens := env.store.RefreshTokens()
	require.Len(t, tokens, 2)
	var old, fresh *models.RefreshToken
	for i := range tokens {
		switch tokens[i].Status {
		case models.RefreshTokenRotated:
			old = tokens[i]
		case models.RefreshTokenActive:
			fresh = tokens[i]
		}
	}
	require.NotNil(t, old)
	require.NotNil(t, fresh)
	assert.Equal(t, old.FamilyID, fresh.FamilyID)
	require.NotNil(t, old.ReplacedByID)
	assert.Equal(t, fresh.ID, *old.ReplacedByID)

	// The session's last-seen timestamp advanced.
	sessions := env.store.Sessions()
	require.Len(t, sessions, 1)
	assert.Equal(t, env.now(), sessions[0].LastSeenAt)

	// The rotated cookie value can be used for the next rotation.
	_, err = env.service.Refresh(tracedContext(), rotated.RefreshToken)
	require.NoError(t, err)
}

func TestRefreshReuseRevokesFamily(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	env.verifiedUser(t, "user@example.com", "user", testPassword)
	login := env.login(t, "user@example.com", testPassword)

	rotated, err := env.service.Refresh(tracedContext(), login.RefreshToken)
	require.NoError(t, err)

	// Replaying the consumed token is treated as theft.
	_, err = env.service.Refresh(tracedContext(), login.RefreshToken)
	require.Error(t, err)
	assert.Equal(t, models.CodeSessionRevoked, models.ErrorCodeOf(err))

	for _, token := range env.store.RefreshTokens() {
		assert.Equal(t, models.RefreshTokenRevoked, token.Status)
	}
	for _, session := range env.store.Sessions() {
		assert.False(t, session.Active(), "reuse detection revokes the session")
	}

	// The legitimate client is signed out as well.
	_, err = env.service.Refresh(tracedContext(), rotated.RefreshToken)
	require.Error(t, err)
	assert.Equal(t, models.CodeSessionRevoked, models.ErrorCodeOf(err))
}

func TestRefreshRejectsExpiredAndUnknownTokens(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	env.verifiedUser(t, "user@example.com", "user", testPassword)
	login := env.login(t, "user@example.com", testPassword)

	_, err := env.service.Refresh(tracedContext(), "not-a-token")
	require.Error(t, err)
	assert.Equal(t, models.CodeInvalidRefreshToken, models.ErrorCodeOf(err))

	_, err = env.service.Refresh(tracedContext(), "")
	require.Error(t, err)
	assert.Equal(t, models.CodeInvalidRefreshToken, models.ErrorCodeOf(err))

	env.clock.Advance(env.config.RefreshTokenTTL + time.Minute)
	_, err = env.service.Refresh(tracedContext(), login.RefreshToken)
	require.Error(t, err)
	assert.Equal(t, models.CodeInvalidRefreshToken, models.ErrorCodeOf(err))
}

func TestRefreshRejectsRevokedSession(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	env.verifiedUser(t, "user@example.com", "user", testPassword)
	login := env.login(t, "user@example.com", testPassword)

	require.NoError(t, env.service.Logout(tracedContext(), env.store.Sessions()[0].ID))

	_, err := env.service.Refresh(tracedContext(), login.RefreshToken)
	require.Error(t, err)
	assert.Equal(t, models.CodeSessionRevoked, models.ErrorCodeOf(err))
}

func TestLogoutRevokesSessionAndIsIdempotent(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	env.verifiedUser(t, "user@example.com", "user", testPassword)
	env.login(t, "user@example.com", testPassword)
	sessionID := env.store.Sessions()[0].ID

	require.NoError(t, env.service.Logout(tracedContext(), sessionID))
	assert.False(t, env.store.Sessions()[0].Active())
	for _, token := range env.store.RefreshTokens() {
		assert.Equal(t, models.RefreshTokenRevoked, token.Status)
	}

	// A repeated logout still succeeds, as does an unknown session id.
	require.NoError(t, env.service.Logout(tracedContext(), sessionID))
	require.NoError(t, env.service.Logout(tracedContext(), mustUUID(t)))
	require.NoError(t, env.service.Logout(tracedContext(), "not-a-uuid"))
}

func TestLogoutAllRevokesEverySession(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	userID := env.verifiedUser(t, "user@example.com", "user", testPassword)
	env.login(t, "user@example.com", testPassword)
	env.clock.Advance(time.Minute)
	env.login(t, "user@example.com", testPassword)
	require.Len(t, env.store.Sessions(), 2)

	require.NoError(t, env.service.LogoutAll(tracedContext(), userID))
	for _, session := range env.store.Sessions() {
		assert.False(t, session.Active())
	}
	for _, token := range env.store.RefreshTokens() {
		assert.Equal(t, models.RefreshTokenRevoked, token.Status)
	}
}

func TestRequestPasswordResetIsEnumerationSafe(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	require.NoError(t, env.service.RequestPasswordReset(tracedContext(), "missing@example.com"))
	assert.Zero(t, env.notifier.ResetCount())
	assert.Empty(t, env.store.ResetTokens())

	env.verifiedUser(t, "user@example.com", "user", testPassword)
	require.NoError(t, env.service.RequestPasswordReset(tracedContext(), "user@example.com"))
	require.Equal(t, 1, env.notifier.ResetCount())

	tokens := env.store.ResetTokens()
	require.Len(t, tokens, 1)
	assert.NotEqual(t, env.notifier.Resets[0].Token, tokens[0].TokenHash)
	assert.Equal(t, env.now().Add(time.Hour).Unix(), tokens[0].ExpiresAt.Unix())
}

func TestRequestPasswordResetReplacesPreviousToken(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	env.verifiedUser(t, "user@example.com", "user", testPassword)

	require.NoError(t, env.service.RequestPasswordReset(tracedContext(), "user@example.com"))
	first := env.notifier.Resets[0].Token
	require.NoError(t, env.service.RequestPasswordReset(tracedContext(), "user@example.com"))
	second := env.notifier.Resets[1].Token

	err := env.service.ConfirmPasswordReset(tracedContext(), first, "brand-new-password")
	require.Error(t, err)
	assert.Equal(t, models.CodeResetLinkExpired, models.ErrorCodeOf(err))

	require.NoError(t, env.service.ConfirmPasswordReset(tracedContext(), second, "brand-new-password"))
}

func TestRequestPasswordResetSurfacesProviderOutage(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	env.verifiedUser(t, "user@example.com", "user", testPassword)
	env.notifier.SetFailure(errors.New("resend unavailable"))

	err := env.service.RequestPasswordReset(tracedContext(), "user@example.com")
	require.Error(t, err)
	assert.Equal(t, models.CodeEmailUnavailable, models.ErrorCodeOf(err))
	assert.Empty(t, env.store.ResetTokens(), "no token may be stored when the email cannot be sent")
}

func TestConfirmPasswordResetReplacesPasswordAndRevokesSessions(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	userID := env.verifiedUser(t, "user@example.com", "user", testPassword)
	env.login(t, "user@example.com", testPassword)

	require.NoError(t, env.service.RequestPasswordReset(tracedContext(), "user@example.com"))
	raw := env.notifier.Resets[0].Token

	require.NoError(t, env.service.ConfirmPasswordReset(tracedContext(), raw, "brand-new-password"))

	ok, err := env.hasher.Verify("brand-new-password", env.store.CredentialHash(userID))
	require.NoError(t, err)
	assert.True(t, ok)

	for _, session := range env.store.Sessions() {
		assert.False(t, session.Active())
	}
	assert.Equal(t, 1, env.notifier.ChangedCount())

	// The token is single use.
	err = env.service.ConfirmPasswordReset(tracedContext(), raw, "another-password")
	require.Error(t, err)
	assert.Equal(t, models.CodeResetLinkExpired, models.ErrorCodeOf(err))
}

func TestConfirmPasswordResetRejectsExpiredAndWeakInput(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	env.verifiedUser(t, "user@example.com", "user", testPassword)

	err := env.service.ConfirmPasswordReset(tracedContext(), "unknown", "brand-new-password")
	require.Error(t, err)
	assert.Equal(t, models.CodeResetLinkExpired, models.ErrorCodeOf(err))

	require.NoError(t, env.service.RequestPasswordReset(tracedContext(), "user@example.com"))
	raw := env.notifier.Resets[0].Token

	err = env.service.ConfirmPasswordReset(tracedContext(), raw, "short")
	require.Error(t, err)
	assert.Equal(t, models.CodeValidationFailed, models.ErrorCodeOf(err))

	env.clock.Advance(2 * time.Hour)
	err = env.service.ConfirmPasswordReset(tracedContext(), raw, "brand-new-password")
	require.Error(t, err)
	assert.Equal(t, models.CodeResetLinkExpired, models.ErrorCodeOf(err))
}

func TestConfirmPasswordResetSurvivesConfirmationEmailFailure(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	userID := env.verifiedUser(t, "user@example.com", "user", testPassword)
	require.NoError(t, env.service.RequestPasswordReset(tracedContext(), "user@example.com"))
	raw := env.notifier.Resets[0].Token

	env.notifier.SetFailure(errors.New("resend unavailable"))
	require.NoError(t, env.service.ConfirmPasswordReset(tracedContext(), raw, "brand-new-password"))

	ok, err := env.hasher.Verify("brand-new-password", env.store.CredentialHash(userID))
	require.NoError(t, err)
	assert.True(t, ok)
}
