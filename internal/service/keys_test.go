package service

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"identity_service/internal/clock"
	"identity_service/internal/models"
	"identity_service/tests/fakes"
)

func TestEnsureKeysPublishesCurrentThenNext(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	jwks, err := env.keys.JWKS(tracedContext())
	require.NoError(t, err)
	require.Len(t, jwks.Keys, 2)

	current, err := env.store.Repositories().SigningKeys.GetByStatus(tracedContext(), models.SigningKeyCurrent)
	require.NoError(t, err)
	next, err := env.store.Repositories().SigningKeys.GetByStatus(tracedContext(), models.SigningKeyNext)
	require.NoError(t, err)

	assert.Equal(t, current.Kid, jwks.Keys[0].Kid, "the current key is published first")
	assert.Equal(t, next.Kid, jwks.Keys[1].Kid)
	for _, key := range jwks.Keys {
		assert.Equal(t, "RSA", key.Kty)
		assert.Equal(t, "RS256", key.Alg)
		assert.Equal(t, "sig", key.Use)
		assert.NotEmpty(t, key.N)
		assert.NotEmpty(t, key.E)
		assert.NotEmpty(t, key.Kid)
	}
}

func TestJWKSNeverExposesPrivateMaterial(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	jwks, err := env.keys.JWKS(tracedContext())
	require.NoError(t, err)

	encoded, err := json.Marshal(jwks)
	require.NoError(t, err)
	body := string(encoded)
	assert.NotContains(t, body, "PRIVATE KEY")
	assert.NotContains(t, body, "private_key")
	assert.NotContains(t, body, "d=")
	assert.NotContains(t, body, "p=")
}

func TestRotationKeepsRetiredKeyPublishedDuringOverlap(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	userID := env.verifiedUser(t, "user@example.com", "user", testPassword)
	login := env.login(t, "user@example.com", testPassword)

	// Capture which key signed the token.
	parsed, _, err := jwt.NewParser().ParseUnverified(login.AccessToken, jwt.MapClaims{})
	require.NoError(t, err)
	oldKid := parsed.Header["kid"].(string)

	require.NoError(t, env.keys.Rotate(tracedContext()))

	jwks, err := env.keys.JWKS(tracedContext())
	require.NoError(t, err)
	require.Len(t, jwks.Keys, 3, "current, next and the retired key inside the overlap window")
	assert.NotEqual(t, oldKid, jwks.Keys[0].Kid, "a fresh key signs new tokens")

	// Tokens signed by the retired key still verify during the overlap.
	_, err = env.tokens.Verify(tracedContext(), login.AccessToken)
	require.NoError(t, err)

	// New tokens use the promoted key.
	rotatedToken, _, err := env.tokens.Issue(tracedContext(), env.store.User(userID), mustUUID(t))
	require.NoError(t, err)
	newParsed, _, err := jwt.NewParser().ParseUnverified(rotatedToken, jwt.MapClaims{})
	require.NoError(t, err)
	assert.Equal(t, jwks.Keys[0].Kid, newParsed.Header["kid"])

	// Once the overlap window closes the retired key disappears and its tokens
	// stop validating.
	env.clock.Advance(env.config.SigningKeyRotationOverlap + time.Minute)
	if _, err := env.store.Repositories().SigningKeys.DeleteRetiredBefore(tracedContext(),
		env.now().Add(-env.config.SigningKeyRotationOverlap)); err != nil {
		require.NoError(t, err)
	}
	jwks, err = env.keys.JWKS(tracedContext())
	require.NoError(t, err)
	require.Len(t, jwks.Keys, 2)
	for _, key := range jwks.Keys {
		assert.NotEqual(t, oldKid, key.Kid)
	}
	_, err = env.tokens.Verify(tracedContext(), login.AccessToken)
	require.Error(t, err)
}

func TestEnsureKeysRotatesWhenIntervalElapsed(t *testing.T) {
	t.Parallel()

	store := fakes.NewStore()
	cfg := testConfig()
	clk := clock.NewFixed(testNow.Add(-time.Hour))
	repos := store.Repositories()
	manager := NewKeyManager(repos.SigningKeys, repos.Transactor, clk,
		time.Hour, cfg.SigningKeyRotationOverlap, nil)
	require.NoError(t, manager.EnsureKeys(tracedContext()))

	before, err := repos.SigningKeys.GetByStatus(tracedContext(), models.SigningKeyCurrent)
	require.NoError(t, err)

	// Two hours later the one-hour rotation interval has elapsed.
	clk.Advance(2 * time.Hour)
	require.NoError(t, manager.EnsureKeys(tracedContext()))

	after, err := repos.SigningKeys.GetByStatus(tracedContext(), models.SigningKeyCurrent)
	require.NoError(t, err)
	assert.NotEqual(t, before.Kid, after.Kid, "the next key was promoted")
	_, err = repos.SigningKeys.GetByStatus(tracedContext(), models.SigningKeyNext)
	require.NoError(t, err, "a fresh next key exists after the rotation")
}

func TestTokenIssuerClaimsAndValidation(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	userID := env.verifiedUser(t, "user@example.com", "user", testPassword)
	user := env.store.User(userID)

	token, expiresIn, err := env.tokens.Issue(tracedContext(), user, mustUUID(t))
	require.NoError(t, err)
	assert.Equal(t, 600, expiresIn)

	claims, err := env.tokens.Verify(tracedContext(), token)
	require.NoError(t, err)
	assert.Equal(t, userID, claims.UserID)
	assert.True(t, claims.EmailVerified)
	assert.Equal(t, env.now().Unix(), claims.IssuedAt.Unix())

	// Tokens for another audience or issuer are rejected.
	foreign := NewTokenIssuer(env.keys, "other_issuer", "other_audience", time.Minute, env.clock)
	foreignToken, _, err := foreign.Issue(tracedContext(), user, mustUUID(t))
	require.NoError(t, err)
	_, err = env.tokens.Verify(tracedContext(), foreignToken)
	require.ErrorIs(t, err, ErrInvalidAccessToken)

	// Tampered and malformed tokens are rejected.
	_, err = env.tokens.Verify(tracedContext(), token+"x")
	require.ErrorIs(t, err, ErrInvalidAccessToken)
	_, err = env.tokens.Verify(tracedContext(), "not-a-jwt")
	require.ErrorIs(t, err, ErrInvalidAccessToken)

	// Expired tokens are rejected.
	env.clock.Advance(11 * time.Minute)
	_, err = env.tokens.Verify(tracedContext(), token)
	require.ErrorIs(t, err, ErrInvalidAccessToken)
}

func TestTokenIssuerRequiresKnownKid(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	user := &models.User{ID: mustUUID(t), EmailVerified: true}
	token, _, err := env.tokens.Issue(tracedContext(), user, mustUUID(t))
	require.NoError(t, err)

	_, err = env.keys.PublicKey(tracedContext(), "unknown-kid")
	require.ErrorIs(t, err, ErrUnknownSigningKey)
	assert.True(t, strings.Contains(err.Error(), "unknown-kid"))
	assert.NotEmpty(t, token)
}
