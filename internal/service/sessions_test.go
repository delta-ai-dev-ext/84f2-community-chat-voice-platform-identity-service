package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"identity_service/internal/models"
	"identity_service/internal/repository"
)

func TestListSessionsPaginatesWithStableCursor(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	userID := env.verifiedUser(t, "user@example.com", "user", testPassword)
	for i := 0; i < 5; i++ {
		env.login(t, "user@example.com", testPassword)
		env.clock.Advance(time.Minute)
	}

	first, err := env.service.ListSessions(tracedContext(), userID, "", "", 2)
	require.NoError(t, err)
	require.Len(t, first.Data, 2)
	require.NotNil(t, first.NextCursor)

	second, err := env.service.ListSessions(tracedContext(), userID, "", *first.NextCursor, 2)
	require.NoError(t, err)
	require.Len(t, second.Data, 2)
	require.NotNil(t, second.NextCursor)

	third, err := env.service.ListSessions(tracedContext(), userID, "", *second.NextCursor, 2)
	require.NoError(t, err)
	require.Len(t, third.Data, 1)
	assert.Nil(t, third.NextCursor, "the last page has no cursor")

	// No session appears twice across pages.
	seen := map[string]bool{}
	for _, page := range [][]models.SessionItem{first.Data, second.Data, third.Data} {
		for _, item := range page {
			assert.False(t, seen[item.SessionID], "duplicate session in pagination")
			seen[item.SessionID] = true
		}
	}
	assert.Len(t, seen, 5)
}

func TestListSessionsAppliesDefaultsAndMarksCurrent(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	userID := env.verifiedUser(t, "user@example.com", "user", testPassword)
	env.login(t, "user@example.com", testPassword)
	current := env.store.Sessions()[0].ID

	list, err := env.service.ListSessions(tracedContext(), userID, current, "", 0)
	require.NoError(t, err)
	require.Len(t, list.Data, 1)
	assert.True(t, list.Data[0].IsCurrent)
	assert.Equal(t, "Test Browser", list.Data[0].DeviceLabel)

	list, err = env.service.ListSessions(tracedContext(), userID, "some-other-session", "", 0)
	require.NoError(t, err)
	require.Len(t, list.Data, 1)
	assert.False(t, list.Data[0].IsCurrent)
}

func TestListSessionsHidesRevokedSessions(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	userID := env.verifiedUser(t, "user@example.com", "user", testPassword)
	env.login(t, "user@example.com", testPassword)
	env.clock.Advance(time.Minute)
	env.login(t, "user@example.com", testPassword)

	first := env.store.Sessions()[0].ID
	require.NoError(t, env.service.Logout(tracedContext(), first))

	list, err := env.service.ListSessions(tracedContext(), userID, "", "", 0)
	require.NoError(t, err)
	require.Len(t, list.Data, 1)
	assert.NotEqual(t, first, list.Data[0].SessionID)
}

func TestListSessionsRejectsInvalidPagination(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	userID := env.verifiedUser(t, "user@example.com", "user", testPassword)

	for _, limit := range []int{-1, 101} {
		_, err := env.service.ListSessions(tracedContext(), userID, "", "", limit)
		require.Error(t, err)
		assert.Equal(t, models.CodeValidationFailed, models.ErrorCodeOf(err))
	}

	_, err := env.service.ListSessions(tracedContext(), userID, "", "not-a-cursor", 0)
	require.Error(t, err)
	assert.Equal(t, models.CodeValidationFailed, models.ErrorCodeOf(err))

	// A cursor built by the repository is accepted.
	cursor := repository.EncodeCursor(repository.PageCursor{CreatedAt: env.now(), ID: mustUUID(t)})
	_, err = env.service.ListSessions(tracedContext(), userID, "", cursor, 10)
	require.NoError(t, err)
}

func TestRevokeSessionOwnershipAndIdempotency(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	owner := env.verifiedUser(t, "owner@example.com", "owner", testPassword)
	other := env.verifiedUser(t, "other@example.com", "other", testPassword)
	env.login(t, "owner@example.com", testPassword)
	sessionID := env.store.Sessions()[0].ID

	// Not owned by the caller.
	err := env.service.RevokeSession(tracedContext(), other, sessionID)
	require.Error(t, err)
	assert.Equal(t, models.CodeSessionNotFound, models.ErrorCodeOf(err))
	assert.True(t, env.store.Sessions()[0].Active(), "a foreign session must not be revoked")

	// Malformed and unknown ids behave the same way.
	err = env.service.RevokeSession(tracedContext(), owner, "nope")
	assert.Equal(t, models.CodeSessionNotFound, models.ErrorCodeOf(err))
	err = env.service.RevokeSession(tracedContext(), owner, mustUUID(t))
	assert.Equal(t, models.CodeSessionNotFound, models.ErrorCodeOf(err))

	// The owner can revoke it once.
	require.NoError(t, env.service.RevokeSession(tracedContext(), owner, sessionID))
	assert.False(t, env.store.Sessions()[0].Active())
	for _, token := range env.store.RefreshTokens() {
		assert.Equal(t, models.RefreshTokenRevoked, token.Status)
	}

	// A second revocation reports not found (the session is no longer active).
	err = env.service.RevokeSession(tracedContext(), owner, sessionID)
	assert.Equal(t, models.CodeSessionNotFound, models.ErrorCodeOf(err))
}

func TestSessionOperationsRequireUserID(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	_, err := env.service.ListSessions(tracedContext(), "invalid", "", "", 0)
	require.Error(t, err)
	assert.Equal(t, models.CodeUnauthorized, models.ErrorCodeOf(err))

	err = env.service.RevokeSession(tracedContext(), "invalid", mustUUID(t))
	require.Error(t, err)
	assert.Equal(t, models.CodeUnauthorized, models.ErrorCodeOf(err))
}
