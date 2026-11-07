package service

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"identity_service/internal/models"
)

func TestProfileReturnsOwnProfile(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	userID := env.verifiedUser(t, "user@example.com", "user", testPassword)

	profile, err := env.service.Profile(tracedContext(), userID)
	require.NoError(t, err)
	assert.Equal(t, userID, profile.UserID)
	assert.Equal(t, "user@example.com", profile.Email)
	assert.Equal(t, "user", profile.Username)
	assert.Equal(t, "Test User", profile.DisplayName)
	assert.True(t, profile.EmailVerified)
}

func TestProfileRejectsUnknownAndMalformedIDs(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	for _, id := range []string{"not-a-uuid", mustUUID(t)} {
		_, err := env.service.Profile(tracedContext(), id)
		require.Error(t, err)
		assert.Equal(t, models.CodeUnauthorized, models.ErrorCodeOf(err))
	}
}

func TestUpdateDisplayNameBumpsVersionAndPublishesEvent(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	userID := env.verifiedUser(t, "user@example.com", "user", testPassword)
	before := env.store.User(userID).AccountVersion

	profile, err := env.service.UpdateDisplayName(tracedContext(), userID, "  New Name  ")
	require.NoError(t, err)
	assert.Equal(t, "New Name", profile.DisplayName)
	assert.Equal(t, before+1, env.store.User(userID).AccountVersion, "account_version increments exactly once")

	records := env.store.Outbox()
	require.Len(t, records, 2) // email_verified + profile_updated
	last := records[len(records)-1]
	assert.Equal(t, userID, last.Key)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(last.Payload, &payload))
	assert.Equal(t, "profile_updated", payload["change"])
	assert.Equal(t, "New Name", payload["display_name"])
	assert.Equal(t, float64(before+1), payload["account_version"])
	for _, envelopeField := range []string{"event_id", "event_type", "event_version", "occurred_at", "producer", "trace_id", "correlation_id", "causation_id", "schema_ref"} {
		assert.NotContains(t, payload, envelopeField, "payload must not carry envelope fields")
	}
}

func TestUpdateDisplayNameValidation(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	userID := env.verifiedUser(t, "user@example.com", "user", testPassword)

	for _, invalid := range []string{"", "   ", longString(65)} {
		_, err := env.service.UpdateDisplayName(tracedContext(), userID, invalid)
		require.Error(t, err)
		assert.Equal(t, models.CodeValidationFailed, models.ErrorCodeOf(err))
	}
	assert.Equal(t, "Test User", env.store.User(userID).DisplayName, "the value is unchanged")

	// Exactly 64 characters is accepted.
	profile, err := env.service.UpdateDisplayName(tracedContext(), userID, longString(64))
	require.NoError(t, err)
	assert.Len(t, profile.DisplayName, 64)
}

func TestUpdateDisplayNameRejectsUnknownUser(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	_, err := env.service.UpdateDisplayName(tracedContext(), mustUUID(t), "Ghost")
	require.Error(t, err)
	assert.Equal(t, models.CodeUnauthorized, models.ErrorCodeOf(err))
}

func TestLookupByUsername(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	env.verifiedUser(t, "user@example.com", "SomeUser", testPassword)

	profile, err := env.service.LookupByUsername(tracedContext(), "someuser")
	require.NoError(t, err)
	assert.Equal(t, "someuser", profile.Username)
	assert.Equal(t, "Test User", profile.DisplayName)

	for _, missing := range []string{"nobody", "a", "bad name"} {
		_, err := env.service.LookupByUsername(tracedContext(), missing)
		require.Error(t, err)
		assert.Equal(t, models.CodeUserNotFound, models.ErrorCodeOf(err))
	}
}

func TestPublicProfilesBatch(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	first := env.verifiedUser(t, "one@example.com", "one", testPassword)
	second := env.verifiedUser(t, "two@example.com", "two", testPassword)

	list, err := env.service.PublicProfiles(tracedContext(), []string{first, second, first, mustUUID(t)})
	require.NoError(t, err)
	require.Len(t, list.Data, 2, "duplicates and unknown ids are dropped")
	assert.Equal(t, first, list.Data[0].UserID)
	assert.Equal(t, second, list.Data[1].UserID)

	empty, err := env.service.PublicProfiles(tracedContext(), nil)
	require.NoError(t, err)
	assert.Empty(t, empty.Data)
}

func TestPublicProfilesValidation(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	tooMany := make([]string, 0, MaxBatchLookupIDs+1)
	for i := 0; i <= MaxBatchLookupIDs; i++ {
		tooMany = append(tooMany, mustUUID(t))
	}
	_, err := env.service.PublicProfiles(tracedContext(), tooMany)
	require.Error(t, err)
	assert.Equal(t, models.CodeValidationFailed, models.ErrorCodeOf(err))

	_, err = env.service.PublicProfiles(tracedContext(), []string{"not-a-uuid"})
	require.Error(t, err)
	assert.Equal(t, models.CodeValidationFailed, models.ErrorCodeOf(err))

	ids := make([]string, 0, MaxBatchLookupIDs)
	for i := 0; i < MaxBatchLookupIDs; i++ {
		ids = append(ids, mustUUID(t))
	}
	list, err := env.service.PublicProfiles(tracedContext(), ids)
	require.NoError(t, err)
	assert.Empty(t, list.Data)
}

func TestPublicProfilesUsesSingleRepositoryCall(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	first := env.verifiedUser(t, "one@example.com", "one", testPassword)

	calls := 0
	wrapped := &countingUsers{UserRepository: env.store.Repositories().Users, calls: &calls}
	env.service.repos.Users = wrapped

	list, err := env.service.PublicProfiles(tracedContext(), []string{first, first, first})
	require.NoError(t, err)
	require.Len(t, list.Data, 1)
	assert.Equal(t, 1, calls, fmt.Sprintf("expected one batch call, got %d", calls))
}
