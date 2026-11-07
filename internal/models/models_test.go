package models

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewUUIDIsCanonicalV4(t *testing.T) {
	t.Parallel()

	id, err := NewUUID()
	require.NoError(t, err)
	assert.True(t, IsUUID(id), id)
	assert.Equal(t, "4", string(id[14]))
	assert.NotEqual(t, id, mustUUID(t))
}

func mustUUID(t *testing.T) string {
	t.Helper()
	id, err := NewUUID()
	require.NoError(t, err)
	return id
}

func TestUUIDFromHashIsDeterministic(t *testing.T) {
	t.Parallel()

	first := UUIDFromHash(sha256.Sum256([]byte("register:key-1")))
	second := UUIDFromHash(sha256.Sum256([]byte("register:key-1")))
	other := UUIDFromHash(sha256.Sum256([]byte("register:key-2")))

	assert.Equal(t, first, second)
	assert.NotEqual(t, first, other)
	assert.True(t, IsUUID(first))
	assert.Equal(t, "4", string(first[14]))
}

func TestIsUUID(t *testing.T) {
	t.Parallel()

	valid := "0f8fad5b-d9cb-469f-a165-70867728950e"
	assert.True(t, IsUUID(valid))
	assert.True(t, IsUUID("0F8FAD5B-D9CB-469F-A165-70867728950E"))

	for _, invalid := range []string{
		"",
		"not-a-uuid",
		"0f8fad5b-d9cb-469f-a165-70867728950",
		"0f8fad5b0d9cb-469f-a165-70867728950e",
		"zf8fad5b-d9cb-469f-a165-70867728950e",
	} {
		assert.False(t, IsUUID(invalid), invalid)
	}
}

func TestNormalisation(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "user@example.com", NormalizeEmail("  User@Example.COM "))
	assert.Equal(t, "some_user", NormalizeUsername(" Some_User "))
}

func TestErrorCarriesCodeDetailAndCause(t *testing.T) {
	t.Parallel()

	cause := errors.New("database is down")
	err := WrapError(CodeEmailUnavailable, "We couldn't send the email. Try again.", cause)

	assert.Equal(t, CodeEmailUnavailable, err.Code)
	assert.Contains(t, err.Error(), "email_unavailable")
	assert.ErrorIs(t, err, cause)
	assert.Equal(t, cause, errors.Unwrap(err))

	code, detail := ErrorDetailOf(err)
	assert.Equal(t, CodeEmailUnavailable, code)
	assert.Equal(t, "We couldn't send the email. Try again.", detail)
}

func TestErrorCodeOfDefaultsToInternal(t *testing.T) {
	t.Parallel()

	assert.Equal(t, CodeInternalError, ErrorCodeOf(errors.New("boom")))

	code, detail := ErrorDetailOf(fmt.Errorf("wrapped: %w", errors.New("boom")))
	assert.Equal(t, CodeInternalError, code)
	assert.Empty(t, detail)
}

func TestValidationErrorf(t *testing.T) {
	t.Parallel()

	err := ValidationErrorf("username must be between %d and %d characters.", 2, 32)
	assert.Equal(t, CodeValidationFailed, err.Code)
	assert.Equal(t, "username must be between 2 and 32 characters.", err.Detail)
	assert.Equal(t, "validation_failed: username must be between 2 and 32 characters.", err.Error())
}

func TestTokenStateHelpers(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	consumedAt := now.Add(-time.Minute)

	verification := &VerificationToken{ExpiresAt: now.Add(time.Hour)}
	assert.False(t, verification.Expired(now))
	assert.False(t, verification.Consumed())
	verification.ConsumedAt = &consumedAt
	assert.True(t, verification.Consumed())
	assert.True(t, verification.Expired(now.Add(2*time.Hour)))

	reset := &PasswordResetToken{ExpiresAt: now}
	assert.True(t, reset.Expired(now))
	assert.False(t, reset.Consumed())

	revokedAt := now
	session := &Session{}
	assert.True(t, session.Active())
	session.RevokedAt = &revokedAt
	assert.False(t, session.Active())

	publishedAt := now
	record := &OutboxRecord{}
	assert.False(t, record.Published())
	record.PublishedAt = &publishedAt
	assert.True(t, record.Published())
}

func TestProfileProjections(t *testing.T) {
	t.Parallel()

	user := &User{ID: mustUUID(t), Email: "user@example.com", Username: "user", DisplayName: "User", EmailVerified: true}

	public := user.PublicProfile()
	assert.Equal(t, user.ID, public.UserID)
	assert.Equal(t, "user", public.Username)
	assert.Equal(t, "User", public.DisplayName)

	own := user.OwnProfile()
	assert.Equal(t, "user@example.com", own.Email)
	assert.True(t, own.EmailVerified)
}
