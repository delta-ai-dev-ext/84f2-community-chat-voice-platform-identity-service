package repository

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCursorRoundTrip(t *testing.T) {
	t.Parallel()

	cursor := PageCursor{
		CreatedAt: time.Date(2026, 2, 11, 12, 0, 0, 123456789, time.UTC),
		ID:        "3f0f5a5e-6f0f-4b3f-9a5e-111111111111",
	}
	encoded := EncodeCursor(cursor)
	decoded, err := DecodeCursor(encoded)
	require.NoError(t, err)
	require.NotNil(t, decoded)
	assert.True(t, cursor.CreatedAt.Equal(decoded.CreatedAt))
	assert.Equal(t, cursor.ID, decoded.ID)
}

func TestDecodeCursorRejectsMalformedValues(t *testing.T) {
	t.Parallel()

	for _, invalid := range []string{
		"",
		"!!!not-base64!!!",
		"bm90LWEtY3Vyc29y",    // "not-a-cursor"
		"MTIzfG5vdC1hLXV1aWQ", // "123|not-a-uuid"
		"bm90LWEtbnVtYmVyfDNmMGY1YTVlLTZmMGYtNGIzZi05YTVlLTExMTExMTExMTExMQ", // bad timestamp
	} {
		_, err := DecodeCursor(invalid)
		assert.ErrorIs(t, err, ErrInvalidCursor, invalid)
	}
}

func TestMapPgError(t *testing.T) {
	t.Parallel()

	assert.NoError(t, mapPgError(nil))
	assert.ErrorIs(t, mapPgError(pgx.ErrNoRows), ErrNotFound)

	for constraint, want := range map[string]error{
		"users_email_key":    ErrEmailConflict,
		"users_username_key": ErrUsernameConflict,
		"users_pkey":         ErrIDConflict,
	} {
		err := &pgconn.PgError{Code: "23505", ConstraintName: constraint}
		assert.ErrorIs(t, mapPgError(err), want, constraint)
	}

	other := &pgconn.PgError{Code: "23505", ConstraintName: "email_verification_tokens_token_hash_key"}
	assert.ErrorIs(t, mapPgError(other), ErrIDConflict)

	unrelated := &pgconn.PgError{Code: "42P01", Message: "relation does not exist"}
	assert.Equal(t, unrelated, mapPgError(unrelated))

	plain := errors.New("connection reset")
	assert.Equal(t, plain, mapPgError(plain))
}

func TestUUIDArgs(t *testing.T) {
	t.Parallel()

	args := uuidArgs([]string{"3f0f5a5e-6f0f-4b3f-9a5e-111111111111", "not-a-uuid"})
	require.Len(t, args, 1)
	assert.True(t, args[0].Valid)

	invalid := uuidArg("not-a-uuid")
	assert.False(t, invalid.Valid, "an unparsable id becomes SQL NULL and never matches")
}

func TestRepositoriesBundleIsComplete(t *testing.T) {
	t.Parallel()

	db := &Postgres{}
	bundle := db.Repositories()
	assert.NotNil(t, bundle.Users)
	assert.NotNil(t, bundle.Credentials)
	assert.NotNil(t, bundle.VerificationTokens)
	assert.NotNil(t, bundle.PasswordResets)
	assert.NotNil(t, bundle.Sessions)
	assert.NotNil(t, bundle.RefreshTokens)
	assert.NotNil(t, bundle.LoginAttempts)
	assert.NotNil(t, bundle.SigningKeys)
	assert.NotNil(t, bundle.Outbox)
	assert.NotNil(t, bundle.Transactor)
}
