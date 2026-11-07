// Package repository defines the data-access interfaces of the identity
// service and their PostgreSQL (pgx) implementations. Interfaces live next to
// the implementations so services can be unit tested with testify mocks.
package repository

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"

	"identity_service/internal/models"
)

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("repository: not found")

// ErrEmailConflict is returned when the email unique constraint is violated.
var ErrEmailConflict = errors.New("repository: email already registered")

// ErrUsernameConflict is returned when the username unique constraint is
// violated.
var ErrUsernameConflict = errors.New("repository: username already taken")

// ErrIDConflict is returned when a primary key collision is detected.
var ErrIDConflict = errors.New("repository: id already exists")

// ErrInvalidCursor is returned when a pagination cursor cannot be decoded.
var ErrInvalidCursor = errors.New("repository: invalid cursor")

// Transactor runs a function inside a database transaction. The callback
// receives a context carrying the transaction, which every repository method
// uses automatically.
type Transactor interface {
	// WithTx runs fn atomically; a returned error rolls the transaction back.
	WithTx(ctx context.Context, fn func(ctx context.Context) error) error
}

// UserRepository stores and updates accounts.
type UserRepository interface {
	Create(ctx context.Context, user *models.User) error
	GetByID(ctx context.Context, id string) (*models.User, error)
	GetByEmail(ctx context.Context, email string) (*models.User, error)
	GetByUsername(ctx context.Context, username string) (*models.User, error)
	GetByIDs(ctx context.Context, ids []string) ([]models.User, error)
	UpdateDisplayName(ctx context.Context, id, displayName string) (*models.User, error)
	MarkEmailVerified(ctx context.Context, id string) (*models.User, error)
}

// CredentialRepository stores password hashes.
type CredentialRepository interface {
	Upsert(ctx context.Context, userID, passwordHash string) error
	GetPasswordHash(ctx context.Context, userID string) (string, error)
}

// VerificationTokenRepository stores single-use email verification tokens.
type VerificationTokenRepository interface {
	Create(ctx context.Context, token *models.VerificationToken) error
	ConsumePending(ctx context.Context, userID string, at time.Time) error
	GetByHash(ctx context.Context, tokenHash string) (*models.VerificationToken, error)
	Consume(ctx context.Context, id string, at time.Time) error
}

// PasswordResetTokenRepository stores single-use password reset tokens.
type PasswordResetTokenRepository interface {
	Create(ctx context.Context, token *models.PasswordResetToken) error
	ConsumePending(ctx context.Context, userID string, at time.Time) error
	GetByHash(ctx context.Context, tokenHash string) (*models.PasswordResetToken, error)
	Consume(ctx context.Context, id string, at time.Time) error
}

// SessionRepository stores signed-in devices.
type SessionRepository interface {
	Create(ctx context.Context, session *models.Session) error
	GetByID(ctx context.Context, id string) (*models.Session, error)
	ListActiveByUser(ctx context.Context, userID string, cursor *PageCursor, limit int) ([]models.Session, error)
	Touch(ctx context.Context, id string, at time.Time) error
	Revoke(ctx context.Context, id string, at time.Time) error
	RevokeAllByUser(ctx context.Context, userID string, at time.Time) error
	CountActive(ctx context.Context) (int64, error)
}

// RefreshTokenRepository stores rotating refresh tokens.
type RefreshTokenRepository interface {
	Create(ctx context.Context, token *models.RefreshToken) error
	GetByHashForUpdate(ctx context.Context, tokenHash string) (*models.RefreshToken, error)
	MarkRotated(ctx context.Context, id, replacedByID string) error
	RevokeFamily(ctx context.Context, familyID string) error
	RevokeBySession(ctx context.Context, sessionID string) error
	RevokeByUser(ctx context.Context, userID string) error
}

// LoginAttemptRepository stores the throttling ledger of sign-in attempts.
type LoginAttemptRepository interface {
	Record(ctx context.Context, attempt *models.LoginAttempt) error
	StateSince(ctx context.Context, accountKey, sourceKey string, since time.Time) (*models.ThrottleState, error)
	ResetAccount(ctx context.Context, accountKey string) error
}

// SigningKeyRepository stores the RS256 key rotation states.
type SigningKeyRepository interface {
	Create(ctx context.Context, key *models.SigningKey) error
	GetByStatus(ctx context.Context, status models.SigningKeyStatus) (*models.SigningKey, error)
	ListPublished(ctx context.Context, retiredCutoff time.Time) ([]models.SigningKey, error)
	SetStatus(ctx context.Context, kid string, status models.SigningKeyStatus, retiredAt *time.Time) error
	DeleteRetiredBefore(ctx context.Context, cutoff time.Time) (int64, error)
}

// OutboxRepository stores events committed with their state change.
type OutboxRepository interface {
	Insert(ctx context.Context, record *models.OutboxRecord) error
	Unpublished(ctx context.Context, limit int) ([]models.OutboxRecord, error)
	MarkPublished(ctx context.Context, id string, at time.Time) error
}

// PageCursor is a keyset pagination cursor over (created_at, id) ordered
// descending.
type PageCursor struct {
	CreatedAt time.Time
	ID        string
}

// EncodeCursor renders a cursor as an opaque URL-safe string.
func EncodeCursor(cursor PageCursor) string {
	raw := strconv.FormatInt(cursor.CreatedAt.UTC().UnixNano(), 10) + "|" + cursor.ID
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// DecodeCursor parses an opaque cursor produced by EncodeCursor.
func DecodeCursor(value string) (*PageCursor, error) {
	if value == "" {
		return nil, ErrInvalidCursor
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, ErrInvalidCursor
	}
	parts := strings.SplitN(string(decoded), "|", 2)
	if len(parts) != 2 || !models.IsUUID(parts[1]) {
		return nil, ErrInvalidCursor
	}
	nanos, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return nil, ErrInvalidCursor
	}
	return &PageCursor{CreatedAt: time.Unix(0, nanos).UTC(), ID: parts[1]}, nil
}
