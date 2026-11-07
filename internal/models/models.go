// Package models holds the identity domain types and the request/response
// payloads described by docs/openapi_spec.yaml.
package models

import (
	"encoding/json"
	"time"
)

// UserStatus is the lifecycle state of an account.
type UserStatus string

// Supported account statuses.
const (
	UserStatusActive      UserStatus = "active"
	UserStatusDeactivated UserStatus = "deactivated"
)

// User is an account row of the users table.
type User struct {
	ID             string
	Email          string
	Username       string
	DisplayName    string
	EmailVerified  bool
	Status         UserStatus
	AccountVersion int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// PublicProfile projects the user fields that may be shared with other members
// and peer services.
func (u *User) PublicProfile() PublicProfile {
	return PublicProfile{UserID: u.ID, Username: u.Username, DisplayName: u.DisplayName}
}

// OwnProfile projects every field the account owner may see.
func (u *User) OwnProfile() OwnProfile {
	return OwnProfile{
		UserID:        u.ID,
		Email:         u.Email,
		Username:      u.Username,
		DisplayName:   u.DisplayName,
		EmailVerified: u.EmailVerified,
	}
}

// Credential is the password hash stored for an account.
type Credential struct {
	UserID       string
	PasswordHash string
	UpdatedAt    time.Time
}

// VerificationToken is a single-use email verification token. Only the SHA-256
// hash of the opaque token is stored.
type VerificationToken struct {
	ID         string
	UserID     string
	TokenHash  string
	ExpiresAt  time.Time
	ConsumedAt *time.Time
	CreatedAt  time.Time
}

// Consumed reports whether the token was already used and invalidated.
func (t *VerificationToken) Consumed() bool { return t.ConsumedAt != nil }

// Expired reports whether the token is past its expiry at now.
func (t *VerificationToken) Expired(now time.Time) bool { return !now.Before(t.ExpiresAt) }

// PasswordResetToken is a single-use password reset token. Only the SHA-256
// hash of the opaque token is stored.
type PasswordResetToken struct {
	ID         string
	UserID     string
	TokenHash  string
	ExpiresAt  time.Time
	ConsumedAt *time.Time
	CreatedAt  time.Time
}

// Consumed reports whether the token was already used and invalidated.
func (t *PasswordResetToken) Consumed() bool { return t.ConsumedAt != nil }

// Expired reports whether the token is past its expiry at now.
func (t *PasswordResetToken) Expired(now time.Time) bool { return !now.Before(t.ExpiresAt) }

// Session is a signed-in device. Its ID is the JWT sid claim.
type Session struct {
	ID          string
	UserID      string
	DeviceLabel string
	CreatedAt   time.Time
	LastSeenAt  time.Time
	RevokedAt   *time.Time
}

// Active reports whether the session can still be used.
func (s *Session) Active() bool { return s.RevokedAt == nil }

// RefreshTokenStatus is the rotation state of a refresh token.
type RefreshTokenStatus string

// Supported refresh-token statuses.
const (
	RefreshTokenActive  RefreshTokenStatus = "active"
	RefreshTokenRotated RefreshTokenStatus = "rotated"
	RefreshTokenRevoked RefreshTokenStatus = "revoked"
)

// RefreshToken is one link in a session's rotation family.
type RefreshToken struct {
	ID           string
	SessionID    string
	FamilyID     string
	TokenHash    string
	Status       RefreshTokenStatus
	ReplacedByID *string
	ExpiresAt    time.Time
	CreatedAt    time.Time
}

// AccountChange enumerates the account changes published as EVT-001.
type AccountChange string

// Supported account change values.
const (
	AccountChangeEmailVerified AccountChange = "email_verified"
	AccountChangeProfileUpdate AccountChange = "profile_updated"
	AccountChangeEmailChanged  AccountChange = "email_changed"
	AccountChangeDeactivated   AccountChange = "deactivated"
)

// SigningKeyStatus is the rotation state of an access-token signing key.
type SigningKeyStatus string

// Supported signing-key statuses.
const (
	SigningKeyCurrent SigningKeyStatus = "current"
	SigningKeyNext    SigningKeyStatus = "next"
	SigningKeyRetired SigningKeyStatus = "retired"
)

// SigningKey is an RS256 key pair used to sign access tokens.
type SigningKey struct {
	Kid          string
	Algorithm    string
	PublicKeyJWK json.RawMessage
	PrivateKey   string
	Status       SigningKeyStatus
	CreatedAt    time.Time
	RetiredAt    *time.Time
}

// LoginOutcome is the recorded result of a sign-in attempt.
type LoginOutcome string

// Supported login attempt outcomes.
const (
	LoginOutcomeSuccess LoginOutcome = "success"
	LoginOutcomeFailure LoginOutcome = "failure"
	LoginOutcomeLocked  LoginOutcome = "locked"
)

// LoginAttempt is one row of the throttling ledger.
type LoginAttempt struct {
	ID          int64
	AccountKey  string
	SourceKey   string
	Outcome     LoginOutcome
	AttemptedAt time.Time
}

// ThrottleState aggregates the failure counters used to decide whether sign-in
// is temporarily locked for an account or a source address.
type ThrottleState struct {
	AccountFailures      int
	SourceFailures       int
	AccountLastFailureAt time.Time
	SourceLastFailureAt  time.Time
}

// OutboxRecord is a committed event awaiting publication to Kafka.
type OutboxRecord struct {
	ID          string
	Topic       string
	Key         string
	Envelope    json.RawMessage
	Payload     json.RawMessage
	PublishedAt *time.Time
	CreatedAt   time.Time
}

// Published reports whether the record already reached the broker.
func (r *OutboxRecord) Published() bool { return r.PublishedAt != nil }
