// Package mocks provides testify-based test doubles for the repository,
// publisher, notifier and HTTP-service boundaries.
package mocks

import (
	"context"
	"time"

	"github.com/stretchr/testify/mock"

	"identity_service/internal/email"
	"identity_service/internal/events"
	"identity_service/internal/models"
	"identity_service/internal/repository"
)

// UserRepository is a testify mock of repository.UserRepository.
type UserRepository struct{ mock.Mock }

// Create implements repository.UserRepository.
func (m *UserRepository) Create(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

// GetByID implements repository.UserRepository.
func (m *UserRepository) GetByID(ctx context.Context, id string) (*models.User, error) {
	args := m.Called(ctx, id)
	user, _ := args.Get(0).(*models.User)
	return user, args.Error(1)
}

// GetByEmail implements repository.UserRepository.
func (m *UserRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	args := m.Called(ctx, email)
	user, _ := args.Get(0).(*models.User)
	return user, args.Error(1)
}

// GetByUsername implements repository.UserRepository.
func (m *UserRepository) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	args := m.Called(ctx, username)
	user, _ := args.Get(0).(*models.User)
	return user, args.Error(1)
}

// GetByIDs implements repository.UserRepository.
func (m *UserRepository) GetByIDs(ctx context.Context, ids []string) ([]models.User, error) {
	args := m.Called(ctx, ids)
	users, _ := args.Get(0).([]models.User)
	return users, args.Error(1)
}

// UpdateDisplayName implements repository.UserRepository.
func (m *UserRepository) UpdateDisplayName(ctx context.Context, id, displayName string) (*models.User, error) {
	args := m.Called(ctx, id, displayName)
	user, _ := args.Get(0).(*models.User)
	return user, args.Error(1)
}

// MarkEmailVerified implements repository.UserRepository.
func (m *UserRepository) MarkEmailVerified(ctx context.Context, id string) (*models.User, error) {
	args := m.Called(ctx, id)
	user, _ := args.Get(0).(*models.User)
	return user, args.Error(1)
}

// CredentialRepository is a testify mock of repository.CredentialRepository.
type CredentialRepository struct{ mock.Mock }

// Upsert implements repository.CredentialRepository.
func (m *CredentialRepository) Upsert(ctx context.Context, userID, passwordHash string) error {
	args := m.Called(ctx, userID, passwordHash)
	return args.Error(0)
}

// GetPasswordHash implements repository.CredentialRepository.
func (m *CredentialRepository) GetPasswordHash(ctx context.Context, userID string) (string, error) {
	args := m.Called(ctx, userID)
	return args.String(0), args.Error(1)
}

// VerificationTokenRepository is a testify mock of
// repository.VerificationTokenRepository.
type VerificationTokenRepository struct{ mock.Mock }

// Create implements repository.VerificationTokenRepository.
func (m *VerificationTokenRepository) Create(ctx context.Context, token *models.VerificationToken) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

// ConsumePending implements repository.VerificationTokenRepository.
func (m *VerificationTokenRepository) ConsumePending(ctx context.Context, userID string, at time.Time) error {
	args := m.Called(ctx, userID, at)
	return args.Error(0)
}

// GetByHash implements repository.VerificationTokenRepository.
func (m *VerificationTokenRepository) GetByHash(ctx context.Context, tokenHash string) (*models.VerificationToken, error) {
	args := m.Called(ctx, tokenHash)
	token, _ := args.Get(0).(*models.VerificationToken)
	return token, args.Error(1)
}

// Consume implements repository.VerificationTokenRepository.
func (m *VerificationTokenRepository) Consume(ctx context.Context, id string, at time.Time) error {
	args := m.Called(ctx, id, at)
	return args.Error(0)
}

// PasswordResetTokenRepository is a testify mock of
// repository.PasswordResetTokenRepository.
type PasswordResetTokenRepository struct{ mock.Mock }

// Create implements repository.PasswordResetTokenRepository.
func (m *PasswordResetTokenRepository) Create(ctx context.Context, token *models.PasswordResetToken) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

// ConsumePending implements repository.PasswordResetTokenRepository.
func (m *PasswordResetTokenRepository) ConsumePending(ctx context.Context, userID string, at time.Time) error {
	args := m.Called(ctx, userID, at)
	return args.Error(0)
}

// GetByHash implements repository.PasswordResetTokenRepository.
func (m *PasswordResetTokenRepository) GetByHash(ctx context.Context, tokenHash string) (*models.PasswordResetToken, error) {
	args := m.Called(ctx, tokenHash)
	token, _ := args.Get(0).(*models.PasswordResetToken)
	return token, args.Error(1)
}

// Consume implements repository.PasswordResetTokenRepository.
func (m *PasswordResetTokenRepository) Consume(ctx context.Context, id string, at time.Time) error {
	args := m.Called(ctx, id, at)
	return args.Error(0)
}

// SessionRepository is a testify mock of repository.SessionRepository.
type SessionRepository struct{ mock.Mock }

// Create implements repository.SessionRepository.
func (m *SessionRepository) Create(ctx context.Context, session *models.Session) error {
	args := m.Called(ctx, session)
	return args.Error(0)
}

// GetByID implements repository.SessionRepository.
func (m *SessionRepository) GetByID(ctx context.Context, id string) (*models.Session, error) {
	args := m.Called(ctx, id)
	session, _ := args.Get(0).(*models.Session)
	return session, args.Error(1)
}

// ListActiveByUser implements repository.SessionRepository.
func (m *SessionRepository) ListActiveByUser(ctx context.Context, userID string, cursor *repository.PageCursor, limit int) ([]models.Session, error) {
	args := m.Called(ctx, userID, cursor, limit)
	sessions, _ := args.Get(0).([]models.Session)
	return sessions, args.Error(1)
}

// Touch implements repository.SessionRepository.
func (m *SessionRepository) Touch(ctx context.Context, id string, at time.Time) error {
	args := m.Called(ctx, id, at)
	return args.Error(0)
}

// Revoke implements repository.SessionRepository.
func (m *SessionRepository) Revoke(ctx context.Context, id string, at time.Time) error {
	args := m.Called(ctx, id, at)
	return args.Error(0)
}

// RevokeAllByUser implements repository.SessionRepository.
func (m *SessionRepository) RevokeAllByUser(ctx context.Context, userID string, at time.Time) error {
	args := m.Called(ctx, userID, at)
	return args.Error(0)
}

// CountActive implements repository.SessionRepository.
func (m *SessionRepository) CountActive(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

// RefreshTokenRepository is a testify mock of
// repository.RefreshTokenRepository.
type RefreshTokenRepository struct{ mock.Mock }

// Create implements repository.RefreshTokenRepository.
func (m *RefreshTokenRepository) Create(ctx context.Context, token *models.RefreshToken) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

// GetByHashForUpdate implements repository.RefreshTokenRepository.
func (m *RefreshTokenRepository) GetByHashForUpdate(ctx context.Context, tokenHash string) (*models.RefreshToken, error) {
	args := m.Called(ctx, tokenHash)
	token, _ := args.Get(0).(*models.RefreshToken)
	return token, args.Error(1)
}

// MarkRotated implements repository.RefreshTokenRepository.
func (m *RefreshTokenRepository) MarkRotated(ctx context.Context, id, replacedByID string) error {
	args := m.Called(ctx, id, replacedByID)
	return args.Error(0)
}

// RevokeFamily implements repository.RefreshTokenRepository.
func (m *RefreshTokenRepository) RevokeFamily(ctx context.Context, familyID string) error {
	args := m.Called(ctx, familyID)
	return args.Error(0)
}

// RevokeBySession implements repository.RefreshTokenRepository.
func (m *RefreshTokenRepository) RevokeBySession(ctx context.Context, sessionID string) error {
	args := m.Called(ctx, sessionID)
	return args.Error(0)
}

// RevokeByUser implements repository.RefreshTokenRepository.
func (m *RefreshTokenRepository) RevokeByUser(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

// LoginAttemptRepository is a testify mock of
// repository.LoginAttemptRepository.
type LoginAttemptRepository struct{ mock.Mock }

// Record implements repository.LoginAttemptRepository.
func (m *LoginAttemptRepository) Record(ctx context.Context, attempt *models.LoginAttempt) error {
	args := m.Called(ctx, attempt)
	return args.Error(0)
}

// StateSince implements repository.LoginAttemptRepository.
func (m *LoginAttemptRepository) StateSince(ctx context.Context, accountKey, sourceKey string, since time.Time) (*models.ThrottleState, error) {
	args := m.Called(ctx, accountKey, sourceKey, since)
	state, _ := args.Get(0).(*models.ThrottleState)
	return state, args.Error(1)
}

// ResetAccount implements repository.LoginAttemptRepository.
func (m *LoginAttemptRepository) ResetAccount(ctx context.Context, accountKey string) error {
	args := m.Called(ctx, accountKey)
	return args.Error(0)
}

// SigningKeyRepository is a testify mock of repository.SigningKeyRepository.
type SigningKeyRepository struct{ mock.Mock }

// Create implements repository.SigningKeyRepository.
func (m *SigningKeyRepository) Create(ctx context.Context, key *models.SigningKey) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

// GetByStatus implements repository.SigningKeyRepository.
func (m *SigningKeyRepository) GetByStatus(ctx context.Context, status models.SigningKeyStatus) (*models.SigningKey, error) {
	args := m.Called(ctx, status)
	key, _ := args.Get(0).(*models.SigningKey)
	return key, args.Error(1)
}

// ListPublished implements repository.SigningKeyRepository.
func (m *SigningKeyRepository) ListPublished(ctx context.Context, retiredCutoff time.Time) ([]models.SigningKey, error) {
	args := m.Called(ctx, retiredCutoff)
	keys, _ := args.Get(0).([]models.SigningKey)
	return keys, args.Error(1)
}

// SetStatus implements repository.SigningKeyRepository.
func (m *SigningKeyRepository) SetStatus(ctx context.Context, kid string, status models.SigningKeyStatus, retiredAt *time.Time) error {
	args := m.Called(ctx, kid, status, retiredAt)
	return args.Error(0)
}

// DeleteRetiredBefore implements repository.SigningKeyRepository.
func (m *SigningKeyRepository) DeleteRetiredBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	args := m.Called(ctx, cutoff)
	return args.Get(0).(int64), args.Error(1)
}

// OutboxRepository is a testify mock of repository.OutboxRepository.
type OutboxRepository struct{ mock.Mock }

// Insert implements repository.OutboxRepository.
func (m *OutboxRepository) Insert(ctx context.Context, record *models.OutboxRecord) error {
	args := m.Called(ctx, record)
	return args.Error(0)
}

// Unpublished implements repository.OutboxRepository.
func (m *OutboxRepository) Unpublished(ctx context.Context, limit int) ([]models.OutboxRecord, error) {
	args := m.Called(ctx, limit)
	records, _ := args.Get(0).([]models.OutboxRecord)
	return records, args.Error(1)
}

// MarkPublished implements repository.OutboxRepository.
func (m *OutboxRepository) MarkPublished(ctx context.Context, id string, at time.Time) error {
	args := m.Called(ctx, id, at)
	return args.Error(0)
}

// Transactor is a testify mock of repository.Transactor that runs the callback
// directly.
type Transactor struct{ mock.Mock }

// WithTx implements repository.Transactor.
func (m *Transactor) WithTx(ctx context.Context, fn func(ctx context.Context) error) error {
	m.Called(ctx)
	return fn(ctx)
}

// Publisher is a testify mock of events.Publisher.
type Publisher struct{ mock.Mock }

// Publish implements events.Publisher.
func (m *Publisher) Publish(ctx context.Context, msg events.OutboundMessage) error {
	args := m.Called(ctx, msg)
	return args.Error(0)
}

// Connected implements events.Publisher.
func (m *Publisher) Connected() bool {
	return m.Called().Bool(0)
}

// Flush implements events.Publisher.
func (m *Publisher) Flush(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// Close implements events.Publisher.
func (m *Publisher) Close() error {
	return m.Called().Error(0)
}

// Notifier is a testify mock of email.Notifier.
type Notifier struct{ mock.Mock }

// SendVerification implements email.Notifier.
func (m *Notifier) SendVerification(ctx context.Context, msg email.VerificationMessage) error {
	args := m.Called(ctx, msg)
	return args.Error(0)
}

// SendPasswordReset implements email.Notifier.
func (m *Notifier) SendPasswordReset(ctx context.Context, msg email.PasswordResetMessage) error {
	args := m.Called(ctx, msg)
	return args.Error(0)
}

// SendPasswordChanged implements email.Notifier.
func (m *Notifier) SendPasswordChanged(ctx context.Context, msg email.PasswordChangedMessage) error {
	args := m.Called(ctx, msg)
	return args.Error(0)
}

// AuthService is a testify mock of handler.AuthService.
type AuthService struct{ mock.Mock }

// Register implements handler.AuthService.
func (m *AuthService) Register(ctx context.Context, req models.RegisterRequest, idempotencyKey string) (*models.RegisterResult, error) {
	args := m.Called(ctx, req, idempotencyKey)
	result, _ := args.Get(0).(*models.RegisterResult)
	return result, args.Error(1)
}

// VerifyEmail implements handler.AuthService.
func (m *AuthService) VerifyEmail(ctx context.Context, token string) (*models.VerifyEmailResponse, error) {
	args := m.Called(ctx, token)
	response, _ := args.Get(0).(*models.VerifyEmailResponse)
	return response, args.Error(1)
}

// ResendVerification implements handler.AuthService.
func (m *AuthService) ResendVerification(ctx context.Context, emailAddr string) error {
	args := m.Called(ctx, emailAddr)
	return args.Error(0)
}

// Login implements handler.AuthService.
func (m *AuthService) Login(ctx context.Context, req models.LoginRequest, sourceKey string) (*models.LoginResult, error) {
	args := m.Called(ctx, req, sourceKey)
	result, _ := args.Get(0).(*models.LoginResult)
	return result, args.Error(1)
}

// Refresh implements handler.AuthService.
func (m *AuthService) Refresh(ctx context.Context, refreshToken string) (*models.LoginResult, error) {
	args := m.Called(ctx, refreshToken)
	result, _ := args.Get(0).(*models.LoginResult)
	return result, args.Error(1)
}

// Logout implements handler.AuthService.
func (m *AuthService) Logout(ctx context.Context, sessionID string) error {
	args := m.Called(ctx, sessionID)
	return args.Error(0)
}

// LogoutAll implements handler.AuthService.
func (m *AuthService) LogoutAll(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

// RequestPasswordReset implements handler.AuthService.
func (m *AuthService) RequestPasswordReset(ctx context.Context, emailAddr string) error {
	args := m.Called(ctx, emailAddr)
	return args.Error(0)
}

// ConfirmPasswordReset implements handler.AuthService.
func (m *AuthService) ConfirmPasswordReset(ctx context.Context, token, newPassword string) error {
	args := m.Called(ctx, token, newPassword)
	return args.Error(0)
}

// AccountService is a testify mock of handler.AccountService.
type AccountService struct{ mock.Mock }

// Profile implements handler.AccountService.
func (m *AccountService) Profile(ctx context.Context, userID string) (*models.OwnProfile, error) {
	args := m.Called(ctx, userID)
	profile, _ := args.Get(0).(*models.OwnProfile)
	return profile, args.Error(1)
}

// UpdateDisplayName implements handler.AccountService.
func (m *AccountService) UpdateDisplayName(ctx context.Context, userID, displayName string) (*models.OwnProfile, error) {
	args := m.Called(ctx, userID, displayName)
	profile, _ := args.Get(0).(*models.OwnProfile)
	return profile, args.Error(1)
}

// LookupByUsername implements handler.AccountService.
func (m *AccountService) LookupByUsername(ctx context.Context, username string) (*models.PublicProfile, error) {
	args := m.Called(ctx, username)
	profile, _ := args.Get(0).(*models.PublicProfile)
	return profile, args.Error(1)
}

// PublicProfiles implements handler.AccountService.
func (m *AccountService) PublicProfiles(ctx context.Context, ids []string) (*models.PublicProfileList, error) {
	args := m.Called(ctx, ids)
	list, _ := args.Get(0).(*models.PublicProfileList)
	return list, args.Error(1)
}

// SessionService is a testify mock of handler.SessionService.
type SessionService struct{ mock.Mock }

// ListSessions implements handler.SessionService.
func (m *SessionService) ListSessions(ctx context.Context, userID, currentSessionID, cursor string, limit int) (*models.SessionList, error) {
	args := m.Called(ctx, userID, currentSessionID, cursor, limit)
	list, _ := args.Get(0).(*models.SessionList)
	return list, args.Error(1)
}

// RevokeSession implements handler.SessionService.
func (m *SessionService) RevokeSession(ctx context.Context, userID, sessionID string) error {
	args := m.Called(ctx, userID, sessionID)
	return args.Error(0)
}

// KeyService is a testify mock of handler.KeyService.
type KeyService struct{ mock.Mock }

// JWKS implements handler.KeyService.
func (m *KeyService) JWKS(ctx context.Context) (*models.JWKS, error) {
	args := m.Called(ctx)
	jwks, _ := args.Get(0).(*models.JWKS)
	return jwks, args.Error(1)
}

// TokenVerifier is a testify mock of handler.TokenVerifier.
type TokenVerifier struct{ mock.Mock }

// Verify implements handler.TokenVerifier.
func (m *TokenVerifier) Verify(ctx context.Context, raw string) (*models.AccessClaims, error) {
	args := m.Called(ctx, raw)
	claims, _ := args.Get(0).(*models.AccessClaims)
	return claims, args.Error(1)
}

// Readiness is a testify mock of handler.ReadinessChecker.
type Readiness struct {
	mock.Mock
	Err error
}

// Ready implements handler.ReadinessChecker.
func (m *Readiness) Ready(context.Context) error { return m.Err }

var (
	_ repository.UserRepository               = (*UserRepository)(nil)
	_ repository.CredentialRepository         = (*CredentialRepository)(nil)
	_ repository.VerificationTokenRepository  = (*VerificationTokenRepository)(nil)
	_ repository.PasswordResetTokenRepository = (*PasswordResetTokenRepository)(nil)
	_ repository.SessionRepository            = (*SessionRepository)(nil)
	_ repository.RefreshTokenRepository       = (*RefreshTokenRepository)(nil)
	_ repository.LoginAttemptRepository       = (*LoginAttemptRepository)(nil)
	_ repository.SigningKeyRepository         = (*SigningKeyRepository)(nil)
	_ repository.OutboxRepository             = (*OutboxRepository)(nil)
	_ repository.Transactor                   = (*Transactor)(nil)
	_ events.Publisher                        = (*Publisher)(nil)
	_ email.Notifier                          = (*Notifier)(nil)
)
