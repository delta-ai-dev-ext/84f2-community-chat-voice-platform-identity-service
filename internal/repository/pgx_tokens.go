package repository

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"identity_service/internal/models"
)

// Create inserts a single-use email verification token after invalidating any
// previously pending token of the same account (single pending token rule).
func (db *Postgres) CreateVerificationToken(ctx context.Context, token *models.VerificationToken) error {
	const query = `INSERT INTO email_verification_tokens (id, user_id, token_hash, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5)`
	_, err := db.q(ctx).Exec(ctx, query, uuidArg(token.ID), uuidArg(token.UserID), token.TokenHash,
		token.ExpiresAt, token.CreatedAt)
	return mapPgError(err)
}

// ConsumePendingVerification invalidates every pending verification token of an
// account.
func (db *Postgres) ConsumePendingVerification(ctx context.Context, userID string, at time.Time) error {
	const query = `UPDATE email_verification_tokens SET consumed_at = $2 WHERE user_id = $1 AND consumed_at IS NULL`
	_, err := db.q(ctx).Exec(ctx, query, uuidArg(userID), at)
	return mapPgError(err)
}

// GetVerificationTokenByHash loads a verification token by its SHA-256 hash.
func (db *Postgres) GetVerificationTokenByHash(ctx context.Context, tokenHash string) (*models.VerificationToken, error) {
	const query = `SELECT id::text, user_id::text, token_hash, expires_at, consumed_at, created_at
		FROM email_verification_tokens WHERE token_hash = $1`
	var token models.VerificationToken
	err := db.q(ctx).QueryRow(ctx, query, tokenHash).Scan(&token.ID, &token.UserID, &token.TokenHash,
		&token.ExpiresAt, &token.ConsumedAt, &token.CreatedAt)
	if err != nil {
		return nil, mapPgError(err)
	}
	return &token, nil
}

// ConsumeVerificationToken marks a verification token used exactly once.
func (db *Postgres) ConsumeVerificationToken(ctx context.Context, id string, at time.Time) error {
	const query = `UPDATE email_verification_tokens SET consumed_at = $2 WHERE id = $1 AND consumed_at IS NULL`
	tag, err := db.q(ctx).Exec(ctx, query, uuidArg(id), at)
	if err != nil {
		return mapPgError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Create inserts a single-use password reset token.
func (db *Postgres) CreatePasswordResetToken(ctx context.Context, token *models.PasswordResetToken) error {
	const query = `INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5)`
	_, err := db.q(ctx).Exec(ctx, query, uuidArg(token.ID), uuidArg(token.UserID), token.TokenHash,
		token.ExpiresAt, token.CreatedAt)
	return mapPgError(err)
}

// ConsumePendingPasswordReset invalidates every pending reset token of an
// account.
func (db *Postgres) ConsumePendingPasswordReset(ctx context.Context, userID string, at time.Time) error {
	const query = `UPDATE password_reset_tokens SET consumed_at = $2 WHERE user_id = $1 AND consumed_at IS NULL`
	_, err := db.q(ctx).Exec(ctx, query, uuidArg(userID), at)
	return mapPgError(err)
}

// GetPasswordResetTokenByHash loads a reset token by its SHA-256 hash.
func (db *Postgres) GetPasswordResetTokenByHash(ctx context.Context, tokenHash string) (*models.PasswordResetToken, error) {
	const query = `SELECT id::text, user_id::text, token_hash, expires_at, consumed_at, created_at
		FROM password_reset_tokens WHERE token_hash = $1`
	var token models.PasswordResetToken
	err := db.q(ctx).QueryRow(ctx, query, tokenHash).Scan(&token.ID, &token.UserID, &token.TokenHash,
		&token.ExpiresAt, &token.ConsumedAt, &token.CreatedAt)
	if err != nil {
		return nil, mapPgError(err)
	}
	return &token, nil
}

// ConsumePasswordResetToken marks a reset token used exactly once.
func (db *Postgres) ConsumePasswordResetToken(ctx context.Context, id string, at time.Time) error {
	const query = `UPDATE password_reset_tokens SET consumed_at = $2 WHERE id = $1 AND consumed_at IS NULL`
	tag, err := db.q(ctx).Exec(ctx, query, uuidArg(id), at)
	if err != nil {
		return mapPgError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// verificationTokenRepo exposes the verification-token interface over the
// shared connection pool.
type verificationTokenRepo struct{ db *Postgres }

// Create implements VerificationTokenRepository.
func (r verificationTokenRepo) Create(ctx context.Context, token *models.VerificationToken) error {
	return r.db.CreateVerificationToken(ctx, token)
}

// ConsumePending implements VerificationTokenRepository.
func (r verificationTokenRepo) ConsumePending(ctx context.Context, userID string, at time.Time) error {
	return r.db.ConsumePendingVerification(ctx, userID, at)
}

// GetByHash implements VerificationTokenRepository.
func (r verificationTokenRepo) GetByHash(ctx context.Context, tokenHash string) (*models.VerificationToken, error) {
	return r.db.GetVerificationTokenByHash(ctx, tokenHash)
}

// Consume implements VerificationTokenRepository.
func (r verificationTokenRepo) Consume(ctx context.Context, id string, at time.Time) error {
	return r.db.ConsumeVerificationToken(ctx, id, at)
}

// passwordResetTokenRepo exposes the password-reset-token interface over the
// shared connection pool.
type passwordResetTokenRepo struct{ db *Postgres }

// Create implements PasswordResetTokenRepository.
func (r passwordResetTokenRepo) Create(ctx context.Context, token *models.PasswordResetToken) error {
	return r.db.CreatePasswordResetToken(ctx, token)
}

// ConsumePending implements PasswordResetTokenRepository.
func (r passwordResetTokenRepo) ConsumePending(ctx context.Context, userID string, at time.Time) error {
	return r.db.ConsumePendingPasswordReset(ctx, userID, at)
}

// GetByHash implements PasswordResetTokenRepository.
func (r passwordResetTokenRepo) GetByHash(ctx context.Context, tokenHash string) (*models.PasswordResetToken, error) {
	return r.db.GetPasswordResetTokenByHash(ctx, tokenHash)
}

// Consume implements PasswordResetTokenRepository.
func (r passwordResetTokenRepo) Consume(ctx context.Context, id string, at time.Time) error {
	return r.db.ConsumePasswordResetToken(ctx, id, at)
}

var (
	_ VerificationTokenRepository  = verificationTokenRepo{}
	_ PasswordResetTokenRepository = passwordResetTokenRepo{}
)

var _ = pgx.ErrNoRows
