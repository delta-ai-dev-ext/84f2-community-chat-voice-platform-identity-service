package repository

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"identity_service/internal/models"
)

const sessionColumns = `id::text, user_id::text, device_label, created_at, last_seen_at, revoked_at`

func scanSession(row pgx.Row) (*models.Session, error) {
	var session models.Session
	if err := row.Scan(&session.ID, &session.UserID, &session.DeviceLabel, &session.CreatedAt,
		&session.LastSeenAt, &session.RevokedAt); err != nil {
		return nil, mapPgError(err)
	}
	return &session, nil
}

// Create stores a new session row.
func (db *Postgres) CreateSession(ctx context.Context, session *models.Session) error {
	const query = `INSERT INTO sessions (id, user_id, device_label, created_at, last_seen_at)
		VALUES ($1, $2, $3, $4, $5)`
	_, err := db.q(ctx).Exec(ctx, query, uuidArg(session.ID), uuidArg(session.UserID), session.DeviceLabel,
		session.CreatedAt, session.LastSeenAt)
	return mapPgError(err)
}

// GetByID loads a session by id.
func (db *Postgres) GetSession(ctx context.Context, id string) (*models.Session, error) {
	query := `SELECT ` + sessionColumns + ` FROM sessions WHERE id = $1`
	return scanSession(db.q(ctx).QueryRow(ctx, query, uuidArg(id)))
}

// ListActiveByUser returns a page of active sessions newest first.
func (db *Postgres) ListActiveByUser(ctx context.Context, userID string, cursor *PageCursor, limit int) ([]models.Session, error) {
	var (
		rows pgx.Rows
		err  error
	)
	if cursor == nil {
		const query = `SELECT ` + sessionColumns + ` FROM sessions
			WHERE user_id = $1 AND revoked_at IS NULL
			ORDER BY created_at DESC, id DESC LIMIT $2`
		rows, err = db.q(ctx).Query(ctx, query, uuidArg(userID), limit)
	} else {
		const query = `SELECT ` + sessionColumns + ` FROM sessions
			WHERE user_id = $1 AND revoked_at IS NULL AND (created_at, id) < ($2, $3)
			ORDER BY created_at DESC, id DESC LIMIT $4`
		rows, err = db.q(ctx).Query(ctx, query, uuidArg(userID), cursor.CreatedAt, uuidArg(cursor.ID), limit)
	}
	if err != nil {
		return nil, mapPgError(err)
	}
	defer rows.Close()

	var sessions []models.Session
	for rows.Next() {
		session, scanErr := scanSession(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		sessions = append(sessions, *session)
	}
	return sessions, mapPgError(rows.Err())
}

// Touch advances the last-seen timestamp of a session.
func (db *Postgres) Touch(ctx context.Context, id string, at time.Time) error {
	const query = `UPDATE sessions SET last_seen_at = $2 WHERE id = $1`
	_, err := db.q(ctx).Exec(ctx, query, uuidArg(id), at)
	return mapPgError(err)
}

// Revoke marks a session revoked; already-revoked sessions stay revoked.
func (db *Postgres) Revoke(ctx context.Context, id string, at time.Time) error {
	const query = `UPDATE sessions SET revoked_at = COALESCE(revoked_at, $2) WHERE id = $1`
	_, err := db.q(ctx).Exec(ctx, query, uuidArg(id), at)
	return mapPgError(err)
}

// RevokeAllByUser revokes every active session of an account.
func (db *Postgres) RevokeAllByUser(ctx context.Context, userID string, at time.Time) error {
	const query = `UPDATE sessions SET revoked_at = COALESCE(revoked_at, $2) WHERE user_id = $1 AND revoked_at IS NULL`
	_, err := db.q(ctx).Exec(ctx, query, uuidArg(userID), at)
	return mapPgError(err)
}

// CountActive counts active sessions across all accounts (metrics gauge).
func (db *Postgres) CountActive(ctx context.Context) (int64, error) {
	const query = `SELECT count(*) FROM sessions WHERE revoked_at IS NULL`
	var count int64
	if err := db.q(ctx).QueryRow(ctx, query).Scan(&count); err != nil {
		return 0, mapPgError(err)
	}
	return count, nil
}

// CreateRefreshToken stores a refresh token hash.
func (db *Postgres) CreateRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	const query = `INSERT INTO refresh_tokens (id, session_id, family_id, token_hash, status, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := db.q(ctx).Exec(ctx, query, uuidArg(token.ID), uuidArg(token.SessionID), uuidArg(token.FamilyID),
		token.TokenHash, string(token.Status), token.ExpiresAt, token.CreatedAt)
	return mapPgError(err)
}

// GetByHashForUpdate loads and row-locks a refresh token for rotation so two
// concurrent refreshes cannot both rotate the same token.
func (db *Postgres) GetRefreshTokenByHashForUpdate(ctx context.Context, tokenHash string) (*models.RefreshToken, error) {
	const query = `SELECT id::text, session_id::text, family_id::text, token_hash, status, replaced_by_id::text, expires_at, created_at
		FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE`
	var token models.RefreshToken
	err := db.q(ctx).QueryRow(ctx, query, tokenHash).Scan(&token.ID, &token.SessionID, &token.FamilyID,
		&token.TokenHash, &token.Status, &token.ReplacedByID, &token.ExpiresAt, &token.CreatedAt)
	if err != nil {
		return nil, mapPgError(err)
	}
	return &token, nil
}

// MarkRotated marks a refresh token rotated and links it to its successor.
func (db *Postgres) MarkRotated(ctx context.Context, id, replacedByID string) error {
	const query = `UPDATE refresh_tokens SET status = 'rotated', replaced_by_id = $2 WHERE id = $1 AND status = 'active'`
	tag, err := db.q(ctx).Exec(ctx, query, uuidArg(id), uuidArg(replacedByID))
	if err != nil {
		return mapPgError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RevokeFamily revokes every token of a rotation family.
func (db *Postgres) RevokeFamily(ctx context.Context, familyID string) error {
	const query = `UPDATE refresh_tokens SET status = 'revoked' WHERE family_id = $1 AND status <> 'revoked'`
	_, err := db.q(ctx).Exec(ctx, query, uuidArg(familyID))
	return mapPgError(err)
}

// RevokeBySessionTokens revokes every token of one session.
func (db *Postgres) RevokeBySessionTokens(ctx context.Context, sessionID string) error {
	const query = `UPDATE refresh_tokens SET status = 'revoked' WHERE session_id = $1 AND status <> 'revoked'`
	_, err := db.q(ctx).Exec(ctx, query, uuidArg(sessionID))
	return mapPgError(err)
}

// RevokeSessionFamilies revokes the families of a set of sessions in one
// statement (used by password reset and logout-all).
func (db *Postgres) RevokeSessionFamilies(ctx context.Context, userID string) error {
	const query = `UPDATE refresh_tokens SET status = 'revoked'
		WHERE status <> 'revoked' AND session_id IN (SELECT id FROM sessions WHERE user_id = $1)`
	_, err := db.q(ctx).Exec(ctx, query, uuidArg(userID))
	return mapPgError(err)
}

// sessionRepo exposes the session interface over the shared pool.
type sessionRepo struct{ db *Postgres }

// Create implements SessionRepository.
func (r sessionRepo) Create(ctx context.Context, session *models.Session) error {
	return r.db.CreateSession(ctx, session)
}

// GetByID implements SessionRepository.
func (r sessionRepo) GetByID(ctx context.Context, id string) (*models.Session, error) {
	return r.db.GetSession(ctx, id)
}

// ListActiveByUser implements SessionRepository.
func (r sessionRepo) ListActiveByUser(ctx context.Context, userID string, cursor *PageCursor, limit int) ([]models.Session, error) {
	return r.db.ListActiveByUser(ctx, userID, cursor, limit)
}

// Touch implements SessionRepository.
func (r sessionRepo) Touch(ctx context.Context, id string, at time.Time) error {
	return r.db.Touch(ctx, id, at)
}

// Revoke implements SessionRepository.
func (r sessionRepo) Revoke(ctx context.Context, id string, at time.Time) error {
	return r.db.Revoke(ctx, id, at)
}

// RevokeAllByUser implements SessionRepository.
func (r sessionRepo) RevokeAllByUser(ctx context.Context, userID string, at time.Time) error {
	return r.db.RevokeAllByUser(ctx, userID, at)
}

// CountActive implements SessionRepository.
func (r sessionRepo) CountActive(ctx context.Context) (int64, error) {
	return r.db.CountActive(ctx)
}

// refreshTokenRepo exposes the refresh-token interface over the shared pool.
type refreshTokenRepo struct{ db *Postgres }

// Create implements RefreshTokenRepository.
func (r refreshTokenRepo) Create(ctx context.Context, token *models.RefreshToken) error {
	return r.db.CreateRefreshToken(ctx, token)
}

// GetByHashForUpdate implements RefreshTokenRepository.
func (r refreshTokenRepo) GetByHashForUpdate(ctx context.Context, tokenHash string) (*models.RefreshToken, error) {
	return r.db.GetRefreshTokenByHashForUpdate(ctx, tokenHash)
}

// MarkRotated implements RefreshTokenRepository.
func (r refreshTokenRepo) MarkRotated(ctx context.Context, id, replacedByID string) error {
	return r.db.MarkRotated(ctx, id, replacedByID)
}

// RevokeFamily implements RefreshTokenRepository.
func (r refreshTokenRepo) RevokeFamily(ctx context.Context, familyID string) error {
	return r.db.RevokeFamily(ctx, familyID)
}

// RevokeBySession implements RefreshTokenRepository.
func (r refreshTokenRepo) RevokeBySession(ctx context.Context, sessionID string) error {
	return r.db.RevokeBySessionTokens(ctx, sessionID)
}

// RevokeByUser implements RefreshTokenRepository.
func (r refreshTokenRepo) RevokeByUser(ctx context.Context, userID string) error {
	return r.db.RevokeSessionFamilies(ctx, userID)
}

var (
	_ SessionRepository      = sessionRepo{}
	_ RefreshTokenRepository = refreshTokenRepo{}
)
