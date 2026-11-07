package repository

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"identity_service/internal/models"
)

const signingKeyColumns = `kid, algorithm, public_key_jwk, private_key, status, created_at, retired_at`

func scanSigningKey(row pgx.Row) (*models.SigningKey, error) {
	var key models.SigningKey
	if err := row.Scan(&key.Kid, &key.Algorithm, &key.PublicKeyJWK, &key.PrivateKey, &key.Status,
		&key.CreatedAt, &key.RetiredAt); err != nil {
		return nil, mapPgError(err)
	}
	return &key, nil
}

// CreateSigningKey stores a key pair and its rotation status.
func (db *Postgres) CreateSigningKey(ctx context.Context, key *models.SigningKey) error {
	const query = `INSERT INTO signing_keys (kid, algorithm, public_key_jwk, private_key, status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := db.q(ctx).Exec(ctx, query, key.Kid, key.Algorithm, []byte(key.PublicKeyJWK), key.PrivateKey,
		string(key.Status), key.CreatedAt)
	return mapPgError(err)
}

// GetSigningKeyByStatus loads the key with the given rotation status.
func (db *Postgres) GetSigningKeyByStatus(ctx context.Context, status models.SigningKeyStatus) (*models.SigningKey, error) {
	query := `SELECT ` + signingKeyColumns + ` FROM signing_keys WHERE status = $1
		ORDER BY created_at DESC LIMIT 1`
	return scanSigningKey(db.q(ctx).QueryRow(ctx, query, string(status)))
}

// ListPublished returns the keys a verifier may use: current, next, and retired
// keys whose retirement is not older than the overlap cutoff.
func (db *Postgres) ListPublishedSigningKeys(ctx context.Context, retiredCutoff time.Time) ([]models.SigningKey, error) {
	query := `SELECT ` + signingKeyColumns + ` FROM signing_keys
		WHERE status IN ('current', 'next') OR (status = 'retired' AND retired_at >= $1)
		ORDER BY CASE status WHEN 'current' THEN 0 WHEN 'next' THEN 1 ELSE 2 END, created_at DESC`
	rows, err := db.q(ctx).Query(ctx, query, retiredCutoff)
	if err != nil {
		return nil, mapPgError(err)
	}
	defer rows.Close()

	var keys []models.SigningKey
	for rows.Next() {
		key, scanErr := scanSigningKey(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		keys = append(keys, *key)
	}
	return keys, mapPgError(rows.Err())
}

// SetSigningKeyStatus moves a key to another rotation status.
func (db *Postgres) SetSigningKeyStatus(ctx context.Context, kid string, status models.SigningKeyStatus, retiredAt *time.Time) error {
	const query = `UPDATE signing_keys SET status = $2, retired_at = $3 WHERE kid = $1`
	_, err := db.q(ctx).Exec(ctx, query, kid, string(status), retiredAt)
	return mapPgError(err)
}

// DeleteRetiredSigningKeys removes retired keys whose overlap window closed.
func (db *Postgres) DeleteRetiredSigningKeys(ctx context.Context, cutoff time.Time) (int64, error) {
	const query = `DELETE FROM signing_keys WHERE status = 'retired' AND retired_at IS NOT NULL AND retired_at < $1`
	tag, err := db.q(ctx).Exec(ctx, query, cutoff)
	if err != nil {
		return 0, mapPgError(err)
	}
	return tag.RowsAffected(), nil
}

// loginAttemptRepo exposes the throttling ledger over the shared pool.
type loginAttemptRepo struct{ db *Postgres }

// Record appends a sign-in attempt.
func (r loginAttemptRepo) Record(ctx context.Context, attempt *models.LoginAttempt) error {
	const query = `INSERT INTO login_attempts (account_key, source_key, outcome, attempted_at)
		VALUES ($1, $2, $3, $4)`
	_, err := r.db.q(ctx).Exec(ctx, query, attempt.AccountKey, attempt.SourceKey, string(attempt.Outcome), attempt.AttemptedAt)
	return mapPgError(err)
}

// StateSince aggregates failure counters inside the rolling throttle window.
func (r loginAttemptRepo) StateSince(ctx context.Context, accountKey, sourceKey string, since time.Time) (*models.ThrottleState, error) {
	const query = `SELECT
			count(*) FILTER (WHERE account_key = $1),
			count(*) FILTER (WHERE source_key = $2),
			max(attempted_at) FILTER (WHERE account_key = $1),
			max(attempted_at) FILTER (WHERE source_key = $2)
		FROM login_attempts
		WHERE outcome = 'failure' AND attempted_at >= $3 AND (account_key = $1 OR source_key = $2)`
	var (
		state                   models.ThrottleState
		accountLast, sourceLast *time.Time
	)
	if err := r.db.q(ctx).QueryRow(ctx, query, accountKey, sourceKey, since).Scan(
		&state.AccountFailures, &state.SourceFailures, &accountLast, &sourceLast); err != nil {
		return nil, mapPgError(err)
	}
	if accountLast != nil {
		state.AccountLastFailureAt = *accountLast
	}
	if sourceLast != nil {
		state.SourceLastFailureAt = *sourceLast
	}
	return &state, nil
}

// ResetAccount clears the failure window of an account after a success.
func (r loginAttemptRepo) ResetAccount(ctx context.Context, accountKey string) error {
	const query = `DELETE FROM login_attempts WHERE account_key = $1 AND outcome = 'failure'`
	_, err := r.db.q(ctx).Exec(ctx, query, accountKey)
	return mapPgError(err)
}

// outboxRepo exposes the transactional outbox over the shared pool.
type outboxRepo struct{ db *Postgres }

// Insert stores an event in the outbox (inside the state-change transaction).
func (r outboxRepo) Insert(ctx context.Context, record *models.OutboxRecord) error {
	const query = `INSERT INTO event_outbox (id, topic, key, envelope, payload, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := r.db.q(ctx).Exec(ctx, query, uuidArg(record.ID), record.Topic, record.Key,
		[]byte(record.Envelope), []byte(record.Payload), record.CreatedAt)
	return mapPgError(err)
}

// Unpublished returns the oldest unpublished events.
func (r outboxRepo) Unpublished(ctx context.Context, limit int) ([]models.OutboxRecord, error) {
	const query = `SELECT id::text, topic, key, envelope, payload, published_at, created_at
		FROM event_outbox WHERE published_at IS NULL ORDER BY created_at, id LIMIT $1`
	rows, err := r.db.q(ctx).Query(ctx, query, limit)
	if err != nil {
		return nil, mapPgError(err)
	}
	defer rows.Close()

	var records []models.OutboxRecord
	for rows.Next() {
		var record models.OutboxRecord
		if scanErr := rows.Scan(&record.ID, &record.Topic, &record.Key, &record.Envelope, &record.Payload,
			&record.PublishedAt, &record.CreatedAt); scanErr != nil {
			return nil, mapPgError(scanErr)
		}
		records = append(records, record)
	}
	return records, mapPgError(rows.Err())
}

// MarkPublished records successful publication of an outbox event.
func (r outboxRepo) MarkPublished(ctx context.Context, id string, at time.Time) error {
	const query = `UPDATE event_outbox SET published_at = $2 WHERE id = $1`
	_, err := r.db.q(ctx).Exec(ctx, query, uuidArg(id), at)
	return mapPgError(err)
}

// signingKeyRepo exposes the signing-key interface over the shared pool.
type signingKeyRepo struct{ db *Postgres }

// Create implements SigningKeyRepository.
func (r signingKeyRepo) Create(ctx context.Context, key *models.SigningKey) error {
	return r.db.CreateSigningKey(ctx, key)
}

// GetByStatus implements SigningKeyRepository.
func (r signingKeyRepo) GetByStatus(ctx context.Context, status models.SigningKeyStatus) (*models.SigningKey, error) {
	return r.db.GetSigningKeyByStatus(ctx, status)
}

// ListPublished implements SigningKeyRepository.
func (r signingKeyRepo) ListPublished(ctx context.Context, retiredCutoff time.Time) ([]models.SigningKey, error) {
	return r.db.ListPublishedSigningKeys(ctx, retiredCutoff)
}

// SetStatus implements SigningKeyRepository.
func (r signingKeyRepo) SetStatus(ctx context.Context, kid string, status models.SigningKeyStatus, retiredAt *time.Time) error {
	return r.db.SetSigningKeyStatus(ctx, kid, status, retiredAt)
}

// DeleteRetiredBefore implements SigningKeyRepository.
func (r signingKeyRepo) DeleteRetiredBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	return r.db.DeleteRetiredSigningKeys(ctx, cutoff)
}

var (
	_ SigningKeyRepository   = signingKeyRepo{}
	_ LoginAttemptRepository = loginAttemptRepo{}
	_ OutboxRepository       = outboxRepo{}
)
