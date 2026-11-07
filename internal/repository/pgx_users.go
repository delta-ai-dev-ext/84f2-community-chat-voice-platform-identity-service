package repository

import (
	"context"

	"github.com/jackc/pgx/v5"

	"identity_service/internal/models"
)

const userColumns = `id::text, email::text, username::text, display_name, email_verified, status, account_version, created_at, updated_at`

func scanUser(row pgx.Row) (*models.User, error) {
	var user models.User
	if err := row.Scan(&user.ID, &user.Email, &user.Username, &user.DisplayName, &user.EmailVerified,
		&user.Status, &user.AccountVersion, &user.CreatedAt, &user.UpdatedAt); err != nil {
		return nil, mapPgError(err)
	}
	return &user, nil
}

// Create inserts an account row.
func (db *Postgres) Create(ctx context.Context, user *models.User) error {
	const query = `INSERT INTO users (id, email, username, display_name, email_verified, status, account_version, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err := db.q(ctx).Exec(ctx, query, uuidArg(user.ID), user.Email, user.Username, user.DisplayName,
		user.EmailVerified, string(user.Status), user.AccountVersion, user.CreatedAt, user.UpdatedAt)
	return mapPgError(err)
}

// GetByID loads an account by primary key.
func (db *Postgres) GetByID(ctx context.Context, id string) (*models.User, error) {
	query := `SELECT ` + userColumns + ` FROM users WHERE id = $1`
	return scanUser(db.q(ctx).QueryRow(ctx, query, uuidArg(id)))
}

// GetByEmail loads an account by case-insensitive email.
func (db *Postgres) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	query := `SELECT ` + userColumns + ` FROM users WHERE email = $1`
	return scanUser(db.q(ctx).QueryRow(ctx, query, email))
}

// GetByUsername loads an account by case-insensitive username.
func (db *Postgres) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	query := `SELECT ` + userColumns + ` FROM users WHERE username = $1`
	return scanUser(db.q(ctx).QueryRow(ctx, query, username))
}

// GetByIDs loads the accounts whose ids are in ids.
func (db *Postgres) GetByIDs(ctx context.Context, ids []string) ([]models.User, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	query := `SELECT ` + userColumns + ` FROM users WHERE id = ANY($1::uuid[])`
	rows, err := db.q(ctx).Query(ctx, query, uuidArgs(ids))
	if err != nil {
		return nil, mapPgError(err)
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		user, scanErr := scanUser(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		users = append(users, *user)
	}
	return users, mapPgError(rows.Err())
}

// UpdateDisplayName sets a new display name and bumps account_version.
func (db *Postgres) UpdateDisplayName(ctx context.Context, id, displayName string) (*models.User, error) {
	query := `UPDATE users SET display_name = $2, account_version = account_version + 1, updated_at = now()
		WHERE id = $1 RETURNING ` + userColumns
	return scanUser(db.q(ctx).QueryRow(ctx, query, uuidArg(id), displayName))
}

// MarkEmailVerified flags the account as verified and bumps account_version.
func (db *Postgres) MarkEmailVerified(ctx context.Context, id string) (*models.User, error) {
	query := `UPDATE users SET email_verified = true, account_version = account_version + 1, updated_at = now()
		WHERE id = $1 RETURNING ` + userColumns
	return scanUser(db.q(ctx).QueryRow(ctx, query, uuidArg(id)))
}

// Upsert stores a password hash, replacing any previous value.
func (db *Postgres) Upsert(ctx context.Context, userID, passwordHash string) error {
	const query = `INSERT INTO credentials (user_id, password_hash) VALUES ($1, $2)
		ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash, updated_at = now()`
	_, err := db.q(ctx).Exec(ctx, query, uuidArg(userID), passwordHash)
	return mapPgError(err)
}

// GetPasswordHash returns the stored PHC hash of an account.
func (db *Postgres) GetPasswordHash(ctx context.Context, userID string) (string, error) {
	const query = `SELECT password_hash FROM credentials WHERE user_id = $1`
	var hash string
	if err := db.q(ctx).QueryRow(ctx, query, uuidArg(userID)).Scan(&hash); err != nil {
		return "", mapPgError(err)
	}
	return hash, nil
}

var _ UserRepository = (*Postgres)(nil)

var _ CredentialRepository = (*Postgres)(nil)
