package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// uuidArg converts a validated UUID string into a pgx UUID parameter. An
// unparsable value becomes SQL NULL, which never matches a row (fail closed).
func uuidArg(id string) pgtype.UUID {
	var u pgtype.UUID
	_ = u.Scan(id)
	return u
}

// uuidArgs converts UUID strings into a pgx UUID array parameter.
func uuidArgs(ids []string) []pgtype.UUID {
	out := make([]pgtype.UUID, 0, len(ids))
	for _, id := range ids {
		var u pgtype.UUID
		if err := u.Scan(id); err != nil {
			continue
		}
		out = append(out, u)
	}
	return out
}

// mapPgError translates driver errors into the package's sentinel errors so
// services never depend on pgx internals.
func mapPgError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		switch pgErr.ConstraintName {
		case "users_email_key":
			return ErrEmailConflict
		case "users_username_key":
			return ErrUsernameConflict
		case "users_pkey":
			return ErrIDConflict
		default:
			return fmt.Errorf("%w: %s", ErrIDConflict, pgErr.ConstraintName)
		}
	}
	return err
}

// txKey is the context key under which an active transaction is stored.
type txKey struct{}

// Postgres is the pgx-backed implementation of every repository interface plus
// Transactor. Repositories obtain the active transaction from the context, so a
// service method can compose several repository calls atomically.
type Postgres struct {
	pool *pgxpool.Pool
}

// Open connects to PostgreSQL and verifies connectivity.
func Open(ctx context.Context, databaseURL string) (*Postgres, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("repository: parse database url: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("repository: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("repository: ping: %w", err)
	}
	return &Postgres{pool: pool}, nil
}

// Ping verifies that PostgreSQL is reachable (readiness probe).
func (db *Postgres) Ping(ctx context.Context) error {
	return db.pool.Ping(ctx)
}

// Close releases every pooled connection.
func (db *Postgres) Close() { db.pool.Close() }

// Pool exposes the underlying pool for startup checks that need raw SQL.
func (db *Postgres) Pool() *pgxpool.Pool { return db.pool }

type querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// q returns the transaction carried by ctx when present, else the pool.
func (db *Postgres) q(ctx context.Context) querier {
	if tx, ok := ctx.Value(txKey{}).(pgx.Tx); ok {
		return tx
	}
	return db.pool
}

// WithTx implements Transactor.
func (db *Postgres) WithTx(ctx context.Context, fn func(ctx context.Context) error) error {
	// Nested calls join the outer transaction instead of opening a new one.
	if _, ok := ctx.Value(txKey{}).(pgx.Tx); ok {
		return fn(ctx)
	}
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("repository: begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	if err := fn(context.WithValue(ctx, txKey{}, tx)); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("repository: commit transaction: %w", err)
	}
	return nil
}
