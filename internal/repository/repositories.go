package repository

// Repositories bundles every store the services need plus the transaction
// manager, so wiring stays explicit and test doubles can be substituted one by
// one.
type Repositories struct {
	Users              UserRepository
	Credentials        CredentialRepository
	VerificationTokens VerificationTokenRepository
	PasswordResets     PasswordResetTokenRepository
	Sessions           SessionRepository
	RefreshTokens      RefreshTokenRepository
	LoginAttempts      LoginAttemptRepository
	SigningKeys        SigningKeyRepository
	Outbox             OutboxRepository
	Transactor         Transactor
}

// Repositories returns the PostgreSQL-backed repository set.
func (db *Postgres) Repositories() Repositories {
	return Repositories{
		Users:              db,
		Credentials:        db,
		VerificationTokens: verificationTokenRepo{db: db},
		PasswordResets:     passwordResetTokenRepo{db: db},
		Sessions:           sessionRepo{db: db},
		RefreshTokens:      refreshTokenRepo{db: db},
		LoginAttempts:      loginAttemptRepo{db: db},
		SigningKeys:        signingKeyRepo{db: db},
		Outbox:             outboxRepo{db: db},
		Transactor:         db,
	}
}
