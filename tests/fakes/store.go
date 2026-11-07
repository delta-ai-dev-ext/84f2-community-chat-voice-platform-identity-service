// Package fakes provides in-memory implementations of every repository
// interface plus a recording publisher and a fake email notifier. They make the
// service flows testable without PostgreSQL, Kafka or Resend.
package fakes

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"identity_service/internal/models"
	"identity_service/internal/repository"
)

// Store is an in-memory implementation of every repository interface.
type Store struct {
	mu sync.Mutex

	users         map[string]*models.User
	credentials   map[string]string
	verification  []*models.VerificationToken
	resetTokens   []*models.PasswordResetToken
	sessions      map[string]*models.Session
	refreshTokens []*models.RefreshToken
	attempts      []models.LoginAttempt
	keys          map[string]*models.SigningKey
	outbox        []*models.OutboxRecord

	// TxCount counts transactions started through WithTx.
	TxCount int
	// FailWith, when set, makes the next repository call fail.
	FailWith error
}

// NewStore returns an empty in-memory store.
func NewStore() *Store {
	return &Store{
		users:       map[string]*models.User{},
		credentials: map[string]string{},
		sessions:    map[string]*models.Session{},
		keys:        map[string]*models.SigningKey{},
	}
}

// Repositories exposes the store as the service's repository bundle.
func (s *Store) Repositories() repository.Repositories {
	return repository.Repositories{
		Users:              userRepo{s},
		Credentials:        credentialRepo{s},
		VerificationTokens: verificationRepo{s},
		PasswordResets:     resetRepo{s},
		Sessions:           sessionRepo{s},
		RefreshTokens:      refreshRepo{s},
		LoginAttempts:      attemptRepo{s},
		SigningKeys:        keyRepo{s},
		Outbox:             outboxRepo{s},
		Transactor:         s,
	}
}

// WithTx implements repository.Transactor. The in-memory store has no real
// transaction scope, so the callback simply runs; the lock must NOT be held
// while it runs because every repository call re-acquires it.
func (s *Store) WithTx(ctx context.Context, fn func(ctx context.Context) error) error {
	s.mu.Lock()
	s.TxCount++
	s.mu.Unlock()
	return fn(ctx)
}

func (s *Store) fail() error {
	if s.FailWith != nil {
		err := s.FailWith
		s.FailWith = nil
		return err
	}
	return nil
}

// AddUser inserts a user directly (test setup).
func (s *Store) AddUser(user *models.User, passwordHash string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[user.ID] = user
	if passwordHash != "" {
		s.credentials[user.ID] = passwordHash
	}
}

// AddVerificationToken inserts a verification token directly (test setup).
func (s *Store) AddVerificationToken(token *models.VerificationToken) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verification = append(s.verification, token)
}

// VerificationTokens returns the stored verification tokens.
func (s *Store) VerificationTokens() []*models.VerificationToken {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*models.VerificationToken, len(s.verification))
	copy(out, s.verification)
	return out
}

// ResetTokens returns the stored password-reset tokens.
func (s *Store) ResetTokens() []*models.PasswordResetToken {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*models.PasswordResetToken, len(s.resetTokens))
	copy(out, s.resetTokens)
	return out
}

// AddSession inserts a session directly (test setup).
func (s *Store) AddSession(session *models.Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	copied := *session
	s.sessions[session.ID] = &copied
}

// Sessions returns the stored sessions.
func (s *Store) Sessions() []*models.Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*models.Session, 0, len(s.sessions))
	for _, session := range s.sessions {
		out = append(out, session)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// RefreshTokens returns the stored refresh tokens.
func (s *Store) RefreshTokens() []*models.RefreshToken {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*models.RefreshToken, len(s.refreshTokens))
	copy(out, s.refreshTokens)
	return out
}

// LoginAttempts returns the recorded attempts.
func (s *Store) LoginAttempts() []models.LoginAttempt {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]models.LoginAttempt, len(s.attempts))
	copy(out, s.attempts)
	return out
}

// Outbox returns the stored outbox records.
func (s *Store) Outbox() []*models.OutboxRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*models.OutboxRecord, len(s.outbox))
	copy(out, s.outbox)
	return out
}

// CredentialHash returns the stored password hash of a user.
func (s *Store) CredentialHash(userID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.credentials[userID]
}

// CopySigningKeysFrom copies the signing keys of another store. Tests use it to
// reuse one expensive RSA key generation fixture across cases.
func (s *Store) CopySigningKeysFrom(src *Store) {
	src.mu.Lock()
	keys := make([]models.SigningKey, 0, len(src.keys))
	for _, key := range src.keys {
		keys = append(keys, *key)
	}
	src.mu.Unlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, key := range keys {
		copied := key
		s.keys[key.Kid] = &copied
	}
}

// User returns a stored user.
func (s *Store) User(id string) *models.User {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.users[id]
}

// ---- users ----

type userRepo struct{ s *Store }

func (r userRepo) Create(_ context.Context, user *models.User) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return err
	}
	for _, existing := range r.s.users {
		if strings.EqualFold(existing.Email, user.Email) {
			return repository.ErrEmailConflict
		}
		if strings.EqualFold(existing.Username, user.Username) {
			return repository.ErrUsernameConflict
		}
	}
	if _, ok := r.s.users[user.ID]; ok {
		return repository.ErrIDConflict
	}
	copied := *user
	r.s.users[user.ID] = &copied
	return nil
}

func (r userRepo) GetByID(_ context.Context, id string) (*models.User, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return nil, err
	}
	user, ok := r.s.users[id]
	if !ok {
		return nil, repository.ErrNotFound
	}
	copied := *user
	return &copied, nil
}

func (r userRepo) GetByEmail(_ context.Context, email string) (*models.User, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return nil, err
	}
	for _, user := range r.s.users {
		if strings.EqualFold(user.Email, email) {
			copied := *user
			return &copied, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (r userRepo) GetByUsername(_ context.Context, username string) (*models.User, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return nil, err
	}
	for _, user := range r.s.users {
		if strings.EqualFold(user.Username, username) {
			copied := *user
			return &copied, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (r userRepo) GetByIDs(_ context.Context, ids []string) ([]models.User, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return nil, err
	}
	var out []models.User
	for _, id := range ids {
		if user, ok := r.s.users[id]; ok {
			out = append(out, *user)
		}
	}
	return out, nil
}

func (r userRepo) UpdateDisplayName(_ context.Context, id, displayName string) (*models.User, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return nil, err
	}
	user, ok := r.s.users[id]
	if !ok {
		return nil, repository.ErrNotFound
	}
	user.DisplayName = displayName
	user.AccountVersion++
	user.UpdatedAt = user.UpdatedAt.Add(time.Second)
	copied := *user
	return &copied, nil
}

func (r userRepo) MarkEmailVerified(_ context.Context, id string) (*models.User, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return nil, err
	}
	user, ok := r.s.users[id]
	if !ok {
		return nil, repository.ErrNotFound
	}
	user.EmailVerified = true
	user.AccountVersion++
	copied := *user
	return &copied, nil
}

// ---- credentials ----

type credentialRepo struct{ s *Store }

func (r credentialRepo) Upsert(_ context.Context, userID, passwordHash string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return err
	}
	r.s.credentials[userID] = passwordHash
	return nil
}

func (r credentialRepo) GetPasswordHash(_ context.Context, userID string) (string, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return "", err
	}
	hash, ok := r.s.credentials[userID]
	if !ok {
		return "", repository.ErrNotFound
	}
	return hash, nil
}

var (
	_ repository.UserRepository       = userRepo{}
	_ repository.CredentialRepository = credentialRepo{}
)
