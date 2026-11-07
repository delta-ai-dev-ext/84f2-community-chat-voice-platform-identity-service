package fakes

import (
	"context"
	"sort"
	"time"

	"identity_service/internal/models"
	"identity_service/internal/repository"
)

// ---- sessions ----

type sessionRepo struct{ s *Store }

func (r sessionRepo) Create(_ context.Context, session *models.Session) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return err
	}
	copied := *session
	r.s.sessions[session.ID] = &copied
	return nil
}

func (r sessionRepo) GetByID(_ context.Context, id string) (*models.Session, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return nil, err
	}
	session, ok := r.s.sessions[id]
	if !ok {
		return nil, repository.ErrNotFound
	}
	copied := *session
	return &copied, nil
}

func (r sessionRepo) ListActiveByUser(_ context.Context, userID string, cursor *repository.PageCursor, limit int) ([]models.Session, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return nil, err
	}
	active := make([]models.Session, 0, len(r.s.sessions))
	for _, session := range r.s.sessions {
		if session.UserID == userID && session.Active() {
			active = append(active, *session)
		}
	}
	sort.Slice(active, func(i, j int) bool {
		if active[i].CreatedAt.Equal(active[j].CreatedAt) {
			return active[i].ID > active[j].ID
		}
		return active[i].CreatedAt.After(active[j].CreatedAt)
	})
	if cursor != nil {
		filtered := make([]models.Session, 0, len(active))
		for _, session := range active {
			if session.CreatedAt.Before(cursor.CreatedAt) ||
				(session.CreatedAt.Equal(cursor.CreatedAt) && session.ID < cursor.ID) {
				filtered = append(filtered, session)
			}
		}
		active = filtered
	}
	if limit > 0 && len(active) > limit {
		active = active[:limit]
	}
	return active, nil
}

func (r sessionRepo) Touch(_ context.Context, id string, at time.Time) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return err
	}
	if session, ok := r.s.sessions[id]; ok {
		session.LastSeenAt = at
	}
	return nil
}

func (r sessionRepo) Revoke(_ context.Context, id string, at time.Time) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return err
	}
	if session, ok := r.s.sessions[id]; ok && session.RevokedAt == nil {
		revoked := at
		session.RevokedAt = &revoked
	}
	return nil
}

func (r sessionRepo) RevokeAllByUser(_ context.Context, userID string, at time.Time) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return err
	}
	for _, session := range r.s.sessions {
		if session.UserID == userID && session.RevokedAt == nil {
			revoked := at
			session.RevokedAt = &revoked
		}
	}
	return nil
}

func (r sessionRepo) CountActive(_ context.Context) (int64, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return 0, err
	}
	var count int64
	for _, session := range r.s.sessions {
		if session.Active() {
			count++
		}
	}
	return count, nil
}

// ---- refresh tokens ----

type refreshRepo struct{ s *Store }

func (r refreshRepo) Create(_ context.Context, token *models.RefreshToken) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return err
	}
	copied := *token
	r.s.refreshTokens = append(r.s.refreshTokens, &copied)
	return nil
}

func (r refreshRepo) GetByHashForUpdate(_ context.Context, tokenHash string) (*models.RefreshToken, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return nil, err
	}
	for _, token := range r.s.refreshTokens {
		if token.TokenHash == tokenHash {
			copied := *token
			return &copied, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (r refreshRepo) MarkRotated(_ context.Context, id, replacedByID string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return err
	}
	for _, token := range r.s.refreshTokens {
		if token.ID == id {
			if token.Status != models.RefreshTokenActive {
				return repository.ErrNotFound
			}
			token.Status = models.RefreshTokenRotated
			replacement := replacedByID
			token.ReplacedByID = &replacement
			return nil
		}
	}
	return repository.ErrNotFound
}

func (r refreshRepo) RevokeFamily(_ context.Context, familyID string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return err
	}
	for _, token := range r.s.refreshTokens {
		if token.FamilyID == familyID && token.Status != models.RefreshTokenRevoked {
			token.Status = models.RefreshTokenRevoked
		}
	}
	return nil
}

func (r refreshRepo) RevokeBySession(_ context.Context, sessionID string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return err
	}
	for _, token := range r.s.refreshTokens {
		if token.SessionID == sessionID && token.Status != models.RefreshTokenRevoked {
			token.Status = models.RefreshTokenRevoked
		}
	}
	return nil
}

func (r refreshRepo) RevokeByUser(_ context.Context, userID string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return err
	}
	for _, token := range r.s.refreshTokens {
		if session, ok := r.s.sessions[token.SessionID]; ok && session.UserID == userID &&
			token.Status != models.RefreshTokenRevoked {
			token.Status = models.RefreshTokenRevoked
		}
	}
	return nil
}

var (
	_ repository.SessionRepository      = sessionRepo{}
	_ repository.RefreshTokenRepository = refreshRepo{}
)
