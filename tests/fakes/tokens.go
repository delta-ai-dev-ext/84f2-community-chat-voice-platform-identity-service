package fakes

import (
	"context"
	"time"

	"identity_service/internal/models"
	"identity_service/internal/repository"
)

// ---- verification tokens ----

type verificationRepo struct{ s *Store }

func (r verificationRepo) Create(_ context.Context, token *models.VerificationToken) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return err
	}
	copied := *token
	r.s.verification = append(r.s.verification, &copied)
	return nil
}

func (r verificationRepo) ConsumePending(_ context.Context, userID string, at time.Time) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return err
	}
	for _, token := range r.s.verification {
		if token.UserID == userID && token.ConsumedAt == nil {
			consumed := at
			token.ConsumedAt = &consumed
		}
	}
	return nil
}

func (r verificationRepo) GetByHash(_ context.Context, tokenHash string) (*models.VerificationToken, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return nil, err
	}
	for _, token := range r.s.verification {
		if token.TokenHash == tokenHash {
			copied := *token
			return &copied, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (r verificationRepo) Consume(_ context.Context, id string, at time.Time) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return err
	}
	for _, token := range r.s.verification {
		if token.ID == id {
			if token.ConsumedAt != nil {
				return repository.ErrNotFound
			}
			consumed := at
			token.ConsumedAt = &consumed
			return nil
		}
	}
	return repository.ErrNotFound
}

// ---- password reset tokens ----

type resetRepo struct{ s *Store }

func (r resetRepo) Create(_ context.Context, token *models.PasswordResetToken) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return err
	}
	copied := *token
	r.s.resetTokens = append(r.s.resetTokens, &copied)
	return nil
}

func (r resetRepo) ConsumePending(_ context.Context, userID string, at time.Time) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return err
	}
	for _, token := range r.s.resetTokens {
		if token.UserID == userID && token.ConsumedAt == nil {
			consumed := at
			token.ConsumedAt = &consumed
		}
	}
	return nil
}

func (r resetRepo) GetByHash(_ context.Context, tokenHash string) (*models.PasswordResetToken, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return nil, err
	}
	for _, token := range r.s.resetTokens {
		if token.TokenHash == tokenHash {
			copied := *token
			return &copied, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (r resetRepo) Consume(_ context.Context, id string, at time.Time) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return err
	}
	for _, token := range r.s.resetTokens {
		if token.ID == id {
			if token.ConsumedAt != nil {
				return repository.ErrNotFound
			}
			consumed := at
			token.ConsumedAt = &consumed
			return nil
		}
	}
	return repository.ErrNotFound
}

var (
	_ repository.VerificationTokenRepository  = verificationRepo{}
	_ repository.PasswordResetTokenRepository = resetRepo{}
)
