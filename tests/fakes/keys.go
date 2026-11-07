package fakes

import (
	"context"
	"sort"
	"time"

	"identity_service/internal/models"
	"identity_service/internal/repository"
)

// ---- login attempts ----

type attemptRepo struct{ s *Store }

func (r attemptRepo) Record(_ context.Context, attempt *models.LoginAttempt) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return err
	}
	r.s.attempts = append(r.s.attempts, *attempt)
	return nil
}

func (r attemptRepo) StateSince(_ context.Context, accountKey, sourceKey string, since time.Time) (*models.ThrottleState, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return nil, err
	}
	state := &models.ThrottleState{}
	for _, attempt := range r.s.attempts {
		if attempt.Outcome != models.LoginOutcomeFailure || attempt.AttemptedAt.Before(since) {
			continue
		}
		if attempt.AccountKey == accountKey {
			state.AccountFailures++
			if attempt.AttemptedAt.After(state.AccountLastFailureAt) {
				state.AccountLastFailureAt = attempt.AttemptedAt
			}
		}
		if attempt.SourceKey == sourceKey {
			state.SourceFailures++
			if attempt.AttemptedAt.After(state.SourceLastFailureAt) {
				state.SourceLastFailureAt = attempt.AttemptedAt
			}
		}
	}
	return state, nil
}

func (r attemptRepo) ResetAccount(_ context.Context, accountKey string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return err
	}
	kept := make([]models.LoginAttempt, 0, len(r.s.attempts))
	for _, attempt := range r.s.attempts {
		if attempt.AccountKey == accountKey && attempt.Outcome == models.LoginOutcomeFailure {
			continue
		}
		kept = append(kept, attempt)
	}
	r.s.attempts = kept
	return nil
}

// ---- signing keys ----

type keyRepo struct{ s *Store }

func (r keyRepo) Create(_ context.Context, key *models.SigningKey) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return err
	}
	if key.Status != models.SigningKeyRetired {
		for _, existing := range r.s.keys {
			if existing.Status == key.Status {
				return repository.ErrIDConflict
			}
		}
	}
	copied := *key
	r.s.keys[key.Kid] = &copied
	return nil
}

func (r keyRepo) GetByStatus(_ context.Context, status models.SigningKeyStatus) (*models.SigningKey, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return nil, err
	}
	var newest *models.SigningKey
	for _, key := range r.s.keys {
		if key.Status != status {
			continue
		}
		if newest == nil || key.CreatedAt.After(newest.CreatedAt) {
			newest = key
		}
	}
	if newest == nil {
		return nil, repository.ErrNotFound
	}
	copied := *newest
	return &copied, nil
}

func (r keyRepo) ListPublished(_ context.Context, retiredCutoff time.Time) ([]models.SigningKey, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return nil, err
	}
	var keys []models.SigningKey
	for _, key := range r.s.keys {
		switch key.Status {
		case models.SigningKeyCurrent, models.SigningKeyNext:
			keys = append(keys, *key)
		case models.SigningKeyRetired:
			if key.RetiredAt != nil && !key.RetiredAt.Before(retiredCutoff) {
				keys = append(keys, *key)
			}
		}
	}
	rank := func(status models.SigningKeyStatus) int {
		switch status {
		case models.SigningKeyCurrent:
			return 0
		case models.SigningKeyNext:
			return 1
		default:
			return 2
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if rank(keys[i].Status) == rank(keys[j].Status) {
			return keys[i].CreatedAt.After(keys[j].CreatedAt)
		}
		return rank(keys[i].Status) < rank(keys[j].Status)
	})
	return keys, nil
}

func (r keyRepo) SetStatus(_ context.Context, kid string, status models.SigningKeyStatus, retiredAt *time.Time) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return err
	}
	key, ok := r.s.keys[kid]
	if !ok {
		return repository.ErrNotFound
	}
	key.Status = status
	key.RetiredAt = retiredAt
	return nil
}

func (r keyRepo) DeleteRetiredBefore(_ context.Context, cutoff time.Time) (int64, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return 0, err
	}
	var deleted int64
	for kid, key := range r.s.keys {
		if key.Status == models.SigningKeyRetired && key.RetiredAt != nil && key.RetiredAt.Before(cutoff) {
			delete(r.s.keys, kid)
			deleted++
		}
	}
	return deleted, nil
}

// ---- outbox ----

type outboxRepo struct{ s *Store }

func (r outboxRepo) Insert(_ context.Context, record *models.OutboxRecord) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return err
	}
	copied := *record
	r.s.outbox = append(r.s.outbox, &copied)
	return nil
}

func (r outboxRepo) Unpublished(_ context.Context, limit int) ([]models.OutboxRecord, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return nil, err
	}
	out := make([]models.OutboxRecord, 0, len(r.s.outbox))
	for _, record := range r.s.outbox {
		if record.PublishedAt != nil {
			continue
		}
		out = append(out, *record)
		if limit > 0 && len(out) == limit {
			break
		}
	}
	return out, nil
}

func (r outboxRepo) MarkPublished(_ context.Context, id string, at time.Time) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.fail(); err != nil {
		return err
	}
	for _, record := range r.s.outbox {
		if record.ID == id {
			published := at
			record.PublishedAt = &published
			return nil
		}
	}
	return repository.ErrNotFound
}

var (
	_ repository.LoginAttemptRepository = attemptRepo{}
	_ repository.SigningKeyRepository   = keyRepo{}
	_ repository.OutboxRepository       = outboxRepo{}
	_ repository.Transactor             = (*Store)(nil)
)
