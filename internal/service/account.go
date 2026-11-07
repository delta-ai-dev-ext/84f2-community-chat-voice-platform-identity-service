package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"identity_service/internal/models"
	"identity_service/internal/repository"
)

// Profile returns the caller's own profile.
func (s *Service) Profile(ctx context.Context, userID string) (*models.OwnProfile, error) {
	if !models.IsUUID(userID) {
		return nil, models.NewError(models.CodeUnauthorized, "Sign in to continue.")
	}
	user, err := s.repos.Users.GetByID(ctx, userID)
	switch {
	case errors.Is(err, repository.ErrNotFound):
		return nil, models.NewError(models.CodeUnauthorized, "Sign in to continue.")
	case err != nil:
		return nil, fmt.Errorf("service: load account: %w", err)
	}
	profile := user.OwnProfile()
	return &profile, nil
}

// UpdateDisplayName changes the caller's display name, bumps account_version and
// publishes the EVT-001 profile_updated snapshot in the same transaction.
func (s *Service) UpdateDisplayName(ctx context.Context, userID, displayName string) (*models.OwnProfile, error) {
	if !models.IsUUID(userID) {
		return nil, models.NewError(models.CodeUnauthorized, "Sign in to continue.")
	}
	validated, err := validateDisplayName(displayName)
	if err != nil {
		return nil, err
	}

	var updated *models.User
	err = s.repos.Transactor.WithTx(ctx, func(ctx context.Context) error {
		user, err := s.repos.Users.UpdateDisplayName(ctx, userID, validated)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				return models.NewError(models.CodeUnauthorized, "Sign in to continue.")
			}
			return fmt.Errorf("service: update display name: %w", err)
		}
		if err := s.enqueueAccountChanged(ctx, user, models.AccountChangeProfileUpdate); err != nil {
			return err
		}
		updated = user
		return nil
	})
	if err != nil {
		return nil, err
	}
	profile := updated.OwnProfile()
	return &profile, nil
}

// LookupByUsername resolves a username to a public profile. Malformed usernames
// are reported as not found so the endpoint cannot be probed for format rules.
func (s *Service) LookupByUsername(ctx context.Context, username string) (*models.PublicProfile, error) {
	notFound := models.NewError(models.CodeUserNotFound, "No user with that username.")
	normalized := models.NormalizeUsername(username)
	if len(normalized) < MinUsernameLength || len(normalized) > MaxUsernameLength || !UsernamePattern.MatchString(normalized) {
		return nil, notFound
	}
	user, err := s.repos.Users.GetByUsername(ctx, normalized)
	switch {
	case errors.Is(err, repository.ErrNotFound):
		return nil, notFound
	case err != nil:
		return nil, fmt.Errorf("service: load account by username: %w", err)
	}
	profile := user.PublicProfile()
	return &profile, nil
}

// PublicProfiles resolves a batch of user ids to public profiles. Duplicate ids
// are ignored, unknown ids are omitted and more than 100 ids is a validation
// error.
func (s *Service) PublicProfiles(ctx context.Context, ids []string) (*models.PublicProfileList, error) {
	result := &models.PublicProfileList{Data: []models.PublicProfile{}}
	if len(ids) == 0 {
		return result, nil
	}
	if len(ids) > MaxBatchLookupIDs {
		return nil, models.ValidationErrorf("ids must contain at most %d user ids.", MaxBatchLookupIDs)
	}

	seen := make(map[string]struct{}, len(ids))
	unique := make([]string, 0, len(ids))
	for _, raw := range ids {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		if !models.IsUUID(id) {
			return nil, models.ValidationErrorf("ids must be a comma-separated list of user ids.")
		}
		normalized := strings.ToLower(id)
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		unique = append(unique, normalized)
	}
	if len(unique) > MaxBatchLookupIDs {
		return nil, models.ValidationErrorf("ids must contain at most %d user ids.", MaxBatchLookupIDs)
	}

	users, err := s.repos.Users.GetByIDs(ctx, unique)
	if err != nil {
		return nil, fmt.Errorf("service: load accounts: %w", err)
	}
	byID := make(map[string]models.User, len(users))
	for _, user := range users {
		byID[strings.ToLower(user.ID)] = user
	}
	for _, id := range unique {
		if user, ok := byID[id]; ok {
			result.Data = append(result.Data, user.PublicProfile())
		}
	}
	return result, nil
}
