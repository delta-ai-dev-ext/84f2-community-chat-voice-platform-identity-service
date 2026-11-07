package service

import (
	"context"
	"errors"
	"fmt"

	"identity_service/internal/models"
	"identity_service/internal/repository"
)

// DefaultSessionPageSize is the page size used when the caller omits limit.
const DefaultSessionPageSize = 50

// MaxSessionPageSize is the largest accepted page size.
const MaxSessionPageSize = 100

// ListSessions returns a page of the caller's active sessions, newest first,
// using an opaque keyset cursor.
func (s *Service) ListSessions(ctx context.Context, userID, currentSessionID, cursor string, limit int) (*models.SessionList, error) {
	if !models.IsUUID(userID) {
		return nil, models.NewError(models.CodeUnauthorized, "Sign in to continue.")
	}
	if limit == 0 {
		limit = DefaultSessionPageSize
	}
	if limit < 1 || limit > MaxSessionPageSize {
		return nil, models.ValidationErrorf("limit must be between 1 and %d.", MaxSessionPageSize)
	}

	var page *repository.PageCursor
	if cursor != "" {
		decoded, err := repository.DecodeCursor(cursor)
		if err != nil {
			return nil, models.ValidationErrorf("cursor is not valid.")
		}
		page = decoded
	}

	sessions, err := s.repos.Sessions.ListActiveByUser(ctx, userID, page, limit+1)
	if err != nil {
		return nil, fmt.Errorf("service: list sessions: %w", err)
	}

	list := &models.SessionList{Data: make([]models.SessionItem, 0, len(sessions))}
	var nextCursor *string
	if len(sessions) > limit {
		sessions = sessions[:limit]
		encoded := repository.EncodeCursor(repository.PageCursor{
			CreatedAt: sessions[len(sessions)-1].CreatedAt,
			ID:        sessions[len(sessions)-1].ID,
		})
		nextCursor = &encoded
	}
	for _, session := range sessions {
		list.Data = append(list.Data, models.SessionItem{
			SessionID:   session.ID,
			DeviceLabel: session.DeviceLabel,
			CreatedAt:   session.CreatedAt,
			LastSeenAt:  session.LastSeenAt,
			IsCurrent:   session.ID == currentSessionID,
		})
	}
	list.NextCursor = nextCursor
	return list, nil
}

// RevokeSession ends one of the caller's sessions together with its refresh
// family. A session that is unknown, not owned by the caller or already revoked
// is reported as session_not_found.
func (s *Service) RevokeSession(ctx context.Context, userID, sessionID string) error {
	notFound := models.NewError(models.CodeSessionNotFound, "No such active session.")
	if !models.IsUUID(userID) {
		return models.NewError(models.CodeUnauthorized, "Sign in to continue.")
	}
	if !models.IsUUID(sessionID) {
		return notFound
	}

	now := s.clock.Now()
	return s.repos.Transactor.WithTx(ctx, func(ctx context.Context) error {
		session, err := s.repos.Sessions.GetByID(ctx, sessionID)
		switch {
		case errors.Is(err, repository.ErrNotFound):
			return notFound
		case err != nil:
			return fmt.Errorf("service: load session: %w", err)
		}
		if session.UserID != userID || !session.Active() {
			return notFound
		}
		if err := s.repos.Sessions.Revoke(ctx, session.ID, now); err != nil {
			return fmt.Errorf("service: revoke session: %w", err)
		}
		if err := s.repos.RefreshTokens.RevokeBySession(ctx, session.ID); err != nil {
			return fmt.Errorf("service: revoke refresh tokens: %w", err)
		}
		return nil
	})
}
