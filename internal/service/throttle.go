package service

import (
	"context"
	"fmt"
	"time"

	"identity_service/internal/clock"
	"identity_service/internal/models"
	"identity_service/internal/repository"
)

// Throttle implements the DB-backed, replica-safe sign-in protection policy:
// failures are counted per account and per source address inside a rolling
// window, and exceeding either threshold locks the account or source for the
// configured lockout duration.
type Throttle struct {
	attempts          repository.LoginAttemptRepository
	clock             clock.Clock
	maxFailures       int
	sourceMaxFailures int
	window            time.Duration
	lockout           time.Duration
}

// NewThrottle builds the sign-in throttle policy.
func NewThrottle(attempts repository.LoginAttemptRepository, clk clock.Clock, maxFailures, sourceMaxFailures int, window, lockout time.Duration) *Throttle {
	return &Throttle{
		attempts:          attempts,
		clock:             clk,
		maxFailures:       maxFailures,
		sourceMaxFailures: sourceMaxFailures,
		window:            window,
		lockout:           lockout,
	}
}

// Decision reports whether sign-in is currently locked and for how long.
type Decision struct {
	// Locked is true when the caller must be rejected with 429.
	Locked bool
	// RetryAfter is the remaining lockout duration.
	RetryAfter time.Duration
	// Reason is "account" or "source" (for logs only, never for responses).
	Reason string
}

// Check evaluates the throttle state for an account/source pair.
func (t *Throttle) Check(ctx context.Context, accountKey, sourceKey string) (Decision, error) {
	now := t.clock.Now()
	state, err := t.attempts.StateSince(ctx, accountKey, sourceKey, now.Add(-t.window))
	if err != nil {
		return Decision{}, fmt.Errorf("service: load throttle state: %w", err)
	}
	if state == nil {
		return Decision{}, nil
	}
	if state.AccountFailures >= t.maxFailures {
		if until := state.AccountLastFailureAt.Add(t.lockout); now.Before(until) {
			return Decision{Locked: true, RetryAfter: until.Sub(now), Reason: "account"}, nil
		}
	}
	if state.SourceFailures >= t.sourceMaxFailures {
		if until := state.SourceLastFailureAt.Add(t.lockout); now.Before(until) {
			return Decision{Locked: true, RetryAfter: until.Sub(now), Reason: "source"}, nil
		}
	}
	return Decision{}, nil
}

// Record appends an attempt to the ledger.
func (t *Throttle) Record(ctx context.Context, accountKey, sourceKey string, outcome models.LoginOutcome) error {
	attempt := &models.LoginAttempt{
		AccountKey:  accountKey,
		SourceKey:   sourceKey,
		Outcome:     outcome,
		AttemptedAt: t.clock.Now(),
	}
	if err := t.attempts.Record(ctx, attempt); err != nil {
		return fmt.Errorf("service: record login attempt: %w", err)
	}
	return nil
}

// Reset clears the account's failure window after a successful sign-in.
func (t *Throttle) Reset(ctx context.Context, accountKey string) error {
	if err := t.attempts.ResetAccount(ctx, accountKey); err != nil {
		return fmt.Errorf("service: reset login attempts: %w", err)
	}
	return nil
}

// UnknownAccountKey is recorded for attempts against accounts that do not
// exist, so the ledger never stores an unregistered email address in the
// account column.
const UnknownAccountKey = "_"
