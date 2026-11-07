// Package clock provides the injectable time source used for token expiry,
// lockout windows and throttling so behaviour is deterministic in tests.
package clock

import (
	"sync"
	"time"
)

// Clock reports the current time.
type Clock interface {
	// Now returns the current time in UTC.
	Now() time.Time
}

// System is the production clock backed by time.Now.
type System struct{}

// Now implements Clock.
func (System) Now() time.Time { return time.Now().UTC() }

// Fixed is a controllable clock for tests.
type Fixed struct {
	mu  sync.RWMutex
	now time.Time
}

// NewFixed returns a clock frozen at t.
func NewFixed(t time.Time) *Fixed {
	return &Fixed{now: t.UTC()}
}

// Now implements Clock.
func (f *Fixed) Now() time.Time {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.now
}

// Advance moves the frozen clock forward by d.
func (f *Fixed) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

// Set moves the frozen clock to t.
func (f *Fixed) Set(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = t.UTC()
}
