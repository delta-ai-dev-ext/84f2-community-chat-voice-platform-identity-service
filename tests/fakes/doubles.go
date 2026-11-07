package fakes

import (
	"context"
	"sync"

	"identity_service/internal/email"
	"identity_service/internal/events"
)

// RecordingPublisher is an events.Publisher that records published messages.
type RecordingPublisher struct {
	mu       sync.Mutex
	messages []events.OutboundMessage
	failNext error
	down     bool
	flushed  bool
	closed   bool
}

// NewRecordingPublisher returns an empty recording publisher.
func NewRecordingPublisher() *RecordingPublisher { return &RecordingPublisher{} }

// Publish implements events.Publisher.
func (p *RecordingPublisher) Publish(_ context.Context, msg events.OutboundMessage) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failNext != nil {
		err := p.failNext
		p.failNext = nil
		return err
	}
	p.messages = append(p.messages, msg)
	return nil
}

// Connected implements events.Publisher.
func (p *RecordingPublisher) Connected() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.down && !p.closed
}

// Flush implements events.Publisher.
func (p *RecordingPublisher) Flush(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.flushed = true
	return nil
}

// Close implements events.Publisher.
func (p *RecordingPublisher) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return nil
}

// Messages returns every published message.
func (p *RecordingPublisher) Messages() []events.OutboundMessage {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]events.OutboundMessage, len(p.messages))
	copy(out, p.messages)
	return out
}

// SetDown marks the publisher unavailable (readiness tests).
func (p *RecordingPublisher) SetDown(down bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.down = down
}

// Flushed reports whether Flush was called.
func (p *RecordingPublisher) Flushed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.flushed
}

// FailNext makes the next Publish fail.
func (p *RecordingPublisher) FailNext(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failNext = err
}

// FakeNotifier is an email.Notifier that records messages and can fail.
type FakeNotifier struct {
	mu           sync.Mutex
	Verification []email.VerificationMessage
	Resets       []email.PasswordResetMessage
	Changed      []email.PasswordChangedMessage
	FailWith     error
}

// SendVerification implements email.Notifier.
func (n *FakeNotifier) SendVerification(_ context.Context, msg email.VerificationMessage) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.FailWith != nil {
		return n.FailWith
	}
	n.Verification = append(n.Verification, msg)
	return nil
}

// SendPasswordReset implements email.Notifier.
func (n *FakeNotifier) SendPasswordReset(_ context.Context, msg email.PasswordResetMessage) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.FailWith != nil {
		return n.FailWith
	}
	n.Resets = append(n.Resets, msg)
	return nil
}

// SendPasswordChanged implements email.Notifier.
func (n *FakeNotifier) SendPasswordChanged(_ context.Context, msg email.PasswordChangedMessage) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.FailWith != nil {
		return n.FailWith
	}
	n.Changed = append(n.Changed, msg)
	return nil
}

// SetFailure toggles the notifier failure mode.
func (n *FakeNotifier) SetFailure(err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.FailWith = err
}

// VerificationCount returns how many verification emails were recorded.
func (n *FakeNotifier) VerificationCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.Verification)
}

// ResetCount returns how many reset emails were recorded.
func (n *FakeNotifier) ResetCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.Resets)
}

// ChangedCount returns how many password-changed emails were recorded.
func (n *FakeNotifier) ChangedCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.Changed)
}

var (
	_ events.Publisher = (*RecordingPublisher)(nil)
	_ email.Notifier   = (*FakeNotifier)(nil)
)
