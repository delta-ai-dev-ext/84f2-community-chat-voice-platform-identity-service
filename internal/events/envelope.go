// Package events builds the mandatory event envelope and publishes messages to
// Kafka through a transactional outbox.
package events

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"identity_service/internal/models"
	"identity_service/internal/observability"
)

// Event contract constants (docs/architecture.md "Inter-Service Contracts").
const (
	// Producer is the registered producer name.
	Producer = "identity_service"
	// EventTypeUserAccountChanged is EVT-001.
	EventTypeUserAccountChanged = "user_account_changed"
	// EventVersionUserAccountChanged is the EVT-001 major version.
	EventVersionUserAccountChanged = 1
	// SchemaRefUserAccountChangedV1 points at the published payload schema.
	SchemaRefUserAccountChangedV1 = "EVENT_CONTRACTS.md#user_account_changed-v1"

	// HeaderTraceID is the Kafka header mirroring envelope.trace_id.
	HeaderTraceID = "trace_id"
	// HeaderEventType is the Kafka header mirroring envelope.event_type.
	HeaderEventType = "event_type"
)

// Envelope is the single reusable message envelope used for every event
// published by this service.
type Envelope struct {
	EventID       string  `json:"event_id"`
	EventType     string  `json:"event_type"`
	EventVersion  int     `json:"event_version"`
	OccurredAt    string  `json:"occurred_at"`
	Producer      string  `json:"producer"`
	TraceID       string  `json:"trace_id"`
	CorrelationID string  `json:"correlation_id"`
	CausationID   *string `json:"causation_id"`
	SchemaRef     string  `json:"schema_ref"`
}

// Message is the wire format: exactly two top-level keys, envelope and payload.
type Message struct {
	Envelope Envelope `json:"envelope"`
	Payload  any      `json:"payload"`
}

// UserAccountChangedPayload is the EVT-001 v1 payload. It never carries an
// envelope field.
type UserAccountChangedPayload struct {
	UserID         string               `json:"user_id"`
	Change         models.AccountChange `json:"change"`
	Email          string               `json:"email"`
	Username       string               `json:"username"`
	DisplayName    string               `json:"display_name"`
	EmailVerified  bool                 `json:"email_verified"`
	Status         models.UserStatus    `json:"status"`
	AccountVersion int64                `json:"account_version"`
}

// Flow identifies the business flow an event belongs to.
type Flow struct {
	// TraceID is the 32 lowercase hex trace id of the originating request.
	TraceID string
	// CorrelationID groups every event of one business flow.
	CorrelationID string
}

// FlowFromTrace adapts an observability trace into an event flow.
func FlowFromTrace(trace observability.Trace) Flow {
	return Flow{TraceID: trace.TraceID, CorrelationID: trace.CorrelationID}
}

// NewFlow returns a flow with a fresh trace and correlation id, used by
// background work with no originating request.
func NewFlow() Flow {
	return Flow{TraceID: observability.NewTraceID(), CorrelationID: observability.NewCorrelationID()}
}

// NewEnvelope builds an envelope for eventType at occurredAt. A fresh event_id
// is minted; causationID is nil for the first event of a flow.
func NewEnvelope(eventType string, version int, schemaRef string, flow Flow, occurredAt time.Time, causationID *string) (Envelope, error) {
	eventID, err := models.NewUUID()
	if err != nil {
		return Envelope{}, err
	}
	envelope := Envelope{
		EventID:       eventID,
		EventType:     eventType,
		EventVersion:  version,
		OccurredAt:    occurredAt.UTC().Format(time.RFC3339),
		Producer:      Producer,
		TraceID:       flow.TraceID,
		CorrelationID: flow.CorrelationID,
		CausationID:   causationID,
		SchemaRef:     schemaRef,
	}
	if envelope.TraceID == "" {
		envelope.TraceID = observability.NewTraceID()
	}
	if envelope.CorrelationID == "" {
		envelope.CorrelationID = observability.NewCorrelationID()
	}
	if err := envelope.Validate(); err != nil {
		return Envelope{}, err
	}
	return envelope, nil
}

// ErrInvalidEnvelope is returned when an envelope violates the mandatory
// contract.
var ErrInvalidEnvelope = errors.New("events: invalid envelope")

// Validate checks the mandatory envelope rules.
func (e Envelope) Validate() error {
	switch {
	case !models.IsUUID(e.EventID):
		return fmt.Errorf("%w: event_id must be a uuid", ErrInvalidEnvelope)
	case e.EventType == "":
		return fmt.Errorf("%w: event_type is required", ErrInvalidEnvelope)
	case e.EventVersion < 1:
		return fmt.Errorf("%w: event_version must be >= 1", ErrInvalidEnvelope)
	case e.OccurredAt == "":
		return fmt.Errorf("%w: occurred_at is required", ErrInvalidEnvelope)
	case e.Producer != Producer:
		return fmt.Errorf("%w: producer must be %q", ErrInvalidEnvelope, Producer)
	case !observability.IsTraceID(e.TraceID):
		return fmt.Errorf("%w: trace_id must be 32 lowercase hex characters", ErrInvalidEnvelope)
	case !models.IsUUID(e.CorrelationID):
		return fmt.Errorf("%w: correlation_id must be a uuid", ErrInvalidEnvelope)
	case e.SchemaRef == "":
		return fmt.Errorf("%w: schema_ref is required", ErrInvalidEnvelope)
	}
	if e.CausationID != nil && !models.IsUUID(*e.CausationID) {
		return fmt.Errorf("%w: causation_id must be a uuid when present", ErrInvalidEnvelope)
	}
	if _, err := time.Parse(time.RFC3339, e.OccurredAt); err != nil {
		return fmt.Errorf("%w: occurred_at must be RFC3339", ErrInvalidEnvelope)
	}
	return nil
}

// NewAccountChangedMessage builds the EVT-001 message for an account change.
func NewAccountChangedMessage(user *models.User, change models.AccountChange, flow Flow, occurredAt time.Time) (Message, error) {
	envelope, err := NewEnvelope(EventTypeUserAccountChanged, EventVersionUserAccountChanged,
		SchemaRefUserAccountChangedV1, flow, occurredAt, nil)
	if err != nil {
		return Message{}, err
	}
	return Message{
		Envelope: envelope,
		Payload: UserAccountChangedPayload{
			UserID:         user.ID,
			Change:         change,
			Email:          user.Email,
			Username:       user.Username,
			DisplayName:    user.DisplayName,
			EmailVerified:  user.EmailVerified,
			Status:         user.Status,
			AccountVersion: user.AccountVersion,
		},
	}, nil
}

// MarshalEnvelope serialises an envelope for storage in the outbox.
func MarshalEnvelope(envelope Envelope) (json.RawMessage, error) {
	raw, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("events: marshal envelope: %w", err)
	}
	return raw, nil
}

// MarshalPayload serialises a payload for storage in the outbox.
func MarshalPayload(payload any) (json.RawMessage, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("events: marshal payload: %w", err)
	}
	return raw, nil
}

// MarshalForWire assembles the stored envelope and payload into the
// `{"envelope": ..., "payload": ...}` message body.
func MarshalForWire(envelope, payload json.RawMessage) ([]byte, error) {
	if len(envelope) == 0 || len(payload) == 0 {
		return nil, fmt.Errorf("%w: envelope and payload are required", ErrInvalidEnvelope)
	}
	out := make([]byte, 0, len(envelope)+len(payload)+24)
	out = append(out, `{"envelope":`...)
	out = append(out, envelope...)
	out = append(out, `,"payload":`...)
	out = append(out, payload...)
	out = append(out, '}')
	return out, nil
}

// HeadersFromEnvelope extracts the Kafka headers mirrored from the envelope.
func HeadersFromEnvelope(envelope json.RawMessage) (map[string]string, error) {
	var parsed struct {
		EventType string `json:"event_type"`
		TraceID   string `json:"trace_id"`
	}
	if err := json.Unmarshal(envelope, &parsed); err != nil {
		return nil, fmt.Errorf("events: decode envelope: %w", err)
	}
	return map[string]string{
		HeaderTraceID:   parsed.TraceID,
		HeaderEventType: parsed.EventType,
	}, nil
}
