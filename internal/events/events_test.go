package events_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"identity_service/internal/clock"
	"identity_service/internal/events"
	"identity_service/internal/models"
	"identity_service/internal/observability"
	"identity_service/tests/mocks"
)

var testTrace = observability.Trace{
	TraceID:       "0123456789abcdef0123456789abcdef",
	CorrelationID: "11111111-1111-4111-8111-111111111111",
}

func testUser() *models.User {
	return &models.User{
		ID:             "3f0f5a5e-6f0f-4b3f-9a5e-111111111111",
		Email:          "user@example.com",
		Username:       "user",
		DisplayName:    "User Name",
		EmailVerified:  true,
		Status:         models.UserStatusActive,
		AccountVersion: 7,
	}
}

func TestNewAccountChangedMessageIsContractComplete(t *testing.T) {
	t.Parallel()

	occurredAt := time.Date(2026, 2, 11, 12, 0, 5, 0, time.UTC)
	message, err := events.NewAccountChangedMessage(testUser(), models.AccountChangeEmailVerified,
		events.FlowFromTrace(testTrace), occurredAt)
	require.NoError(t, err)

	envelope := message.Envelope
	assert.True(t, models.IsUUID(envelope.EventID))
	assert.Equal(t, "user_account_changed", envelope.EventType)
	assert.Equal(t, 1, envelope.EventVersion)
	assert.Equal(t, "2026-02-11T12:00:05Z", envelope.OccurredAt)
	assert.Equal(t, "identity_service", envelope.Producer)
	assert.Equal(t, testTrace.TraceID, envelope.TraceID)
	assert.True(t, observability.IsTraceID(envelope.TraceID))
	assert.Equal(t, testTrace.CorrelationID, envelope.CorrelationID)
	assert.Nil(t, envelope.CausationID, "the first event of a flow has no causation")
	assert.Equal(t, "EVENT_CONTRACTS.md#user_account_changed-v1", envelope.SchemaRef)

	payload, ok := message.Payload.(events.UserAccountChangedPayload)
	require.True(t, ok)
	assert.Equal(t, "3f0f5a5e-6f0f-4b3f-9a5e-111111111111", payload.UserID)
	assert.Equal(t, models.AccountChangeEmailVerified, payload.Change)
	assert.Equal(t, "user@example.com", payload.Email)
	assert.Equal(t, "user", payload.Username)
	assert.Equal(t, "User Name", payload.DisplayName)
	assert.True(t, payload.EmailVerified)
	assert.Equal(t, models.UserStatusActive, payload.Status)
	assert.Equal(t, int64(7), payload.AccountVersion)
}

func TestNewAccountChangedMessageMintsTraceWhenAbsent(t *testing.T) {
	t.Parallel()

	message, err := events.NewAccountChangedMessage(testUser(), models.AccountChangeProfileUpdate, events.Flow{}, time.Now())
	require.NoError(t, err)
	assert.NotEmpty(t, message.Envelope.TraceID, "trace_id is never empty")
	assert.True(t, observability.IsTraceID(message.Envelope.TraceID))
	assert.True(t, models.IsUUID(message.Envelope.CorrelationID))
}

func TestNewFlowProducesFreshIdentifiers(t *testing.T) {
	t.Parallel()

	first := events.NewFlow()
	second := events.NewFlow()
	assert.True(t, observability.IsTraceID(first.TraceID))
	assert.True(t, models.IsUUID(first.CorrelationID))
	assert.NotEqual(t, first.TraceID, second.TraceID)
	assert.NotEqual(t, first.CorrelationID, second.CorrelationID)
}

func TestEnvelopeValidation(t *testing.T) {
	t.Parallel()

	valid, err := events.NewEnvelope(events.EventTypeUserAccountChanged, 1, events.SchemaRefUserAccountChangedV1,
		events.FlowFromTrace(testTrace), time.Now(), nil)
	require.NoError(t, err)
	require.NoError(t, valid.Validate())

	invalid := []struct {
		name   string
		mutate func(*events.Envelope)
	}{
		{"event_id", func(e *events.Envelope) { e.EventID = "nope" }},
		{"event_type", func(e *events.Envelope) { e.EventType = "" }},
		{"event_version", func(e *events.Envelope) { e.EventVersion = 0 }},
		{"occurred_at empty", func(e *events.Envelope) { e.OccurredAt = "" }},
		{"occurred_at format", func(e *events.Envelope) { e.OccurredAt = "yesterday" }},
		{"producer", func(e *events.Envelope) { e.Producer = "other_service" }},
		{"trace_id", func(e *events.Envelope) { e.TraceID = "" }},
		{"trace_id format", func(e *events.Envelope) { e.TraceID = "not-hex" }},
		{"correlation_id", func(e *events.Envelope) { e.CorrelationID = "1" }},
		{"causation_id", func(e *events.Envelope) { bad := "x"; e.CausationID = &bad }},
		{"schema_ref", func(e *events.Envelope) { e.SchemaRef = "" }},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			candidate := valid
			tc.mutate(&candidate)
			err := candidate.Validate()
			require.Error(t, err)
			assert.ErrorIs(t, err, events.ErrInvalidEnvelope)
		})
	}

	// A valid causation id is accepted.
	causation := "22222222-2222-4222-8222-222222222222"
	withCause, err := events.NewEnvelope(events.EventTypeUserAccountChanged, 1, events.SchemaRefUserAccountChangedV1,
		events.FlowFromTrace(testTrace), time.Now(), &causation)
	require.NoError(t, err)
	require.NotNil(t, withCause.CausationID)
	assert.Equal(t, causation, *withCause.CausationID)
}

func TestWireFormatHasExactlyEnvelopeAndPayload(t *testing.T) {
	t.Parallel()

	message, err := events.NewAccountChangedMessage(testUser(), models.AccountChangeEmailVerified,
		events.FlowFromTrace(testTrace), time.Now())
	require.NoError(t, err)
	envelope, err := events.MarshalEnvelope(message.Envelope)
	require.NoError(t, err)
	payload, err := events.MarshalPayload(message.Payload)
	require.NoError(t, err)

	wire, err := events.MarshalForWire(envelope, payload)
	require.NoError(t, err)

	var decoded map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(wire, &decoded))
	require.Len(t, decoded, 2)
	assert.Contains(t, decoded, "envelope")
	assert.Contains(t, decoded, "payload")

	var payloadFields map[string]any
	require.NoError(t, json.Unmarshal(decoded["payload"], &payloadFields))
	assert.Len(t, payloadFields, 8)
	assert.NotContains(t, payloadFields, "event_id")
	assert.NotContains(t, payloadFields, "trace_id")

	_, err = events.MarshalForWire(nil, payload)
	require.Error(t, err)
}

func TestHeadersMirrorEnvelopeFields(t *testing.T) {
	t.Parallel()

	message, err := events.NewAccountChangedMessage(testUser(), models.AccountChangeDeactivated,
		events.FlowFromTrace(testTrace), time.Now())
	require.NoError(t, err)
	envelope, err := events.MarshalEnvelope(message.Envelope)
	require.NoError(t, err)

	headers, err := events.HeadersFromEnvelope(envelope)
	require.NoError(t, err)
	assert.Equal(t, testTrace.TraceID, headers[events.HeaderTraceID])
	assert.Equal(t, events.EventTypeUserAccountChanged, headers[events.HeaderEventType])

	_, err = events.HeadersFromEnvelope(json.RawMessage("{not-json"))
	require.Error(t, err)
}

func outboxRecord(t *testing.T, change models.AccountChange) models.OutboxRecord {
	t.Helper()
	message, err := events.NewAccountChangedMessage(testUser(), change, events.FlowFromTrace(testTrace), time.Now())
	require.NoError(t, err)
	envelope, err := events.MarshalEnvelope(message.Envelope)
	require.NoError(t, err)
	payload, err := events.MarshalPayload(message.Payload)
	require.NoError(t, err)
	return models.OutboxRecord{
		ID:        "44444444-4444-4444-8444-444444444444",
		Topic:     "identity_events",
		Key:       testUser().ID,
		Envelope:  envelope,
		Payload:   payload,
		CreatedAt: time.Now(),
	}
}

func TestDispatcherPublishesCommittedEvents(t *testing.T) {
	t.Parallel()

	outbox := new(mocks.OutboxRepository)
	publisher := new(mocks.Publisher)
	record := outboxRecord(t, models.AccountChangeEmailVerified)

	outbox.On("Unpublished", mock.Anything, 10).Return([]models.OutboxRecord{record}, nil).Once()
	publisher.On("Publish", mock.Anything, mock.MatchedBy(func(msg events.OutboundMessage) bool {
		return msg.Topic == "identity_events" &&
			msg.Key == testUser().ID &&
			msg.Headers[events.HeaderTraceID] == testTrace.TraceID &&
			msg.Headers[events.HeaderEventType] == events.EventTypeUserAccountChanged &&
			len(msg.Value) > 0
	})).Return(nil).Once()
	outbox.On("MarkPublished", mock.Anything, record.ID, mock.Anything).Return(nil).Once()

	dispatcher := events.NewDispatcher(outbox, publisher, clock.NewFixed(time.Now()), nil, time.Millisecond, 10)
	published, err := dispatcher.DispatchOnce(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, published)

	outbox.AssertExpectations(t)
	publisher.AssertExpectations(t)
}

func TestDispatcherStopsOnPublishFailure(t *testing.T) {
	t.Parallel()

	outbox := new(mocks.OutboxRepository)
	publisher := new(mocks.Publisher)
	record := outboxRecord(t, models.AccountChangeEmailVerified)

	outbox.On("Unpublished", mock.Anything, 10).Return([]models.OutboxRecord{record}, nil).Once()
	publisher.On("Publish", mock.Anything, mock.Anything).Return(errors.New("broker down")).Once()

	dispatcher := events.NewDispatcher(outbox, publisher, clock.NewFixed(time.Now()), nil, time.Millisecond, 10)
	published, err := dispatcher.DispatchOnce(context.Background())
	require.Error(t, err)
	assert.Equal(t, 0, published)
	outbox.AssertNotCalled(t, "MarkPublished", mock.Anything, mock.Anything, mock.Anything)
}

func TestDispatcherReportsRepositoryFailures(t *testing.T) {
	t.Parallel()

	outbox := new(mocks.OutboxRepository)
	publisher := new(mocks.Publisher)
	outbox.On("Unpublished", mock.Anything, 5).Return(nil, errors.New("db down")).Once()

	dispatcher := events.NewDispatcher(outbox, publisher, clock.NewFixed(time.Now()), nil, time.Millisecond, 5)
	_, err := dispatcher.DispatchOnce(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db down")
}

func TestDispatcherFlushDrainsEveryBatch(t *testing.T) {
	t.Parallel()

	outbox := new(mocks.OutboxRepository)
	publisher := new(mocks.Publisher)
	first := outboxRecord(t, models.AccountChangeEmailVerified)
	second := outboxRecord(t, models.AccountChangeProfileUpdate)
	second.ID = "55555555-5555-4555-8555-555555555555"

	outbox.On("Unpublished", mock.Anything, 2).Return([]models.OutboxRecord{first, second}, nil).Once()
	outbox.On("Unpublished", mock.Anything, 2).Return([]models.OutboxRecord{}, nil).Once()
	publisher.On("Publish", mock.Anything, mock.Anything).Return(nil).Twice()
	outbox.On("MarkPublished", mock.Anything, mock.Anything, mock.Anything).Return(nil).Twice()

	dispatcher := events.NewDispatcher(outbox, publisher, clock.NewFixed(time.Now()), nil, time.Millisecond, 2)
	require.NoError(t, dispatcher.Flush(context.Background()))
	outbox.AssertExpectations(t)
	publisher.AssertNumberOfCalls(t, "Publish", 2)
}

func TestDispatcherFlushHonoursCancelledContext(t *testing.T) {
	t.Parallel()

	dispatcher := events.NewDispatcher(new(mocks.OutboxRepository), new(mocks.Publisher),
		clock.NewFixed(time.Now()), nil, time.Millisecond, 10)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.Error(t, dispatcher.Flush(ctx))
}

func TestDispatcherRunStopsOnCancellation(t *testing.T) {
	t.Parallel()

	outbox := new(mocks.OutboxRepository)
	publisher := new(mocks.Publisher)
	outbox.On("Unpublished", mock.Anything, mock.Anything).Return([]models.OutboxRecord{}, nil)

	dispatcher := events.NewDispatcher(outbox, publisher, clock.NewFixed(time.Now()), nil, time.Millisecond, 10)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		dispatcher.Run(ctx)
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("dispatcher did not stop after cancellation")
	}
}
