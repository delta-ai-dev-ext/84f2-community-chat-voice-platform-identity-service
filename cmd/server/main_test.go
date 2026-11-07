package main

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"identity_service/internal/clock"
	"identity_service/internal/events"
	"identity_service/internal/models"
)

// connectedPublisher is a minimal events.Publisher that is always reachable.
type connectedPublisher struct{}

func (connectedPublisher) Publish(context.Context, events.OutboundMessage) error { return nil }
func (connectedPublisher) Connected() bool                                       { return true }
func (connectedPublisher) Flush(context.Context) error                           { return nil }
func (connectedPublisher) Close() error                                          { return nil }

// failingFlushPublisher fails while flushing the producer.
type failingFlushPublisher struct{ connectedPublisher }

func (failingFlushPublisher) Flush(context.Context) error { return errors.New("kafka flush failed") }

// stepRecorder records the order in which shutdown releases components.
type stepRecorder struct {
	mu    sync.Mutex
	steps []string
}

func (r *stepRecorder) record(step string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.steps = append(r.steps, step)
}

func (r *stepRecorder) recorded() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.steps))
	copy(out, r.steps)
	return out
}

// recordingGate records the readiness flip.
type recordingGate struct{ recorder *stepRecorder }

func (g recordingGate) beginShutdown() { g.recorder.record("readiness") }

// recordingServer records the HTTP drain.
type recordingServer struct{ recorder *stepRecorder }

func (s recordingServer) Shutdown(context.Context) error {
	s.recorder.record("http.shutdown")
	return nil
}

func (s recordingServer) Close() error {
	s.recorder.record("http.close")
	return nil
}

// recordingPublisher records the event-pipeline steps.
type recordingPublisher struct{ recorder *stepRecorder }

func (p recordingPublisher) Publish(context.Context, events.OutboundMessage) error {
	p.recorder.record("kafka.publish")
	return nil
}

func (p recordingPublisher) Connected() bool { return true }

func (p recordingPublisher) Flush(context.Context) error {
	p.recorder.record("kafka.flush")
	return nil
}

func (p recordingPublisher) Close() error {
	p.recorder.record("kafka.close")
	return nil
}

// pendingOutbox is a repository.OutboxRepository holding one committed,
// unpublished EVT-001 record.
type pendingOutbox struct {
	recorder *stepRecorder
	records  []models.OutboxRecord
}

func (o *pendingOutbox) Insert(context.Context, *models.OutboxRecord) error { return nil }

func (o *pendingOutbox) Unpublished(context.Context, int) ([]models.OutboxRecord, error) {
	o.recorder.record("outbox.load")
	return o.records, nil
}

func (o *pendingOutbox) MarkPublished(_ context.Context, id string, _ time.Time) error {
	o.recorder.record("outbox.mark")
	kept := o.records[:0]
	for _, record := range o.records {
		if record.ID != id {
			kept = append(kept, record)
		}
	}
	o.records = kept
	return nil
}

func TestReadinessFailsFirstDuringShutdown(t *testing.T) {
	t.Parallel()
	probe := &readiness{publisher: connectedPublisher{}}
	probe.beginShutdown()

	err := probe.Ready(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "shutdown")
}

func TestReadinessRequiresEventProducer(t *testing.T) {
	t.Parallel()
	for name, probe := range map[string]*readiness{
		"nil producer": {},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := probe.Ready(context.Background())
			require.Error(t, err)
			assert.Contains(t, err.Error(), "event producer")
		})
	}
}

func TestReadinessRequiresDatabase(t *testing.T) {
	t.Parallel()
	probe := &readiness{publisher: connectedPublisher{}}

	err := probe.Ready(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "database")
}

func TestShutdownReleasesComponentsInDocumentedOrder(t *testing.T) {
	t.Parallel()
	recorder := &stepRecorder{}
	outbox := &pendingOutbox{recorder: recorder, records: []models.OutboxRecord{newPendingRecord(t)}}
	publisher := recordingPublisher{recorder: recorder}
	dispatcher := events.NewDispatcher(outbox, publisher, clock.System{}, zap.NewNop(), time.Second, 10)

	workers, stopWorkers := context.WithCancel(context.Background())
	defer stopWorkers()
	var running sync.WaitGroup
	running.Add(1)
	go func() {
		defer running.Done()
		<-workers.Done()
		recorder.record("workers.stopped")
	}()

	err := shutdown(shutdownDeps{
		Readiness: recordingGate{recorder: recorder},
		StopWorkers: func() {
			recorder.record("workers.stop")
			stopWorkers()
		},
		Workers:    &running,
		Server:     recordingServer{recorder: recorder},
		Dispatcher: dispatcher,
		Publisher:  publisher,
		ClosePool:  func() { recorder.record("pool.close") },
		Timeout:    time.Second,
	})
	require.NoError(t, err)

	// Readiness must fail before anything is drained, the committed outbox row
	// must reach Kafka before the producer closes, and the pool must be the
	// last resource released.
	assert.Equal(t, []string{
		"readiness",
		"workers.stop",
		"workers.stopped",
		"http.shutdown",
		"outbox.load",
		"kafka.publish",
		"outbox.mark",
		"kafka.flush",
		"kafka.close",
		"pool.close",
	}, recorder.recorded())
}

func TestShutdownReleasesPoolWhenFlushingFails(t *testing.T) {
	t.Parallel()
	poolClosed := false

	err := shutdown(shutdownDeps{
		Readiness: &readiness{publisher: connectedPublisher{}},
		Publisher: failingFlushPublisher{},
		ClosePool: func() { poolClosed = true },
		Timeout:   time.Second,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "flush event producer")
	assert.True(t, poolClosed, "a failing flush must not leak the database pool")
}

func TestHTTPServerBoundsSlowClients(t *testing.T) {
	t.Parallel()
	router := http.NewServeMux()

	server := newHTTPServer(":0", router, zap.NewNop())
	assert.Same(t, router, server.Handler)
	assert.Positive(t, server.ReadHeaderTimeout)
	assert.Positive(t, server.ReadTimeout)
	assert.Positive(t, server.WriteTimeout)
	assert.Positive(t, server.IdleTimeout)
	require.NotNil(t, server.ErrorLog, "net/http errors must be routed through zap")
}

// TestLoadDevelopmentEnvIgnoresProduction is not parallel: it mutates the
// process environment.
func TestLoadDevelopmentEnvIgnoresProduction(t *testing.T) {
	t.Setenv("SERVICE_ENV", "production")

	require.NoError(t, loadDevelopmentEnv())
}

// newPendingRecord builds one committed EVT-001 outbox row for the drain test.
func newPendingRecord(t *testing.T) models.OutboxRecord {
	t.Helper()
	userID, err := models.NewUUID()
	require.NoError(t, err)
	recordID, err := models.NewUUID()
	require.NoError(t, err)
	user := &models.User{
		ID:             userID,
		Email:          "ada@example.com",
		Username:       "ada",
		DisplayName:    "Ada Lovelace",
		EmailVerified:  true,
		Status:         models.UserStatusActive,
		AccountVersion: 2,
	}
	message, err := events.NewAccountChangedMessage(user, models.AccountChangeEmailVerified, events.NewFlow(), time.Now())
	require.NoError(t, err)
	envelope, err := events.MarshalEnvelope(message.Envelope)
	require.NoError(t, err)
	payload, err := events.MarshalPayload(message.Payload)
	require.NoError(t, err)

	return models.OutboxRecord{
		ID:        recordID,
		Topic:     "identity_events",
		Key:       user.ID,
		Envelope:  envelope,
		Payload:   payload,
		CreatedAt: time.Now(),
	}
}
