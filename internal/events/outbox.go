package events

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"identity_service/internal/clock"
	"identity_service/internal/repository"
)

// Dispatcher publishes committed outbox rows after their transaction commits.
// Publication is at-least-once: a row is marked published only after the broker
// acknowledged it, so a crash between publish and mark republishes.
type Dispatcher struct {
	outbox    repository.OutboxRepository
	publisher Publisher
	clock     clock.Clock
	logger    *zap.Logger
	interval  time.Duration
	batch     int
}

// NewDispatcher builds the outbox dispatcher.
func NewDispatcher(outbox repository.OutboxRepository, publisher Publisher, clk clock.Clock, logger *zap.Logger, interval time.Duration, batch int) *Dispatcher {
	if logger == nil {
		logger = zap.NewNop()
	}
	if interval <= 0 {
		interval = time.Second
	}
	if batch <= 0 {
		batch = 50
	}
	return &Dispatcher{outbox: outbox, publisher: publisher, clock: clk, logger: logger, interval: interval, batch: batch}
}

// Run drains the outbox on a ticker until ctx is cancelled.
func (d *Dispatcher) Run(ctx context.Context) {
	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := d.DispatchOnce(ctx); err != nil {
				d.logger.Warn("outbox dispatch failed",
					zap.String("operation", "outbox.dispatch"), zap.Error(err), zap.String("status", "retrying"))
			}
		}
	}
}

// DispatchOnce publishes one batch of unpublished events and returns how many
// were published.
func (d *Dispatcher) DispatchOnce(ctx context.Context) (int, error) {
	records, err := d.outbox.Unpublished(ctx, d.batch)
	if err != nil {
		return 0, fmt.Errorf("events: load outbox: %w", err)
	}
	published := 0
	for i := range records {
		record := records[i]
		value, err := MarshalForWire(record.Envelope, record.Payload)
		if err != nil {
			return published, err
		}
		headers, err := HeadersFromEnvelope(record.Envelope)
		if err != nil {
			return published, err
		}
		if err := d.publisher.Publish(ctx, OutboundMessage{
			Topic:   record.Topic,
			Key:     record.Key,
			Headers: headers,
			Value:   value,
		}); err != nil {
			return published, err
		}
		if err := d.outbox.MarkPublished(ctx, record.ID, d.clock.Now()); err != nil {
			return published, fmt.Errorf("events: mark outbox published: %w", err)
		}
		published++
	}
	return published, nil
}

// Flush publishes every pending outbox row. It is used during graceful
// shutdown so committed state changes reach Kafka before the process exits.
func (d *Dispatcher) Flush(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("events: flush outbox: %w", err)
		}
		count, err := d.DispatchOnce(ctx)
		if err != nil {
			return err
		}
		if count < d.batch {
			return nil
		}
	}
}
