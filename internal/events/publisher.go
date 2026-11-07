package events

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/IBM/sarama"
	"go.uber.org/zap"
)

// OutboundMessage is one Kafka message to publish.
type OutboundMessage struct {
	// Topic is the destination topic.
	Topic string
	// Key is the message key (user_id for account events).
	Key string
	// Headers mirror trace_id and event_type.
	Headers map[string]string
	// Value is the JSON message body.
	Value []byte
}

// Publisher publishes event messages. Tests substitute a recording fake.
type Publisher interface {
	// Publish sends one message and waits for the broker acknowledgement.
	Publish(ctx context.Context, msg OutboundMessage) error
	// Connected reports whether the producer can currently reach the cluster.
	Connected() bool
	// Flush waits for in-flight messages to be acknowledged.
	Flush(ctx context.Context) error
	// Close releases producer resources.
	Close() error
}

// KafkaConfig configures the Sarama producer.
type KafkaConfig struct {
	// Brokers is the bootstrap broker list.
	Brokers []string
	// ClientID is the Kafka client id.
	ClientID string
	// Logger receives publish failures.
	Logger *zap.Logger
}

// KafkaPublisher is the Sarama synchronous, idempotent producer.
type KafkaPublisher struct {
	client   sarama.Client
	producer sarama.SyncProducer
	logger   *zap.Logger
	closed   atomic.Bool
}

// NewKafkaPublisher connects the producer. A failure here fails startup, so the
// process never serves traffic without its event backbone.
func NewKafkaPublisher(cfg KafkaConfig) (*KafkaPublisher, error) {
	saramaConfig := sarama.NewConfig()
	saramaConfig.ClientID = cfg.ClientID
	saramaConfig.Version = sarama.V2_1_0_0
	saramaConfig.Producer.RequiredAcks = sarama.WaitForAll
	saramaConfig.Producer.Return.Successes = true
	saramaConfig.Producer.Idempotent = true
	saramaConfig.Producer.Retry.Max = 5
	saramaConfig.Net.MaxOpenRequests = 1

	client, err := sarama.NewClient(cfg.Brokers, saramaConfig)
	if err != nil {
		return nil, fmt.Errorf("events: connect kafka: %w", err)
	}
	producer, err := sarama.NewSyncProducerFromClient(client)
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("events: create sync producer: %w", err)
	}
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	return &KafkaPublisher{client: client, producer: producer, logger: logger}, nil
}

// Publish implements Publisher.
func (p *KafkaPublisher) Publish(ctx context.Context, msg OutboundMessage) error {
	if p.closed.Load() {
		return fmt.Errorf("events: producer is closed")
	}
	headers := make([]sarama.RecordHeader, 0, len(msg.Headers))
	for key, value := range msg.Headers {
		headers = append(headers, sarama.RecordHeader{Key: []byte(key), Value: []byte(value)})
	}
	message := &sarama.ProducerMessage{
		Topic:   msg.Topic,
		Key:     sarama.StringEncoder(msg.Key),
		Value:   sarama.ByteEncoder(msg.Value),
		Headers: headers,
	}

	type result struct{ err error }
	done := make(chan result, 1)
	go func() {
		_, _, err := p.producer.SendMessage(message)
		done <- result{err: err}
	}()

	select {
	case <-ctx.Done():
		return fmt.Errorf("events: publish cancelled: %w", ctx.Err())
	case res := <-done:
		if res.err != nil {
			return fmt.Errorf("events: publish message: %w", res.err)
		}
		return nil
	}
}

// Connected reports whether the producer can reach the cluster controller.
func (p *KafkaPublisher) Connected() bool {
	if p.closed.Load() {
		return false
	}
	if _, err := p.client.RefreshController(); err != nil {
		if !errors.Is(err, sarama.ErrClosedClient) {
			p.logger.Warn("kafka controller refresh failed",
				zap.String("operation", "kafka.health"), zap.Error(err), zap.String("status", "unavailable"))
		}
		return false
	}
	return true
}

// Flush is a no-op for the synchronous producer: every Publish waits for its
// acknowledgement, so nothing is buffered locally.
func (p *KafkaPublisher) Flush(context.Context) error { return nil }

// Close shuts the producer and the client down.
func (p *KafkaPublisher) Close() error {
	if p.closed.Swap(true) {
		return nil
	}
	var firstErr error
	if err := p.producer.Close(); err != nil {
		firstErr = err
	}
	if err := p.client.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

var _ Publisher = (*KafkaPublisher)(nil)
