// Command server is the identity_service entrypoint: it loads and validates the
// configuration, applies the embedded schema migrations, connects PostgreSQL,
// Kafka and Resend, serves the HTTP API and shuts every component down
// gracefully on SIGTERM/SIGINT (docs/architecture.md §5,
// docs/engineering_guide.md §3).
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/golang-migrate/migrate/v4"
	migratepgx "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"identity_service/internal/clock"
	"identity_service/internal/config"
	"identity_service/internal/email"
	"identity_service/internal/events"
	"identity_service/internal/handler"
	"identity_service/internal/metrics"
	"identity_service/internal/observability"
	"identity_service/internal/repository"
	"identity_service/internal/security"
	"identity_service/internal/service"
	"identity_service/migrations"
)

const (
	// kafkaClientID identifies this service on the event backbone.
	kafkaClientID = observability.ServiceName
	// sessionGaugeInterval is how often identity_active_sessions is refreshed.
	sessionGaugeInterval = 30 * time.Second
	// migrationDriver is the golang-migrate driver name registered by
	// database/pgx/v5.
	migrationDriver = "pgx5"
	// migrationSource is the registered name of the embedded iofs source.
	migrationSource = "iofs"
)

func main() {
	if err := run(); err != nil {
		writeStartupFailure(err)
		os.Exit(1)
	}
}

// writeStartupFailure reports a failure that happened before (or instead of)
// serving traffic as one structured JSON line, following the logging
// conventions of docs/engineering_guide.md §7.
func writeStartupFailure(err error) {
	line, marshalErr := json.Marshal(map[string]string{
		"level":        "error",
		"service_name": observability.ServiceName,
		"operation":    "startup",
		"status":       "failed",
		"error":        err.Error(),
	})
	if marshalErr != nil {
		fmt.Fprintln(os.Stderr, "identity_service: startup failed:", err)
		return
	}
	fmt.Fprintln(os.Stderr, string(line))
}

// run wires the process and blocks until a shutdown signal or a fatal serve
// error. It returns only after every owned resource has been released, so
// main can map the result to the process exit code.
func run() error {
	if err := loadDevelopmentEnv(); err != nil {
		return err
	}
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}

	logger, err := observability.NewLogger(cfg.LogLevel)
	if err != nil {
		return err
	}
	defer func() { _ = logger.Sync() }()

	logger.Info("service starting",
		zap.String("operation", "startup"),
		zap.String("status", "starting"),
		zap.String("environment", cfg.Environment),
		zap.String("address", cfg.HTTPAddr),
		zap.String("hostname", observability.Hostname()),
	)

	// SIGTERM/SIGINT cancel this context and start the documented shutdown
	// sequence.
	signalCtx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()

	// Business, RED and provider metrics are registered on the default registry
	// at startup (docs/architecture.md §6).
	recorder := metrics.New(prometheus.DefaultRegisterer)

	db, err := repository.Open(signalCtx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()

	// Schema migrations always run before the HTTP server starts.
	if err := runMigrations(cfg.DatabaseURL); err != nil {
		return err
	}

	repos := db.Repositories()

	keys := service.NewKeyManager(repos.SigningKeys, repos.Transactor, clock.System{},
		cfg.SigningKeyRotationInterval, cfg.SigningKeyRotationOverlap, logger)
	if err := keys.EnsureKeys(signalCtx); err != nil {
		return err
	}

	hasher, err := security.NewHasher(security.DefaultArgon2Params())
	if err != nil {
		return err
	}

	notifier := email.NewAdapter(nil, email.NewAdapterConfig(cfg.ResendAPIKey, cfg.MailFrom, cfg.AppBaseURL), recorder, logger)

	// An unreachable broker fails startup: traffic is never served without the
	// event backbone (docs/architecture.md §5).
	publisher, err := events.NewKafkaPublisher(events.KafkaConfig{
		Brokers:  cfg.KafkaBrokers,
		ClientID: kafkaClientID,
		Logger:   logger,
	})
	if err != nil {
		return err
	}
	defer func() { _ = publisher.Close() }()

	identity, err := service.NewService(service.Deps{
		Repos:    repos,
		Keys:     keys,
		Notifier: notifier,
		Clock:    clock.System{},
		Metrics:  recorder,
		Logger:   logger,
		Config:   cfg,
		Hasher:   hasher,
	})
	if err != nil {
		return err
	}

	dispatcher := events.NewDispatcher(repos.Outbox, publisher, clock.System{}, logger,
		cfg.OutboxPollInterval, cfg.OutboxBatchSize)
	ready := &readiness{database: db, publisher: publisher}

	router, err := handler.NewRouter(handler.Options{
		Auth:      identity,
		Account:   identity,
		Sessions:  identity,
		Keys:      keys,
		Tokens:    identity.TokenIssuer(),
		Readiness: ready,
		Metrics:   recorder,
		Logger:    logger,
		Cookie: handler.CookieSettings{
			Name: cfg.RefreshCookieName,
			Path: cfg.RefreshCookiePath,
		},
	})
	if err != nil {
		return err
	}

	server := newHTTPServer(cfg.HTTPAddr, router, logger)

	// Background workers: the outbox dispatcher publishes committed events, the
	// session tracker keeps the active-session gauge current. Both stop with
	// stopWorkers and are waited for before the producer and pool are closed.
	workers, stopWorkers := context.WithCancel(context.Background())
	var running sync.WaitGroup
	running.Add(2)
	go func() {
		defer running.Done()
		dispatcher.Run(workers)
	}()
	go func() {
		defer running.Done()
		trackActiveSessions(workers, repos.Sessions, recorder, logger)
	}()

	serveErr := make(chan error, 1)
	go func() {
		err := server.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()

	logger.Info("service ready",
		zap.String("operation", "startup"),
		zap.String("status", "ok"),
		zap.String("address", cfg.HTTPAddr),
	)

	var failure error
	select {
	case <-signalCtx.Done():
		logger.Info("shutdown signal received",
			zap.String("operation", "shutdown"),
			zap.String("status", "draining"),
		)
	case err := <-serveErr:
		if err != nil {
			failure = fmt.Errorf("entrypoint: serve http: %w", err)
			logger.Error("http server stopped",
				zap.String("operation", "serve"),
				zap.String("status", "error"),
				zap.Error(err),
			)
		}
	}

	failure = errors.Join(failure, shutdown(shutdownDeps{
		Readiness:   ready,
		StopWorkers: stopWorkers,
		Workers:     &running,
		Server:      server,
		Dispatcher:  dispatcher,
		Publisher:   publisher,
		ClosePool:   db.Close,
		Timeout:     cfg.ShutdownTimeout,
	}))

	logger.Info("service stopped",
		zap.String("operation", "shutdown"),
		zap.String("status", "stopped"),
	)
	return failure
}

// shutdownGate flips readiness to "not ready" before traffic stops arriving.
type shutdownGate interface {
	beginShutdown()
}

// httpShutdowner drains the HTTP server and force-closes it on timeout.
type httpShutdowner interface {
	Shutdown(ctx context.Context) error
	Close() error
}

// outboxFlusher publishes the events that are still waiting in the outbox.
type outboxFlusher interface {
	Flush(ctx context.Context) error
}

// shutdownDeps are the components released during shutdown, in the order
// docs/engineering_guide.md §3 requires.
type shutdownDeps struct {
	// Readiness must fail first, so no new request is routed to this process.
	Readiness shutdownGate
	// StopWorkers pauses the background loops; Workers waits for them.
	StopWorkers context.CancelFunc
	Workers     *sync.WaitGroup
	// Server drains in-flight requests within Timeout.
	Server httpShutdowner
	// Dispatcher publishes committed outbox rows that have not reached Kafka.
	Dispatcher outboxFlusher
	// Publisher is flushed and closed after the outbox drain.
	Publisher events.Publisher
	// ClosePool releases PostgreSQL last, after every consumer stopped.
	ClosePool func()
	// Timeout bounds the whole drain.
	Timeout time.Duration
}

// shutdown applies the documented sequence: readiness fails, background work
// pauses, in-flight requests drain, the event pipeline is flushed and closed,
// and the database pool is released last. Component failures are aggregated so
// one failing step never prevents the remaining resources from being released.
func shutdown(deps shutdownDeps) error {
	var failure error

	if deps.Readiness != nil {
		deps.Readiness.beginShutdown()
	}
	if deps.StopWorkers != nil {
		deps.StopWorkers()
	}
	if deps.Workers != nil {
		deps.Workers.Wait()
	}

	timeout := deps.Timeout
	if timeout <= 0 {
		timeout = config.DefaultShutdownTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if deps.Server != nil {
		if err := deps.Server.Shutdown(ctx); err != nil {
			_ = deps.Server.Close()
			failure = errors.Join(failure, fmt.Errorf("entrypoint: shutdown http server: %w", err))
		}
	}
	if deps.Dispatcher != nil {
		if err := deps.Dispatcher.Flush(ctx); err != nil {
			failure = errors.Join(failure, fmt.Errorf("entrypoint: flush outbox: %w", err))
		}
	}
	if deps.Publisher != nil {
		if err := deps.Publisher.Flush(ctx); err != nil {
			failure = errors.Join(failure, fmt.Errorf("entrypoint: flush event producer: %w", err))
		}
		if err := deps.Publisher.Close(); err != nil {
			failure = errors.Join(failure, fmt.Errorf("entrypoint: close event producer: %w", err))
		}
	}
	if deps.ClosePool != nil {
		deps.ClosePool()
	}
	return failure
}

// loadDevelopmentEnv reads a local .env file when SERVICE_ENV selects
// development. Production reads plain environment variables only
// (docs/engineering_guide.md §6), so a missing file is not an error there.
func loadDevelopmentEnv() error {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("SERVICE_ENV")), "development") {
		return nil
	}
	if err := godotenv.Load(); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("entrypoint: load .env: %w", err)
	}
	return nil
}

// runMigrations applies every pending migration embedded in the binary. The
// driver takes an advisory lock, so replicas starting at the same time
// serialise instead of racing; "no change" is not a failure.
func runMigrations(databaseURL string) error {
	source, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("entrypoint: open embedded migrations: %w", err)
	}
	sqlDB, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return fmt.Errorf("entrypoint: open migration connection: %w", err)
	}
	defer func() { _ = sqlDB.Close() }()

	driver, err := migratepgx.WithInstance(sqlDB, &migratepgx.Config{
		// One migration file contains several statements; the driver has to
		// split them before executing.
		MultiStatementEnabled: true,
	})
	if err != nil {
		return fmt.Errorf("entrypoint: initialise migration driver: %w", err)
	}
	migrator, err := migrate.NewWithInstance(migrationSource, source, migrationDriver, driver)
	if err != nil {
		return fmt.Errorf("entrypoint: create migrator: %w", err)
	}

	applyErr := migrator.Up()
	switch {
	case applyErr == nil:
	case errors.Is(applyErr, migrate.ErrNoChange):
		applyErr = nil
	default:
		applyErr = fmt.Errorf("entrypoint: apply migrations: %w", applyErr)
	}

	if sourceErr, dbErr := migrator.Close(); errors.Join(sourceErr, dbErr) != nil && applyErr == nil {
		return fmt.Errorf("entrypoint: close migrator: %w", errors.Join(sourceErr, dbErr))
	}
	return applyErr
}

// newHTTPServer builds the HTTP server with timeouts that bound slow or idle
// clients, and routes the server's internal error log through zap so every log
// line stays structured JSON.
func newHTTPServer(addr string, router http.Handler, logger *zap.Logger) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          log.New(zapWriter{logger: logger}, "", 0),
	}
}

// zapWriter adapts the standard library's log output to a zap logger.
type zapWriter struct {
	logger *zap.Logger
}

// Write implements io.Writer for net/http's internal error log.
func (w zapWriter) Write(p []byte) (int, error) {
	w.logger.Warn(strings.TrimSpace(string(p)),
		zap.String("operation", "http.server"),
		zap.String("status", "error"),
	)
	return len(p), nil
}

// trackActiveSessions keeps identity_active_sessions in sync with PostgreSQL
// until ctx is cancelled.
func trackActiveSessions(ctx context.Context, sessions repository.SessionRepository, recorder *metrics.Metrics, logger *zap.Logger) {
	ticker := time.NewTicker(sessionGaugeInterval)
	defer ticker.Stop()
	for {
		count, err := sessions.CountActive(ctx)
		if err != nil {
			if ctx.Err() == nil {
				logger.Warn("active session count failed",
					zap.String("operation", "metrics.active_sessions"),
					zap.String("status", "retrying"),
					zap.Error(err),
				)
			}
		} else {
			recorder.SetActiveSessions(count)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// readiness implements handler.ReadinessChecker for /readyz: PostgreSQL must
// be pingable, the Kafka producer reachable, and shutdown must not have begun
// (docs/architecture.md §5). Details stay in the logs; /readyz only reports
// service_unavailable.
type readiness struct {
	database     *repository.Postgres
	publisher    events.Publisher
	shuttingDown atomic.Bool
}

// Ready reports whether the process may receive traffic.
func (r *readiness) Ready(ctx context.Context) error {
	switch {
	case r.shuttingDown.Load():
		return errors.New("readiness: shutdown in progress")
	case r.publisher == nil || !r.publisher.Connected():
		return errors.New("readiness: event producer unavailable")
	case r.database == nil:
		return errors.New("readiness: database unavailable")
	}
	if err := r.database.Ping(ctx); err != nil {
		return fmt.Errorf("readiness: postgres unavailable: %w", err)
	}
	return nil
}

// beginShutdown makes every subsequent readiness probe fail while in-flight
// requests are still being served.
func (r *readiness) beginShutdown() { r.shuttingDown.Store(true) }
