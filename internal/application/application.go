/*
Copyright © 2025 Denis Khalturin
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/
// prettier-ignore-end
package application

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"ssl-pinning/internal/config"
	"ssl-pinning/internal/keys"
	"ssl-pinning/internal/metrics"
	"ssl-pinning/internal/server"
	"ssl-pinning/internal/signer"
	"ssl-pinning/internal/storage"
	"ssl-pinning/internal/storage/types"
)

// App represents the main application structure that orchestrates all components
// including HTTP servers, storage, cryptographic signer, and domain keys management.
// It manages the application lifecycle from initialization to graceful shutdown.
type App struct {
	config        config.Config
	keys          *keys.Keys
	serverHttp    *server.Server
	serverMetrics *server.Server
	signer        *signer.Signer
	storage       types.Storage
}

// New creates and initializes a new App instance with all required components.
// It sets up the application context with signal handling (SIGTERM, SIGINT),
// loads configuration, initializes cryptographic signer, storage backend,
// HTTP server for API endpoints, and metrics server for monitoring.
// Returns an error if any component fails to initialize.
func New() (*App, error) {
	slog.Debug("initializing application")

	ctx := context.Background()
	// ctx, cancel := context.WithCancel(context.Background())
	// ctx, _ = context.WithTimeout(context.Background(), time.Second*10) // testing close context

	cfg, err := config.New()
	if err != nil {
		slog.Error("failed to load config")
		return nil, err
	}

	signer, err := signer.NewSigner(
		fmt.Sprintf("%s/prv.pem", cfg.TLS.Dir),
	)
	if err != nil {
		slog.Error("failed to create signer")
		return nil, err
	}

	store, err := storage.New(ctx, cfg.Storage.Type,
		types.WithAppID(cfg.UUID.String()),
		types.WithConnMaxIdleTime(cfg.Storage.ConnMaxIdleTime),
		types.WithConnMaxLifetime(cfg.Storage.ConnMaxLifetime),
		types.WithDSN(cfg.Storage.DSN),
		types.WithDumpDir(cfg.Storage.DumpDir),
		types.WithMaxIdleConns(cfg.Storage.MaxIdleConns),
		types.WithMaxOpenConns(cfg.Storage.MaxOpenConns),
		types.WithSigner(signer),
	)
	if err != nil {
		slog.Error("failed to create storage")
		return nil, err
	}

	collector := metrics.NewCollector()

	k := keys.NewKeys(ctx, cfg.Keys,
		keys.WithCollector(collector),
		keys.WithDumpInterval(cfg.TLS.DumpInterval),
		keys.WithFlushFunc(func(keys map[string]types.DomainKey) error {
			slog.Debug("flushing keys to storage", "keys", keys)

			store.SaveKeys(keys)

			return nil
		}),
		keys.WithTimeout(cfg.TLS.Timeout),
	)

	srvHttp := server.NewServer(
		server.WithAddr(cfg.Server.Listen),
		server.WithReadTimeout(cfg.Server.ReadTimeout),
		// server.WithStorage(store),
		server.WithWriteTimeout(cfg.Server.WriteTimeout),
	)

	srvMetrics := server.NewServer(
		server.WithAddr("127.0.0.1:9090"),
	)
	srvMetrics.SetHandle("/metrics", promhttp.Handler())
	srvMetrics.SetHandleFunc("/", metrics.Root)
	srvMetrics.SetHandleFunc("/health/liveness", store.ProbeLiveness())
	srvMetrics.SetHandleFunc("/health/readiness", store.ProbeReadiness())
	srvMetrics.SetHandleFunc("/health/startup", store.ProbeStartup())

	app := &App{
		config:        cfg,
		keys:          k,
		serverMetrics: srvMetrics,
		serverHttp:    srvHttp,
		signer:        signer,
		storage:       store,
	}

	srvHttp.SetHandleFunc("/api/v1/{file}", app.handleFileJSON)

	return app, nil
}

// handleFileJSON handles HTTP requests for retrieving domain keys by filename.
// It accepts GET requests to /api/v1/{file}, retrieves corresponding domain keys
// from storage, signs them if multiple keys are found, and returns JSON response.
// Returns 400 if filename is missing, 404 if file not found, or 500 on internal errors.
func (a *App) handleFileJSON(w http.ResponseWriter, r *http.Request) {
	time.Sleep(time.Second * 3)
	file := r.PathValue("file")
	if file == "" {
		http.Error(w, "file required", http.StatusBadRequest)
		return
	}

	slog.Debug("request", "req", r.URL.Path, "file", file)

	keys, data, err := a.storage.GetByFile(file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if len(keys) > 1 {
		slog.Debug("found keys", "file", file, "keys", keys)
		res, err := types.SignedKeys(file, keys, a.signer)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data = res
	}

	if data != nil {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
		return
	}

	slog.Error("file not found", "file", file, "keys_found", len(keys), "data_len", len(data))

	http.Error(w, fmt.Sprintf("file %s not found", file), http.StatusNotFound)
}

// Up starts the application and all its components in separate goroutines.
// It launches metrics server, main HTTP server, and periodic domain keys persistence to storage.
// Blocks until context is cancelled (via signal or timeout), then triggers graceful shutdown.
func (a *App) Up() {
	slog.Info("starting application",
		"storage_type", a.config.Storage.Type,
		"app_id", a.config.UUID.String(),
	)

	go a.keys.StartPeriodicFlush()
	go a.serverMetrics.Up()
	go a.serverHttp.Up()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs,
		syscall.SIGTERM,
		syscall.SIGINT,
	)

	sig := <-sigs
	slog.Info("shutdown signal received", "signal", fmt.Sprintf("%s (%d)", sig.String(), sig))

	a.Down()
}

// Down performs graceful shutdown of the application.
// It closes the storage connection and ensures all resources are properly released.
// Logs any errors encountered during shutdown and returns the last error if any.
func (a *App) Down() error {
	a.serverMetrics.Down()
	a.serverHttp.Down()

	if a.storage != nil {
		if err := a.storage.Close(); err != nil {
			slog.Error("failed to close storage", "error", err)
		}
	}

	slog.Info("application stopped")
	return nil
}
