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
package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"
)

// Option is a functional option type for configuring Server instance.
type Option func(*Server)

// Server represents an HTTP server with lifecycle management and graceful shutdown.
// It wraps http.Server with context-based lifecycle control, custom routing via ServeMux,
// and error handling through a dedicated error channel.
type Server struct {
	ctx  context.Context
	errs chan error
	http *http.Server
	mux  *http.ServeMux
	// storage types.Storage
}

// NewServer creates and initializes a new Server instance with the provided context and options.
// It sets up an HTTP server with a ServeMux for routing and an error channel for async error handling.
// Configuration is applied via functional options (address, timeouts, handlers).
func NewServer(opts ...Option) *Server {
	s := &Server{
		ctx:  context.Background(),
		errs: make(chan error, 1),
		http: new(http.Server),
		mux:  http.NewServeMux(),
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// WithHandleFunc returns an option that registers an HTTP handler function for the specified pattern.
// This is a convenience option that calls SetHandleFunc during server initialization.
func WithHandleFunc(pattern string, handlerFunc http.HandlerFunc) Option {
	return func(s *Server) {
		s.SetHandleFunc(pattern, handlerFunc)
	}
}

// func WithStorage(storage types.Storage) Option {
// 	return func(s *Server) {
// 		s.storage = storage
// 	}
// }

// WithReadTimeout returns an option that sets the maximum duration for reading the entire request.
func WithReadTimeout(d time.Duration) Option {
	return func(s *Server) {
		s.http.ReadTimeout = d
	}
}

// WithWriteTimeout returns an option that sets the maximum duration before timing out writes of the response.
func WithWriteTimeout(d time.Duration) Option {
	return func(s *Server) {
		s.http.WriteTimeout = d
	}
}

// WithAddr returns an option that sets the TCP address for the server to listen on.
// Format: "host:port" (e.g., "127.0.0.1:8080" or ":8080" for all interfaces).
func WithAddr(addr string) Option {
	return func(s *Server) {
		s.http.Addr = addr
	}
}

// SetHandleFunc registers an HTTP handler function for the specified pattern in the server's mux.
func (s *Server) SetHandleFunc(pattern string, handlerFunc http.HandlerFunc) {
	s.mux.HandleFunc(pattern, handlerFunc)
}

// SetHandle registers an HTTP handler for the specified pattern in the server's mux.
func (s *Server) SetHandle(pattern string, handler http.Handler) {
	s.mux.Handle(pattern, handler)
}

// Up starts the HTTP server in a goroutine and blocks until context is cancelled or an error occurs.
// When stopped, it triggers graceful shutdown via down() method.
func (s *Server) Up() {
	go s.run()

	select {
	case <-s.ctx.Done():
	case err := <-s.errs:
		slog.Error("an error occurred", "err", err)
	}
}

// Down performs graceful shutdown of the HTTP server with a 10-second timeout.
// It waits for active connections to complete or forces shutdown after timeout.
// Exits with status code 1 if shutdown fails for reasons other than deadline exceeded.
func (s *Server) Down() {
	ctx := s.ctx
	// ctx, cancel := context.WithTimeout(s.ctx, time.Second*10)
	// defer cancel()

	if err := s.http.Shutdown(ctx); err != nil {
		if !errors.Is(err, context.DeadlineExceeded) {
			slog.Error("failed to shutdown http server", "err", err)
			os.Exit(1)
		}
	}

	slog.Info("http server stopped gracefully")
}

// run starts the HTTP server and listens for incoming connections.
// Errors other than http.ErrServerClosed are sent to the error channel for handling.
// This method is intended to be called in a goroutine from Up().
func (s *Server) run() error {
	slog.Info("start http server", "addr", s.http.Addr)

	s.http.Handler = s.mux

	err := s.http.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.errs <- err
	}

	return nil
}
