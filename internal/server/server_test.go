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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	logger "gopkg.in/slog-handler.v1"
)

func TestNewServer(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	tests := []struct {
		name     string
		opts     []Option
		validate func(t *testing.T, s *Server)
	}{
		{
			name: "default server",
			opts: []Option{},
			validate: func(t *testing.T, s *Server) {
				if s == nil {
					t.Fatal("NewServer() returned nil")
				}
				if s.ctx == nil {
					t.Error("ctx is nil")
				}
				if s.errs == nil {
					t.Error("errs channel is nil")
				}
				if s.http == nil {
					t.Error("http server is nil")
				}
				if s.mux == nil {
					t.Error("mux is nil")
				}
			},
		},
		{
			name: "server with address",
			opts: []Option{
				WithAddr("127.0.0.1:8080"),
			},
			validate: func(t *testing.T, s *Server) {
				if s.http.Addr != "127.0.0.1:8080" {
					t.Errorf("addr = %v, want 127.0.0.1:8080", s.http.Addr)
				}
			},
		},
		{
			name: "server with timeouts",
			opts: []Option{
				WithReadTimeout(5 * time.Second),
				WithWriteTimeout(10 * time.Second),
			},
			validate: func(t *testing.T, s *Server) {
				if s.http.ReadTimeout != 5*time.Second {
					t.Errorf("ReadTimeout = %v, want 5s", s.http.ReadTimeout)
				}
				if s.http.WriteTimeout != 10*time.Second {
					t.Errorf("WriteTimeout = %v, want 10s", s.http.WriteTimeout)
				}
			},
		},
		{
			name: "server with handler",
			opts: []Option{
				WithHandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					fmt.Fprint(w, "test response")
				}),
			},
			validate: func(t *testing.T, s *Server) {
				if s.mux == nil {
					t.Fatal("mux should not be nil")
				}

				assert.HTTPBodyContains(t, s.mux.ServeHTTP, http.MethodGet, "/test", nil, "test response")
				assert.HTTPStatusCode(t, s.mux.ServeHTTP, http.MethodGet, "/test", nil, http.StatusOK)
			},
		},
		{
			name: "server with multiple options",
			opts: []Option{
				WithAddr(":9090"),
				WithReadTimeout(3 * time.Second),
				WithWriteTimeout(5 * time.Second),
				WithHandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					fmt.Fprint(w, "healthy")
				}),
			},
			validate: func(t *testing.T, s *Server) {
				if s.http.Addr != ":9090" {
					t.Errorf("addr = %v, want :9090", s.http.Addr)
				}
				if s.http.ReadTimeout != 3*time.Second {
					t.Errorf("ReadTimeout = %v, want 3s", s.http.ReadTimeout)
				}
				if s.http.WriteTimeout != 5*time.Second {
					t.Errorf("WriteTimeout = %v, want 5s", s.http.WriteTimeout)
				}

				assert.HTTPBodyContains(t, s.mux.ServeHTTP, http.MethodGet, "/health", nil, "healthy")
				assert.HTTPStatusCode(t, s.mux.ServeHTTP, http.MethodGet, "/health", nil, http.StatusOK)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewServer(tt.opts...)
			tt.validate(t, s)
		})
	}
}

func TestServer_SetHandleFunc(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	s := NewServer()

	s.SetHandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "handler called")
	})

	assert.HTTPBodyContains(t, s.mux.ServeHTTP, http.MethodGet, "/test", nil, "handler called")
	assert.HTTPStatusCode(t, s.mux.ServeHTTP, http.MethodGet, "/test", nil, http.StatusOK)
}

func TestServer_SetHandle(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	s := NewServer()

	s.SetHandle("/test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "handle called")
	}))

	assert.HTTPBodyContains(t, s.mux.ServeHTTP, http.MethodGet, "/test", nil, "handle called")
	assert.HTTPStatusCode(t, s.mux.ServeHTTP, http.MethodGet, "/test", nil, http.StatusOK)
}

func TestWithAddr(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	tests := []struct {
		name string
		addr string
	}{
		{
			name: "localhost with port",
			addr: "127.0.0.1:8080",
		},
		{
			name: "all interfaces",
			addr: ":8080",
		},
		{
			name: "specific interface",
			addr: "0.0.0.0:9090",
		},
		{
			name: "empty address",
			addr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewServer(WithAddr(tt.addr))
			if s.http.Addr != tt.addr {
				t.Errorf("WithAddr() addr = %v, want %v", s.http.Addr, tt.addr)
			}
		})
	}
}

func TestWithReadTimeout(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	tests := []struct {
		name    string
		timeout time.Duration
	}{
		{
			name:    "5 seconds",
			timeout: 5 * time.Second,
		},
		{
			name:    "1 minute",
			timeout: time.Minute,
		},
		{
			name:    "zero timeout",
			timeout: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewServer(WithReadTimeout(tt.timeout))
			if s.http.ReadTimeout != tt.timeout {
				t.Errorf("WithReadTimeout() timeout = %v, want %v", s.http.ReadTimeout, tt.timeout)
			}
		})
	}
}

func TestWithWriteTimeout(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	tests := []struct {
		name    string
		timeout time.Duration
	}{
		{
			name:    "10 seconds",
			timeout: 10 * time.Second,
		},
		{
			name:    "30 seconds",
			timeout: 30 * time.Second,
		},
		{
			name:    "zero timeout",
			timeout: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewServer(WithWriteTimeout(tt.timeout))
			if s.http.WriteTimeout != tt.timeout {
				t.Errorf("WithWriteTimeout() timeout = %v, want %v", s.http.WriteTimeout, tt.timeout)
			}
		})
	}
}

func TestWithHandleFunc(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	s := NewServer(WithHandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "with handle func")
	}))

	assert.HTTPBodyContains(t, s.mux.ServeHTTP, http.MethodGet, "/test", nil, "with handle func")
	assert.HTTPStatusCode(t, s.mux.ServeHTTP, http.MethodGet, "/test", nil, http.StatusOK)
}

func TestServer_Integration(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	// Find available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find available port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	addr := fmt.Sprintf("127.0.0.1:%d", port)

	// Create server with test handler
	s := NewServer(
		WithAddr(addr),
		WithHandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "test response")
		}),
		WithHandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "OK")
		}),
		WithReadTimeout(5*time.Second),
		WithWriteTimeout(5*time.Second),
	)

	// Start server in background
	go func() {
		s.run()
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Test /test endpoint
	resp, err := http.Get(fmt.Sprintf("http://%s/test", addr))
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status code = %v, want %v", resp.StatusCode, http.StatusOK)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}

	if string(body) != "test response" {
		t.Errorf("body = %v, want 'test response'", string(body))
	}

	// Test /health endpoint
	resp2, err := http.Get(fmt.Sprintf("http://%s/health", addr))
	if err != nil {
		t.Fatalf("failed to make health request: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("health status code = %v, want %v", resp2.StatusCode, http.StatusOK)
	}

	// Shutdown server
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := s.http.Shutdown(ctx); err != nil {
		t.Errorf("failed to shutdown server: %v", err)
	}
}

func TestServer_Down(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	// Find available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find available port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	addr := fmt.Sprintf("127.0.0.1:%d", port)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := &Server{
		ctx:  ctx,
		errs: make(chan error, 1),
		http: &http.Server{Addr: addr},
		mux:  http.NewServeMux(),
	}

	// Start server
	go func() {
		s.run()
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Test graceful shutdown
	s.Down()

	// Verify server is stopped
	_, err = http.Get(fmt.Sprintf("http://%s/", addr))
	if err == nil {
		t.Error("server should be stopped after Down()")
	}
}

func TestServer_MultipleHandlers(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	s := NewServer()

	handlers := map[string]bool{
		"/handler1": false,
		"/handler2": false,
		"/handler3": false,
	}

	for pattern := range handlers {
		p := pattern // capture for closure
		s.SetHandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			handlers[p] = true
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "response from %s", p)
		})
	}

	// Verify all handlers are registered
	if s.mux == nil {
		t.Fatal("mux should not be nil after registering handlers")
	}

	// Test each handler
	for pattern := range handlers {
		req := httptest.NewRequest(http.MethodGet, pattern, nil)
		w := httptest.NewRecorder()

		s.mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("handler %s: status code = %v, want %v", pattern, w.Code, http.StatusOK)
		}

		expectedBody := fmt.Sprintf("response from %s", pattern)
		body := w.Body.String()
		if body != expectedBody {
			t.Errorf("handler %s: body = %v, want %v", pattern, body, expectedBody)
		}

		if !handlers[pattern] {
			t.Errorf("handler %s was not called", pattern)
		}
	}
}

func TestServer_ErrorChannel(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	s := NewServer()

	if s.errs == nil {
		t.Error("error channel should be initialized")
	}

	// Test that we can send to error channel
	testErr := fmt.Errorf("test error")
	go func() {
		s.errs <- testErr
	}()

	select {
	case err := <-s.errs:
		if err != testErr {
			t.Errorf("error = %v, want %v", err, testErr)
		}
	case <-time.After(time.Second):
		t.Error("timeout waiting for error")
	}
}

func BenchmarkNewServer(b *testing.B) {
	opts := []Option{
		WithAddr(":8080"),
		WithReadTimeout(5 * time.Second),
		WithWriteTimeout(10 * time.Second),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewServer(opts...)
	}
}

func BenchmarkServer_SetHandleFunc(b *testing.B) {
	s := NewServer()
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pattern := fmt.Sprintf("/test%d", i)
		s.SetHandleFunc(pattern, handler)
	}
}
