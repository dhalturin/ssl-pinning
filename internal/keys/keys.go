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
package keys

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"log/slog"
	"net"
	"ssl-pinning/internal/metrics"
	"ssl-pinning/internal/storage/types"
	"sync"
	"time"
)

// NewKeys creates and initializes a new Keys instance with domain key management.
// It accepts a context for lifecycle management, a list of domain keys to monitor,
// and optional configuration via functional options.
// Automatically starts workers for each domain key to fetch and update their SSL certificates.
func NewKeys(ctx context.Context, keys []types.DomainKey, opts ...Option) *Keys {
	k := &Keys{
		ctx:     ctx,
		store:   make(map[string]*types.DomainKey),
		workers: make(map[string]context.CancelFunc),
	}

	for _, opt := range opts {
		opt(k)
	}

	for _, key := range keys {
		k.AddKey(key.Fqdn, &key)
	}

	slog.Debug("keys list", "keys", k.store)

	return k
}

// WithTimeout sets the timeout duration for TLS connections when fetching domain certificates.
func WithTimeout(d time.Duration) Option {
	return func(k *Keys) {
		k.timeout = d
	}
}

// WithCollector sets the Prometheus metrics collector for tracking key operations and errors.
func WithCollector(c *metrics.Collector) Option {
	return func(k *Keys) {
		k.collector = c
	}
}

// WithDumpInterval sets the interval for periodic persistence of keys to storage.
func WithDumpInterval(d time.Duration) Option {
	return func(k *Keys) {
		k.dumpInterval = d
	}
}

// WithFlushFunc sets the callback function used to persist keys to storage during periodic dumps.
func WithFlushFunc(f func(map[string]types.DomainKey) error) Option {
	return func(k *Keys) {
		k.flushFunc = f
	}
}

// Option is a functional option type for configuring Keys instance.
type Option func(*Keys)

// Keys manages a collection of domain keys with concurrent access and automatic certificate updates.
// It maintains a map of domain keys, runs background workers for each domain to fetch SSL certificates,
// collects metrics, and periodically persists keys to storage.
type Keys struct {
	ctx context.Context
	mu  sync.RWMutex

	store   map[string]*types.DomainKey
	workers map[string]context.CancelFunc

	collector    *metrics.Collector
	dumpInterval time.Duration
	flushFunc    func(map[string]types.DomainKey) error
	timeout      time.Duration
}

// Set stores or updates a domain key in the collection with thread-safe write access.
func (k *Keys) Set(key string, v types.DomainKey) {
	k.mu.Lock()
	defer k.mu.Unlock()

	slog.Debug("set key", "key", key)

	k.store[key] = &v
}

// Get retrieves a domain key by its FQDN with thread-safe read access.
// Returns the domain key and a boolean indicating whether the key was found.
func (k *Keys) Get(key string) (types.DomainKey, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	v, ok := k.store[key]
	if !ok || v == nil {
		return types.DomainKey{}, false
	}

	return *v, ok
}

// Snapshot creates a thread-safe copy of all domain keys in the collection.
// Returns a map of FQDN to DomainKey values, safe for use without holding locks.
func (k *Keys) Snapshot() map[string]types.DomainKey {
	k.mu.RLock()
	defer k.mu.RUnlock()

	out := make(map[string]types.DomainKey, len(k.store))
	for fqdn, ptr := range k.store {
		out[fqdn] = *ptr
	}
	return out
}

// AddKey adds a domain key to the collection and starts a background worker for it.
// If a worker for this FQDN already exists, it skips worker creation.
// The worker continuously fetches and updates the SSL certificate for the domain.
func (k *Keys) AddKey(fqdn string, key *types.DomainKey) {
	k.Set(fqdn, *key)

	if _, exists := k.workers[fqdn]; exists {
		return
	}

	ctx, cancel := context.WithCancel(k.ctx)
	k.workers[fqdn] = cancel

	go k.worker(ctx, key)
}

// fetchDomainKey establishes a TLS connection to the domain and extracts its SSL certificate.
// It computes the SHA-256 hash of the certificate's public key and returns it base64-encoded
// along with the certificate's expiration time in seconds.
// Returns an error if connection fails or certificate cannot be processed.
func (k *Keys) fetchDomainKey(fqdn string) (*types.DomainKey, error) {
	dialer := &net.Dialer{
		Timeout: k.timeout,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", fqdn+":443", &tls.Config{
		ServerName: fqdn,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		slog.Error("Failed to marshal public key", "error", err, "fqdn", fqdn)
		return nil, err
	}

	hash := sha256.Sum256(pubKeyBytes)

	return &types.DomainKey{
		Expire: int64(time.Until(cert.NotAfter).Seconds()),
		Key:    base64.StdEncoding.EncodeToString(hash[:]),
	}, nil
}

// worker is a background goroutine that periodically fetches and updates SSL certificate for a domain.
// It runs every second, fetches the domain's certificate, updates the key with new expiration and hash,
// tracks errors in metrics, and continues until the context is cancelled.
func (k *Keys) worker(ctx context.Context, key *types.DomainKey) {
	slog.Info("starting key worker", "fqdn", key.Fqdn)

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	k.collector.ClearError(key.File)

	for {
		select {
		case <-ctx.Done():
			slog.Info("key worker stopping", "fqdn", key.Fqdn)
			return
		case <-ticker.C:
			cur := time.Now()

			val, _ := k.Get(key.Fqdn)
			val.Date = &cur

			if res, err := k.fetchDomainKey(key.Fqdn); err == nil {
				val.Expire = res.Expire
				val.Key = res.Key
				val.LastError = ""

				k.collector.SetExpire(res.Key, key.Fqdn, float64(res.Expire))
			} else {
				slog.Error("failed to fetch domain key", "fqdn", key.Fqdn, "err", err)

				val.LastError = err.Error()
				k.collector.IncError(key.File)
			}

			k.Set(key.Fqdn, val)

			slog.Debug("updated domain key", "fqdn", key.Fqdn)
		}
	}
}

// StartPeriodicFlush runs a background loop that periodically persists all domain keys to storage.
// It creates a snapshot of current keys and calls the configured flush function at intervals
// specified by dumpInterval. Continues until the context is cancelled.
func (k *Keys) StartPeriodicFlush() {
	slog.Info("starting periodic flush", "interval", k.dumpInterval.Seconds())

	ticker := time.NewTicker(k.dumpInterval)
	defer ticker.Stop()

	for {
		select {
		case <-k.ctx.Done():
			slog.Info("stopping periodic flush")
			return
		case <-ticker.C:
			list := k.Snapshot()

			slog.Debug("StartPeriodicFlush", "keys_count", len(list), "keys", list)

			if err := k.flushFunc(list); err != nil {
				slog.Error("failed to flush keys", "err", err)
			} else {
				slog.Debug("successfully flushed keys")
			}
		}
	}
}
