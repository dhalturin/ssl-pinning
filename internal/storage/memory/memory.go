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
package memory

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"ssl-pinning/internal/signer"
	"ssl-pinning/internal/storage/types"
)

// New creates and initializes a new in-memory storage backend.
// This storage is ephemeral and all data is lost when the process terminates.
// Suitable for testing or development environments where persistence is not required.
func New(ctx context.Context, opts ...types.Option) (types.Storage, error) {
	s := new(Storage)

	for _, opt := range opts {
		opt(s)
	}

	// if s.dumpInterval < 1 {
	// 	s.dumpInterval = 15 * time.Second
	// }

	return s, nil
}

// Storage implements the types.Storage interface using in-memory map storage.
// All data is stored in RAM and is lost when the application restarts.
// Keys are indexed by FQDN for fast lookup.
type Storage struct {
	appID  string
	keys   map[string]types.DomainKey
	signer *signer.Signer
	// dumpInterval time.Duration
}

// WithAppID sets the application ID for this storage instance.
func (s *Storage) WithAppID(appID string) {
	s.appID = appID
}

// WithDSN is a no-op for in-memory storage as it doesn't use external connections.
func (s *Storage) WithDSN(dsn string) {
	// no-op for this storage
}

// WithDumpDir is a no-op for in-memory storage as it doesn't persist to disk.
func (s *Storage) WithDumpDir(dumpDir string) {
	// no-op for this storage
}

// WithDumpInterval is a no-op for in-memory storage as persistence is not supported.
// func (s *Storage) WithDumpInterval(dumpInterval time.Duration) {
// 	s.dumpInterval = dumpInterval
// }

// WithSigner is a no-op for in-memory storage as signing is handled at a higher level.
func (s *Storage) WithSigner(signer *signer.Signer) {
	// no-op for this storage
}

// WithConnMaxIdleTime returns an option that sets the maximum amount of time a connection may be idle.
func (s *Storage) WithConnMaxIdleTime(d time.Duration) {
	// no-op for this storage
}

// WithConnMaxLifetime returns an option that sets the maximum amount of time a connection may be reused.
func (s *Storage) WithConnMaxLifetime(d time.Duration) {
	// no-op for this storage
}

// WithMaxIdleConns returns an option that sets the maximum number of connections in the idle connection pool.
func (s *Storage) WithMaxIdleConns(n int) {
	// no-op for this storage
}

// WithMaxOpenConns returns an option that sets the maximum number of open connections to the database.
func (s *Storage) WithMaxOpenConns(n int) {
	// no-op for this storage
}

// SaveKeys stores domain keys in memory, indexed by FQDN.
// Keys with empty Key field are skipped. This operation replaces all existing keys.
func (s *Storage) SaveKeys(keys map[string]types.DomainKey) error {
	errs := make([]error, 0)

	list := make(map[string]types.DomainKey, len(keys))
	for _, key := range keys {
		if key.Key == "" {
			errs = append(errs, fmt.Errorf("empty key for fqdn=%q domain=%q file=%q",
				key.Fqdn, key.DomainName, key.File))
			continue
		}

		list[key.Fqdn] = key
	}
	s.keys = list

	if len(errs) > 0 {
		return fmt.Errorf("failed to save some keys: %v", errs)
	}

	return nil
}

// GetByFile retrieves all domain keys associated with a specific file from memory.
// The File field is cleared in returned keys to avoid redundancy.
// Returns empty slice if no matching keys are found.
func (s *Storage) GetByFile(file string) ([]types.DomainKey, []byte, error) {
	keys := []types.DomainKey{}

	for _, key := range s.keys {
		if key.Key == "" {
			continue
		}

		if key.File == file {
			key.File = ""

			keys = append(keys, key)
		}
	}

	return keys, nil, nil
}

// Close is a no-op for in-memory storage as there are no resources to release.
func (s *Storage) Close() error {
	return nil
}

// ProbeLiveness returns an HTTP handler for Kubernetes liveness probe.
// It checks that:
//   - Keys exist in memory
//   - At least one key has been updated within maxAge (10 seconds)
//   - Keys contain required fields (key, date) and have no errors
//
// Returns 503 Service Unavailable if any check fails, 200 OK if all checks pass.
func (s *Storage) ProbeLiveness() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		const maxAge = 10 * time.Second

		now := time.Now()
		errs := make([]string, 0)
		freshKeys := 0

		defer func() {
			if len(errs) > 0 {
				slog.Warn("liveness: NOT alive (memory)",
					"appID", s.appID,
					"errors", errs,
					"freshKeys", freshKeys,
				)

				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(strings.Join(errs, "\n")))
				return
			}

			slog.Debug("liveness: OK (memory)",
				"appID", s.appID,
				"freshKeys", freshKeys,
			)
			w.WriteHeader(http.StatusOK)
		}()

		if len(s.keys) == 0 {
			errs = append(errs, "no keys in memory")
			return
		}

		for _, k := range s.keys {
			if k.Key == "" {
				errs = append(errs,
					fmt.Sprintf("empty key for fqdn=%q domain=%q file=%q",
						k.Fqdn, k.DomainName, k.File),
				)
				continue
			}

			if k.Date == nil {
				errs = append(errs,
					fmt.Sprintf("missing date for key %s (%s)",
						k.Fqdn, k.DomainName))
				continue
			}

			age := now.Sub(*k.Date)
			if age >= maxAge {
				errs = append(errs,
					fmt.Sprintf("key for %s (%s) appears stale (age=%s >= %s)",
						k.Fqdn, k.DomainName, age, maxAge))
				continue
			}

			freshKeys++
		}

		if freshKeys == 0 {
			errs = append(errs, "no fresh keys found in memory")
		}
	}
}

// ProbeReadiness returns an HTTP handler for Kubernetes readiness probe.
// It checks that:
//   - Keys exist in memory
//   - Keys contain required fields (key, date, fqdn)
//   - At least one valid key is present
//
// Returns 503 Service Unavailable if any check fails, 200 OK if all checks pass.
func (s *Storage) ProbeReadiness() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		errs := make([]string, 0)
		validKeys := 0

		defer func() {
			if len(errs) > 0 {
				slog.Warn("readiness: NOT ready (memory)",
					"appID", s.appID,
					"errors", errs,
					"validKeys", validKeys,
				)

				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(strings.Join(errs, "\n")))
				return
			}

			slog.Debug("readiness: OK (memory)",
				"appID", s.appID,
				"validKeys", validKeys,
			)
			w.WriteHeader(http.StatusOK)
		}()

		if len(s.keys) == 0 {
			errs = append(errs, "no keys in memory")
			return
		}

		for _, k := range s.keys {
			if k.Key == "" {
				errs = append(errs,
					fmt.Sprintf("empty key for fqdn=%q domain=%q file=%q",
						k.Fqdn, k.DomainName, k.File))
				continue
			}

			if k.Date == nil {
				errs = append(errs,
					fmt.Sprintf("missing date for key fqdn=%q domain=%q file=%q",
						k.Fqdn, k.DomainName, k.File))
				continue
			}

			validKeys++
		}

		if validKeys == 0 {
			errs = append(errs, "no valid keys in memory")
		}
	}
}

// ProbeStartup returns an HTTP handler for Kubernetes startup probe.
// Always returns 200 OK as in-memory storage requires no initialization time.
func (s *Storage) ProbeStartup() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
}
