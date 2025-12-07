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
package filesystem

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ssl-pinning/internal/signer"
	"ssl-pinning/internal/storage/types"
)

// New creates and initializes a new filesystem-based storage backend.
// It creates the dump directory if it doesn't exist with 0700 permissions.
// Returns an error if directory creation fails.
func New(ctx context.Context, opts ...types.Option) (types.Storage, error) {
	s := new(Storage)

	for _, opt := range opts {
		opt(s)
	}

	// if s.dumpInterval < 1 {
	// 	s.dumpInterval = 15 * time.Second
	// }

	if err := os.MkdirAll(s.dumpDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create dump directory: %w", err)
	}

	return s, nil
}

// Storage implements the types.Storage interface using filesystem for persistence.
// Keys are stored as signed JSON files in the dump directory, with atomic writes
// using temporary files and rename operations to ensure consistency.
type Storage struct {
	appID   string
	dumpDir string
	signer  *signer.Signer
	// dumpInterval time.Duration
}

// WithAppID sets the application ID for this storage instance.
func (s *Storage) WithAppID(appID string) {
	s.appID = appID
}

// WithDSN is a no-op for filesystem storage as it doesn't use database connections.
func (s *Storage) WithDSN(dsn string) {
	// no-op for this storage
}

// WithDumpDir sets the directory path where JSON files will be stored.
func (s *Storage) WithDumpDir(dumpDir string) {
	s.dumpDir = dumpDir
}

// WithDumpInterval is currently not used for filesystem storage.
// func (s *Storage) WithDumpInterval(dumpInterval time.Duration) {
// 	s.dumpInterval = dumpInterval
// }

// WithSigner sets the cryptographic signer used to sign JSON files before writing.
func (s *Storage) WithSigner(signer *signer.Signer) {
	s.signer = signer
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

// SaveKeys persists domain keys to filesystem as signed JSON files.
// Keys are grouped by file name, signed using the configured signer,
// and written atomically to prevent corruption. Keys with empty Key field are skipped.
func (s *Storage) SaveKeys(keys map[string]types.DomainKey) error {
	errs := make([]error, 0)

	files := make(map[string][]types.DomainKey)
	for _, key := range keys {
		if key.Key == "" {
			errs = append(errs, fmt.Errorf("empty key for fqdn=%q domain=%q file=%q",
				key.Fqdn, key.DomainName, key.File))
			continue
		}

		f := key.File

		key.File = ""

		files[f] = append(files[f], key)
	}

	for file, keys := range files {
		data, err := types.SignedKeys(file, keys, s.signer)
		if err != nil {
			slog.Error("failed signing keys", "file", file, "error", err)
			errs = append(errs, fmt.Errorf("failed signing keys for file %s: %w", file, err))
			continue
		}

		if err := s.saveFile(file, data); err != nil {
			slog.Error("failed to save file", "file", file, "error", err)
			errs = append(errs, fmt.Errorf("failed to save file %s: %w", file, err))
			continue
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to save some files: %v", errs)
	}

	return nil
}

// GetByFile reads and returns the contents of a JSON file from the dump directory.
// Returns the raw file data suitable for HTTP response.
// Returns an error if the file doesn't exist or cannot be read.
func (s *Storage) GetByFile(file string) ([]types.DomainKey, []byte, error) {
	f := fmt.Sprintf("%s/%s", s.dumpDir, file)

	if data, err := os.ReadFile(f); err == nil {
		return nil, data, nil
	} else {
		slog.Error("GetByFile: read file", "file", file, "error", err)
		return nil, nil, fmt.Errorf("file %s not found", file)
	}
}

// Close is a no-op for filesystem storage as there are no connections to close.
func (s *Storage) Close() error {
	return nil
}

// saveFile writes data to a file atomically using a temporary file.
// Steps:
//  1. Creates a temporary file in the dump directory
//  2. Writes data to the temporary file
//  3. Syncs to disk (fsync)
//  4. Renames temporary file to target file (atomic operation)
//
// This ensures the file is never partially written or corrupted.
func (s *Storage) saveFile(file string, data []byte) error {
	tmpFile, err := os.CreateTemp(s.dumpDir, fmt.Sprintf(".%s.tmp-*", file))
	file = fmt.Sprintf("%s/%s", s.dumpDir, file)

	if err != nil {
		return fmt.Errorf("DumpFile: create temp file: %w", err)
	}
	defer func() { os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return fmt.Errorf("DumpFile: write temp file: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("DumpFile: fsync temp file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("DumpFile: close temp file: %w", err)
	}

	if err := os.Rename(tmpFile.Name(), file); err != nil {
		return fmt.Errorf("DumpFile: rename %s -> %s: %w", tmpFile.Name(), file, err)
	}

	return nil
}

// ProbeLiveness returns an HTTP handler for Kubernetes liveness probe.
// It checks that:
//   - Dump directory is readable
//   - At least one JSON file exists
//   - Files can be parsed as valid JSON
//   - Keys contain valid data and no errors
//   - At least one key has been updated within maxAge (10 seconds)
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
				slog.Warn("liveness: NOT alive",
					"appID", s.appID,
					"dumpDir", s.dumpDir,
					"errors", errs,
					"freshKeys", freshKeys,
				)

				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(strings.Join(errs, "\n")))
				return
			}

			slog.Debug("liveness: OK",
				"appID", s.appID,
				"dumpDir", s.dumpDir,
				"freshKeys", freshKeys,
			)
			w.WriteHeader(http.StatusOK)
		}()

		entries, err := os.ReadDir(s.dumpDir)
		if err != nil {
			errs = append(errs,
				fmt.Sprintf("failed to read dump dir %q: %v", s.dumpDir, err))
			return
		}

		if len(entries) == 0 {
			errs = append(errs, "no dump files found")
			return
		}

		for _, e := range entries {
			if e.IsDir() {
				continue
			}

			path := filepath.Join(s.dumpDir, e.Name())

			raw, err := os.ReadFile(path)
			if err != nil {
				errs = append(errs,
					fmt.Sprintf("failed to read file %q: %v", path, err))
				continue
			}

			var data types.FileStructure
			if err := json.Unmarshal(raw, &data); err != nil {
				errs = append(errs,
					fmt.Sprintf("failed to unmarshal file %q: %v", path, err))
				continue
			}

			if len(data.Payload.Keys) == 0 {
				errs = append(errs,
					fmt.Sprintf("no keys in file (%s)", e.Name()))
				continue
			}

			for _, k := range data.Payload.Keys {
				if k.LastError != "" {
					errs = append(errs,
						fmt.Sprintf("key for %s (%s) has last_error: %s",
							k.Fqdn, k.DomainName, k.LastError))
					continue
				}

				// date
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
		}

		if freshKeys == 0 {
			errs = append(errs, "no fresh keys found")
		}
	}
}

// ProbeReadiness returns an HTTP handler for Kubernetes readiness probe.
// It checks that:
//   - Dump directory is readable
//   - At least one file exists
//   - At least one file has been modified within maxAge (10 seconds)
//
// Returns 503 Service Unavailable if any check fails, 200 OK if all checks pass.
func (s *Storage) ProbeReadiness() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		const maxAge = 10 * time.Second

		now := time.Now()
		errs := make([]string, 0)

		defer func() {
			if len(errs) > 0 {
				slog.Warn("readiness: NOT ready",
					"appID", s.appID,
					"dumpDir", s.dumpDir,
					"errors", errs,
				)

				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(strings.Join(errs, "\n")))
				return
			}

			slog.Debug("readiness: OK",
				"appID", s.appID,
				"dumpDir", s.dumpDir,
			)
			w.WriteHeader(http.StatusOK)
		}()

		entries, err := os.ReadDir(s.dumpDir)
		if err != nil {
			errs = append(errs,
				fmt.Sprintf("failed to read dump dir %q: %v", s.dumpDir, err))
			return
		}

		if len(entries) == 0 {
			errs = append(errs, "no dump files found")
			return
		}

		for _, e := range entries {
			info, err := e.Info()
			if err != nil {
				errs = append(errs,
					fmt.Sprintf("failed to get file info for %q: %v", e.Name(), err))
				continue
			}

			if now.Sub(info.ModTime()) >= maxAge {
				errs = append(errs,
					fmt.Sprintf("no dump files newer than %s", maxAge))
			}
		}
	}
}

// ProbeStartup returns an HTTP handler for Kubernetes startup probe.
// Always returns 200 OK as filesystem storage requires no initialization time.
func (s *Storage) ProbeStartup() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
}
