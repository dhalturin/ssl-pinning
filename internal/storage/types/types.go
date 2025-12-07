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
package types

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"ssl-pinning/internal/signer"
)

// DomainKey represents a domain's SSL certificate pinning information.
// It contains the certificate's public key hash, expiration time, associated domain details,
// and metadata such as application ID, last update timestamp, and error information.
type DomainKey struct {
	AppID      string     `json:"app_id,omitempty"`
	Date       *time.Time `json:"date,omitempty"`
	DomainName string     `json:"domainName,omitempty"`
	Expire     int64      `json:"expire,omitempty"`
	File       string     `json:"file,omitempty"`
	Fqdn       string     `json:"fqdn,omitempty"`
	Key        string     `json:"key,omitempty"`
	LastError  string     `json:"last_error,omitempty"`
}

// FileStructure represents the JSON file format for signed domain keys.
// It wraps the payload (keys) along with a cryptographic signature for integrity verification.
type FileStructure struct {
	Payload   FileKeys `json:"payload,omitempty"`
	Signature string   `json:"signature,omitempty"`
}

// FileKeys contains a collection of domain keys for a specific file.
type FileKeys struct {
	Keys []DomainKey `json:"keys,omitempty"`
}

// StorageType defines the type of storage backend to use.
type StorageType string

const (
	// StorageFS represents file system-based storage
	StorageFS StorageType = "fs"
	// StorageMemory represents in-memory ephemeral storage
	StorageMemory StorageType = "memory"
	// StorageRedis represents Redis-based storage
	StorageRedis StorageType = "redis"
	// StoragePostgres represents PostgreSQL database storage
	StoragePostgres StorageType = "postgres"
)

// Storage defines the interface for domain key storage backends.
// It provides methods for retrieving keys, health checks, persistence, and configuration.
type Storage interface {
	// Close releases storage resources and closes connections
	Close() error
	// GetByFile retrieves domain keys by filename
	GetByFile(string) ([]DomainKey, []byte, error)
	// ProbeLiveness returns an HTTP handler for liveness probe
	ProbeLiveness() func(w http.ResponseWriter, r *http.Request)
	// ProbeReadiness returns an HTTP handler for readiness probe
	ProbeReadiness() func(w http.ResponseWriter, r *http.Request)
	// ProbeStartup returns an HTTP handler for startup probe
	ProbeStartup() func(w http.ResponseWriter, r *http.Request)
	// SaveKeys persists a map of domain keys to storage
	SaveKeys(map[string]DomainKey) error
	// WithAppID sets the application ID for the storage instance
	WithAppID(string)
	// WithDSN sets the data source name (connection string) for the storage
	WithDSN(string)
	// WithDumpDir sets the directory path for file dumps
	WithDumpDir(string)
	// WithDumpInterval sets the interval for periodic dumps
	// WithDumpInterval(time.Duration)
	// WithSigner sets the cryptographic signer for signing keys
	WithSigner(*signer.Signer)
	// WithConnMaxIdleTime sets the maximum amount of time a connection may be idle
	WithConnMaxIdleTime(time.Duration)
	// WithConnMaxLifetime sets the maximum amount of time a connection may be reused
	WithConnMaxLifetime(time.Duration)
	// WithMaxIdleConns sets the maximum number of connections in the idle connection pool
	WithMaxIdleConns(int)
	// WithMaxOpenConns sets the maximum number of open connections to the database
	WithMaxOpenConns(int)
}

// Option is a functional option type for configuring Storage implementations.
type Option func(Storage)

// WithAppID returns an option that sets the application ID for the storage instance.
func WithAppID(appID string) Option {
	return func(s Storage) {
		s.WithAppID(appID)
	}
}

// WithDSN returns an option that sets the data source name (connection string) for the storage.
func WithDSN(dsn string) Option {
	return func(s Storage) {
		s.WithDSN(dsn)
	}
}

// WithDumpDir returns an option that sets the directory path for file-based storage dumps.
func WithDumpDir(dir string) Option {
	return func(s Storage) {
		s.WithDumpDir(dir)
	}
}

// WithDumpInterval returns an option that sets the interval for periodic persistence of keys to storage.
// func WithDumpInterval(interval time.Duration) Option {
// 	return func(s Storage) {
// 		s.WithDumpInterval(interval)
// 	}
// }

// WithSigner returns an option that sets the cryptographic signer for signing domain keys.
func WithSigner(signer *signer.Signer) Option {
	return func(s Storage) {
		s.WithSigner(signer)
	}
}

// WithConnMaxIdleTime returns an option that sets the maximum amount of time a connection may be idle.
func WithConnMaxIdleTime(d time.Duration) Option {
	return func(s Storage) {
		s.WithConnMaxIdleTime(d)
	}
}

// WithConnMaxLifetime returns an option that sets the maximum amount of time a connection may be reused.
func WithConnMaxLifetime(d time.Duration) Option {
	return func(s Storage) {
		s.WithConnMaxLifetime(d)
	}
}

// WithMaxIdleConns returns an option that sets the maximum number of connections in the idle connection pool.
func WithMaxIdleConns(n int) Option {
	return func(s Storage) {
		s.WithMaxIdleConns(n)
	}
}

// WithMaxOpenConns returns an option that sets the maximum number of open connections to the database.
func WithMaxOpenConns(n int) Option {
	return func(s Storage) {
		s.WithMaxOpenConns(n)
	}
}

// SignedKeys creates a signed JSON structure containing domain keys for a file.
// It performs the following steps:
//  1. Validates that keys are provided
//  2. Sorts keys by expiration time (ascending)
//  3. Marshals keys to indented JSON
//  4. Signs the JSON using the provided signer
//  5. Wraps payload and signature into FileStructure
//
// Returns the final JSON bytes or an error if any step fails.
func SignedKeys(file string, keys []DomainKey, signer *signer.Signer) ([]byte, error) {
	if len(keys) < 1 {
		slog.Warn("SignedKeys - no keys to save", "file", file)
		return nil, nil
	}

	sort.Slice(keys, func(i, j int) bool {
		return keys[i].Expire < keys[j].Expire
	})

	payload := FileKeys{
		Keys: keys,
	}

	out := []byte{}

	if res, err := json.MarshalIndent(payload, "", "  "); err == nil {
		out = res
	} else {
		return nil, fmt.Errorf("SignedKeys - failed to marshal keys to JSON: %w", err)
	}

	sig, err := signer.Sign(out)
	if err != nil {
		return nil, fmt.Errorf("SignedKeys - failed to sign data: %w", err)
	}

	slog.Debug("signature created",
		"canonical", string(out),
		"file", file,
		"sig", string(sig),
	)

	if res, err := json.MarshalIndent(FileStructure{
		Payload:   payload,
		Signature: string(sig),
	}, "", "  "); err == nil {
		out = res
	} else {
		return nil, fmt.Errorf("SignedKeys - failed to marshal signed payload to JSON: %w", err)
	}

	return out, nil
}
