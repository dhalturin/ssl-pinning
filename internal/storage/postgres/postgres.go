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
package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	_ "github.com/lib/pq"

	"ssl-pinning/internal/signer"
	"ssl-pinning/internal/storage/postgres/migrations"
	"ssl-pinning/internal/storage/types"
)

// New creates and initializes a new PostgreSQL storage backend.
// It opens a connection to PostgreSQL using the provided DSN, validates connectivity,
// and runs database migrations to ensure the schema is up to date.
// Returns an error if connection fails or migrations cannot be applied.
func New(ctx context.Context, opts ...types.Option) (types.Storage, error) {
	s := new(Storage)

	for _, opt := range opts {
		opt(s)
	}

	// if s.dumpInterval < 1 {
	// 	s.dumpInterval = 15 * time.Second
	// }

	db, err := sql.Open("postgres", s.dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open postgres dsn: %w", err)
	}

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to postgres: %w", err)
	}

	if err := migrations.Up(db); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	db.SetConnMaxIdleTime(s.connMaxIdleTime)
	db.SetConnMaxLifetime(s.connMaxLifetime)
	db.SetMaxIdleConns(s.maxIdleConns)
	db.SetMaxOpenConns(s.maxOpenConns)

	s.client = db
	s.ctx = ctx

	return s, nil
}

// Storage implements the types.Storage interface using PostgreSQL as the backend.
// It stores domain keys in the domain_keys table with automatic conflict resolution
// on (app_id, file, fqdn) composite key.
type Storage struct {
	ctx             context.Context
	appID           string
	client          *sql.DB
	dsn             string
	signer          *signer.Signer
	connMaxIdleTime time.Duration
	connMaxLifetime time.Duration
	maxIdleConns    int
	maxOpenConns    int
	// dumpInterval time.Duration
}

// WithAppID sets the application ID for this storage instance.
func (s *Storage) WithAppID(appID string) {
	s.appID = appID
}

// WithDSN sets the PostgreSQL connection string (DSN).
func (s *Storage) WithDSN(dsn string) {
	s.dsn = dsn
}

// WithDumpDir is a no-op for PostgreSQL storage as it doesn't use file dumps.
func (s *Storage) WithDumpDir(dumpDir string) {
	// no-op for this storage
}

// WithDumpInterval is a no-op for PostgreSQL storage as persistence is automatic.
// func (s *Storage) WithDumpInterval(dumpInterval time.Duration) {
// 	s.dumpInterval = dumpInterval
// }

// WithSigner is a no-op for PostgreSQL storage as signing is handled at a higher level.
func (s *Storage) WithSigner(signer *signer.Signer) {
	// no-op for this storage
}

// WithConnMaxIdleTime returns an option that sets the maximum amount of time a connection may be idle.
func (s *Storage) WithConnMaxIdleTime(d time.Duration) {
	s.connMaxIdleTime = d
}

// WithConnMaxLifetime returns an option that sets the maximum amount of time a connection may be reused.
func (s *Storage) WithConnMaxLifetime(d time.Duration) {
	s.connMaxLifetime = d
}

// WithMaxIdleConns returns an option that sets the maximum number of connections in the idle connection pool.
func (s *Storage) WithMaxIdleConns(n int) {
	s.maxIdleConns = n
}

// WithMaxOpenConns returns an option that sets the maximum number of open connections to the database.
func (s *Storage) WithMaxOpenConns(n int) {
	s.maxOpenConns = n
}

// SaveKeys persists a map of domain keys to PostgreSQL in a single transaction.
// Uses INSERT ... ON CONFLICT DO UPDATE to handle duplicate keys gracefully.
// The composite unique key is (app_id, file, fqdn).
// Rolls back the transaction if any insert fails.
func (s *Storage) SaveKeys(keys map[string]types.DomainKey) error {
	tx, err := s.client.BeginTx(s.ctx, nil)
	if err != nil {
		slog.Error("failed to begin tx", "error", err)
		return err
	}

	const q = `
INSERT INTO domain_keys (
    app_id,
    date,
    domain_name,
    expire,
    file,
    fqdn,
    key,
    last_error
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (app_id, file, fqdn) DO UPDATE
SET
    date        = EXCLUDED.date,
    domain_name = EXCLUDED.domain_name,
    expire      = EXCLUDED.expire,
    key         = EXCLUDED.key,
    last_error  = EXCLUDED.last_error,
    updated_at  = now();
`

	stmt, err := tx.PrepareContext(s.ctx, q)
	if err != nil {
		slog.Error("failed to prepare stmt", "error", err)
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()

	for _, k := range keys {
		if _, err := stmt.ExecContext(
			s.ctx,
			s.appID,
			k.Date,
			k.DomainName,
			k.Expire,
			k.File,
			k.Fqdn,
			k.Key,
			k.LastError,
		); err != nil {
			slog.Error("failed to save key to postgres", "error", err, "key", k)
			_ = tx.Rollback()
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		slog.Error("failed to commit tx", "error", err)
		return err
	}
	return nil
}

// GetByFile retrieves domain keys for a specific file from PostgreSQL.
// Uses DISTINCT ON (fqdn) to return only the earliest expiring key per FQDN.
// Filters out empty keys and returns nil if no valid keys are found.
func (s *Storage) GetByFile(file string) ([]types.DomainKey, []byte, error) {
	slog.Debug("postgres connection infromation", "stats", s.client.Stats())

	const q = `
SELECT DISTINCT ON (fqdn)
       date,
       domain_name,
       expire,
       fqdn,
       key,
       last_error
FROM domain_keys
WHERE file = $1
  AND key <> ''
ORDER BY fqdn, expire ASC
`

	rows, err := s.client.QueryContext(s.ctx, q, file)
	if err != nil {
		slog.Error("failed to query domain_keys by file", "error", err, "file", file)
		return nil, nil, fmt.Errorf("failed to query keys from postgres")
	}
	defer rows.Close()

	var result []types.DomainKey

	for rows.Next() {
		var (
			dk        types.DomainKey
			dateNT    sql.NullTime
			lastErrNS sql.NullString
		)

		if err := rows.Scan(
			&dateNT,
			&dk.DomainName,
			&dk.Expire,
			&dk.Fqdn,
			&dk.Key,
			&lastErrNS,
		); err != nil {
			slog.Error("failed to scan row", "error", err)
			return nil, nil, fmt.Errorf("failed to scan row")
		}

		if dk.Key == "" {
			// защитный случай, хотя уже фильтруем в WHERE
			continue
		}

		if dateNT.Valid {
			dk.Date = &dateNT.Time
		}

		if lastErrNS.Valid {
			dk.LastError = lastErrNS.String
		}

		result = append(result, dk)
	}

	if err := rows.Err(); err != nil {
		slog.Error("rows error", "error", err)
		return nil, nil, fmt.Errorf("failed to read rows")
	}

	slog.Debug("selected best keys by file", "file", file, "keys", result)

	return result, nil, nil
}

// Close releases PostgreSQL database connection resources.
// Logs any errors but always returns nil to satisfy the Storage interface.
func (s *Storage) Close() error {
	slog.Warn("closing postgres storage")
	return s.client.Close()
}

// ProbeLiveness returns an HTTP handler for Kubernetes liveness probe.
// It checks that:
//   - PostgreSQL is accessible
//   - Keys exist for the current appID
//   - At least one key has been updated within maxAge (10 seconds)
//   - Keys have no errors and contain valid data
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
					"errors", errs,
					"storage", "postgres",
				)

				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(strings.Join(errs, "\n")))
				return
			}

			slog.Debug("liveness: OK",
				"appID", s.appID,
				"freshKeys", freshKeys,
				"storage", "postgres",
			)
			w.WriteHeader(http.StatusOK)
		}()

		const q = `
SELECT
    date,
    domain_name,
    expire,
    file,
    fqdn,
    key,
    last_error
FROM domain_keys
WHERE app_id = $1
  AND key <> ''
`
		rows, err := s.client.QueryContext(s.ctx, q, s.appID)
		if err != nil {
			errs = append(errs, fmt.Sprintf("failed to query postgres: %v", err))
			return
		}
		defer rows.Close()

		for rows.Next() {
			var (
				k         types.DomainKey
				dateNT    sql.NullTime
				lastErrNS sql.NullString
			)

			if err := rows.Scan(
				&dateNT,
				&k.DomainName,
				&k.Expire,
				&k.File,
				&k.Fqdn,
				&k.Key,
				&lastErrNS,
			); err != nil {
				errs = append(errs, fmt.Sprintf("failed to scan row: %v", err))
				continue
			}

			if k.Key == "" {
				errs = append(errs,
					fmt.Sprintf("empty key for fqdn=%q domain=%q file=%q",
						k.Fqdn, k.DomainName, k.File),
				)
				continue
			}

			if lastErrNS.Valid {
				k.LastError = lastErrNS.String
			}

			if k.LastError != "" {
				errs = append(errs,
					fmt.Sprintf("key for %s (%s) has last_error: %s",
						k.Fqdn, k.DomainName, k.LastError))
				continue
			}

			if !dateNT.Valid {
				errs = append(errs,
					fmt.Sprintf("missing date for key %s (%s)",
						k.Fqdn, k.DomainName))
				continue
			}

			k.Date = &dateNT.Time

			age := now.Sub(*k.Date)
			if age >= maxAge {
				errs = append(errs,
					fmt.Sprintf("key for %s (%s) appears stale (age=%s >= %s)",
						k.Fqdn, k.DomainName, age, maxAge))
				continue
			}

			freshKeys++
		}

		if err := rows.Err(); err != nil {
			errs = append(errs, fmt.Sprintf("rows error: %v", err))
			return
		}

		if freshKeys == 0 {
			errs = append(errs, "no fresh keys found in postgres")
		}
	}
}

// ProbeReadiness returns an HTTP handler for Kubernetes readiness probe.
// It checks that:
//   - PostgreSQL is accessible
//   - Keys exist for the current appID
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
				slog.Warn("readiness: NOT ready",
					"appID", s.appID,
					"errors", errs,
					"storage", "postgres",
				)

				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(strings.Join(errs, "\n")))
				return
			}

			slog.Debug("readiness: OK",
				"appID", s.appID,
				"storage", "postgres",
				"validKeys", validKeys,
			)
			w.WriteHeader(http.StatusOK)
		}()

		const q = `
SELECT
    date,
    domain_name,
    expire,
    file,
    fqdn,
    key,
    last_error
FROM domain_keys
WHERE app_id = $1
  AND key <> ''
`
		rows, err := s.client.QueryContext(s.ctx, q, s.appID)
		if err != nil {
			errs = append(errs, fmt.Sprintf("failed to query postgres: %v", err))
			return
		}
		defer rows.Close()

		for rows.Next() {
			var (
				k         types.DomainKey
				dateNT    sql.NullTime
				lastErrNS sql.NullString
			)

			if err := rows.Scan(
				&dateNT,
				&k.DomainName,
				&k.Expire,
				&k.File,
				&k.Fqdn,
				&k.Key,
				&lastErrNS,
			); err != nil {
				errs = append(errs, fmt.Sprintf("failed to scan row: %v", err))
				continue
			}

			if k.Key == "" {
				errs = append(errs,
					fmt.Sprintf("empty key for fqdn=%q domain=%q file=%q",
						k.Fqdn, k.DomainName, k.File))
				continue
			}
			if !dateNT.Valid {
				errs = append(errs,
					fmt.Sprintf("missing date for fqdn=%s file=%s", k.Fqdn, k.File))
				continue
			}

			validKeys++
		}

		if err := rows.Err(); err != nil {
			errs = append(errs, fmt.Sprintf("rows error: %v", err))
			return
		}

		if validKeys == 0 {
			errs = append(errs, "no valid keys found in postgres")
		}
	}
}

// ProbeStartup returns an HTTP handler for Kubernetes startup probe.
// Always returns 200 OK as PostgreSQL storage initialization is handled in New().
func (s *Storage) ProbeStartup() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
}
