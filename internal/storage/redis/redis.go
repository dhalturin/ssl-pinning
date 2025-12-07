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
package redis

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/redis/go-redis/v9/maintnotifications"

	"ssl-pinning/internal/signer"
	"ssl-pinning/internal/storage/types"
)

// New creates and initializes a new Redis storage backend.
// It parses the DSN (Data Source Name) to configure Redis connection parameters including:
// - host and port
// - password authentication
// - database number
// - maintenance notifications mode
// Validates the connection with a ping and returns an error if connection fails.
//
// Example DSN: redis://user:password@localhost:6379/0?maintnotifications=enabled
func New(ctx context.Context, opts ...types.Option) (types.Storage, error) {
	s := new(Storage)

	for _, opt := range opts {
		opt(s)
	}

	s.ctx = ctx

	o := &redis.Options{
		ClientName:               s.appID,
		MaintNotificationsConfig: &maintnotifications.Config{},
	}

	u, err := url.Parse(s.dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to parse redis dsn: %w", err)
	}

	if mode := u.Query().Get("maintnotifications"); mode == "" {
		o.MaintNotificationsConfig.Mode = maintnotifications.ModeDisabled
	} else {
		o.MaintNotificationsConfig.Mode = maintnotifications.Mode(mode)
	}

	o.Addr = u.Host

	if u.User != nil {
		if password, ok := u.User.Password(); ok {
			o.Password = password
		}
	}

	if len(u.Path) > 1 {
		db, err := strconv.Atoi(u.Path[1:])
		if err != nil {
			return nil, err
		}
		o.DB = db
	}

	slog.Debug("initialized redis client", "raw;options", o, "raw;storage", s)

	s.client = redis.NewClient(o)

	if err := s.client.Ping(s.ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	return s, nil
}

// Storage implements the types.Storage interface using Redis as the backend.
// It stores domain keys as Redis hashes with composite keys (file:fqdn:appID).
type Storage struct {
	ctx    context.Context
	appID  string
	client *redis.Client
	dsn    string
	signer *signer.Signer
	// dumpInterval time.Duration
}

// WithAppID sets the application ID for this storage instance.
func (s *Storage) WithAppID(appID string) {
	s.appID = appID
}

// WithDSN sets the Redis connection string (DSN).
func (s *Storage) WithDSN(dsn string) {
	s.dsn = dsn
}

// WithDumpDir is a no-op for Redis storage as it doesn't use file dumps.
func (s *Storage) WithDumpDir(dumpDir string) {
	// no-op this storage
}

// WithDumpInterval sets the interval for periodic persistence operations.
// func (s *Storage) WithDumpInterval(dumpInterval time.Duration) {
// 	s.dumpInterval = dumpInterval
// }

// WithSigner is a no-op for Redis storage as signing is handled at a higher level.
func (s *Storage) WithSigner(signer *signer.Signer) {
	// no-op this storage
}

// WithConnMaxIdleTime returns an option that sets the maximum amount of time a connection may be idle.
func (s *Storage) WithConnMaxIdleTime(d time.Duration) {
	// no-op this storage
}

// WithConnMaxLifetime returns an option that sets the maximum amount of time a connection may be reused.
func (s *Storage) WithConnMaxLifetime(d time.Duration) {
	// no-op this storage
}

// WithMaxIdleConns returns an option that sets the maximum number of connections in the idle connection pool.
func (s *Storage) WithMaxIdleConns(n int) {
	// no-op this storage
}

// WithMaxOpenConns returns an option that sets the maximum number of open connections to the database.
func (s *Storage) WithMaxOpenConns(n int) {
	// no-op this storage
}

// SaveKeys persists a map of domain keys to Redis.
// Each key is stored as a Redis hash with composite key format: "file:fqdn:appID".
// Keys with empty Key field are skipped.
func (s *Storage) SaveKeys(keys map[string]types.DomainKey) error {
	errs := make([]error, 0)

	for _, key := range keys {
		if key.Key == "" {
			continue
		}

		hash := fmt.Sprintf("%s:%s:%s", key.File, key.Fqdn, s.appID)

		if err := s.client.HSet(s.ctx, hash,
			"date", key.Date,
			"domainName", key.DomainName,
			"expire", key.Expire,
			"file", key.File,
			"fqdn", key.Fqdn,
			"key", key.Key,
			"last_error", key.LastError,
		).Err(); err != nil {
			slog.Error("failed to save key to redis", "error", err, "key", key)
			errs = append(errs, err)
			continue
		}

		slog.Debug("saved key to redis", "hash", hash, "key", key)
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to save some keys: %v", errs)
	}

	return nil
}

// GetByFile retrieves all domain keys associated with a specific file from Redis.
// It searches for keys matching the pattern "file:*" and returns the best (earliest expiring)
// key for each unique FQDN. Returns empty slices if no keys are found.
func (s *Storage) GetByFile(file string) ([]types.DomainKey, []byte, error) {
	pattern := fmt.Sprintf("%s:*", file)

	list, err := s.client.Keys(s.ctx, pattern).Result()
	if err != nil {
		slog.Error("failed to get keys from redis", "error", err)
		return nil, nil, fmt.Errorf("failed to get keys from redis")
	}

	slog.Debug("getting keys by file", "keys", list, "file", file)

	if len(list) == 0 {
		return nil, nil, nil
	}

	pipe := s.client.Pipeline()
	cmds := make([]*redis.MapStringStringCmd, len(list))

	for i, k := range list {
		cmds[i] = pipe.HGetAll(s.ctx, k)
	}

	if _, err := pipe.Exec(s.ctx); err != nil {
		slog.Error("failed to execute pipeline", "error", err)
		return nil, nil, fmt.Errorf("failed to execute pipeline")
	}

	best := make(map[string]types.DomainKey)

	for _, cmd := range cmds {
		data, err := cmd.Result()
		if err != nil || len(data) == 0 {
			continue
		}

		if data["key"] == "" {
			continue
		}

		date, _ := time.Parse(time.RFC3339Nano, data["date"])
		expire, _ := strconv.ParseInt(data["expire"], 10, 64)

		k := types.DomainKey{
			Date:       &date,
			DomainName: data["domainName"],
			Expire:     expire,
			Fqdn:       data["fqdn"],
			Key:        data["key"],
			LastError:  data["last_error"],
		}

		fqdn := data["fqdn"]

		if prev, ok := best[fqdn]; !ok || k.Expire < prev.Expire {
			best[fqdn] = k
		}
	}

	keys := make([]types.DomainKey, 0, len(best))
	for _, v := range best {
		keys = append(keys, v)
	}

	slog.Debug("selected best keys by file", "file", file, "keys", keys)

	return keys, nil, nil
}

// Close releases Redis client resources. Currently a no-op but satisfies the Storage interface.
func (s *Storage) Close() error {
	return s.client.Close()
}

// ProbeLiveness returns an HTTP handler for Kubernetes liveness probe.
// It checks that:
//   - Redis is accessible
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
					"freshKeys", freshKeys,
					"storage", "redis",
				)

				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(strings.Join(errs, "\n")))
				return
			}

			slog.Debug("liveness: OK",
				"appID", s.appID,
				"freshKeys", freshKeys,
				"storage", "redis",
			)
			w.WriteHeader(http.StatusOK)
		}()

		pattern := fmt.Sprintf("*:*:%s", s.appID)

		list, err := s.client.Keys(s.ctx, pattern).Result()
		if err != nil {
			errs = append(errs, fmt.Sprintf("failed to query redis: %v", err))
			return
		}

		if len(list) == 0 {
			errs = append(errs, "no redis keys found for app")
			return
		}

		pipe := s.client.Pipeline()
		cmds := make([]*redis.MapStringStringCmd, len(list))

		for i, k := range list {
			cmds[i] = pipe.HGetAll(s.ctx, k)
		}

		if _, err := pipe.Exec(s.ctx); err != nil {
			errs = append(errs, fmt.Sprintf("redis pipeline error: %v", err))
			return
		}

		for _, cmd := range cmds {
			data, err := cmd.Result()
			if err != nil {
				errs = append(errs, fmt.Sprintf("HGetAll failed: %v", err))
				continue
			}

			if len(data) == 0 {
				errs = append(errs, "empty redis hash")
				continue
			}

			if data["key"] == "" {
				errs = append(errs,
					fmt.Sprintf("empty key for fqdn=%q domain=%q file=%q",
						data["fqdn"], data["domainName"], data["file"]),
				)
				continue
			}

			if data["last_error"] != "" {
				errs = append(errs,
					fmt.Sprintf("key for %s (%s) has last_error: %s",
						data["fqdn"], data["domainName"], data["last_error"]))
				continue
			}

			if data["date"] == "" {
				errs = append(errs,
					fmt.Sprintf("missing date for key %s (%s)",
						data["fqdn"], data["domainName"]))
				continue
			}

			t, err := time.Parse(time.RFC3339Nano, data["date"])
			if err != nil {
				errs = append(errs,
					fmt.Sprintf("invalid date %q for fqdn=%s: %v",
						data["date"], data["fqdn"], err))
				continue
			}

			age := now.Sub(t)
			if age >= maxAge {
				errs = append(errs,
					fmt.Sprintf("key for %s (%s) appears stale (age=%s >= %s)",
						data["fqdn"], data["domainName"], age, maxAge))
				continue
			}

			freshKeys++
		}

		if freshKeys == 0 {
			errs = append(errs, "no fresh keys in redis")
		}
	}
}

// ProbeReadiness returns an HTTP handler for Kubernetes readiness probe.
// It checks that:
//   - Redis is accessible
//   - Keys exist for the current appID
//   - Keys contain required fields (key, fqdn, date)
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
					"storage", "redis",
				)

				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(strings.Join(errs, "\n")))
				return
			}

			slog.Debug("readiness: OK",
				"appID", s.appID,
				"storage", "redis",
				"validKeys", validKeys,
			)
			w.WriteHeader(http.StatusOK)
		}()

		// ищем все ключи текущего appID
		pattern := fmt.Sprintf("*:*:%s", s.appID)

		list, err := s.client.Keys(s.ctx, pattern).Result()
		if err != nil {
			errs = append(errs, fmt.Sprintf("failed to query redis: %v", err))
			return
		}

		if len(list) == 0 {
			errs = append(errs, "no redis keys found for app")
			return
		}

		pipe := s.client.Pipeline()
		cmds := make([]*redis.MapStringStringCmd, len(list))

		for i, k := range list {
			cmds[i] = pipe.HGetAll(s.ctx, k)
		}

		if _, err := pipe.Exec(s.ctx); err != nil {
			errs = append(errs, fmt.Sprintf("redis pipeline error: %v", err))
			return
		}

		for _, cmd := range cmds {
			data, err := cmd.Result()
			if err != nil {
				errs = append(errs, fmt.Sprintf("HGetAll failed: %v", err))
				continue
			}

			if len(data) == 0 {
				errs = append(errs, "empty redis hash")
				continue
			}

			if data["key"] == "" {
				errs = append(errs, "redis key missing 'key' field")
				continue
			}

			if data["fqdn"] == "" {
				errs = append(errs, "redis key missing 'fqdn'")
				continue
			}

			if data["date"] == "" {
				errs = append(errs, "redis key missing 'date'")
				continue
			}

			validKeys++
		}

		if validKeys == 0 {
			errs = append(errs, "no valid keys in redis")
		}
	}
}

// ProbeStartup returns an HTTP handler for Kubernetes startup probe.
// Always returns 200 OK as Redis storage doesn't require initialization time.
func (s *Storage) ProbeStartup() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
}
