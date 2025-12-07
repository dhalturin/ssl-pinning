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
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	logger "gopkg.in/slog-handler.v1"

	"ssl-pinning/internal/storage/types"
)

func setupMiniRedis(t *testing.T) (*miniredis.Miniredis, string) {
	t.Helper()

	mr, err := miniredis.Run()
	require.NoError(t, err)

	t.Cleanup(func() {
		mr.Close()
	})

	dsn := fmt.Sprintf("redis://%s", mr.Addr())
	return mr, dsn
}

func TestNew(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	// Suppress Redis client's logging to stderr
	oldStderr := os.Stderr
	_, w, _ := os.Pipe()
	os.Stderr = w
	t.Cleanup(func() {
		os.Stderr = oldStderr
		w.Close()
	})

	tests := []struct {
		name       string
		setup      func(t *testing.T) string
		opts       func(dsn string) []types.Option
		wantErr    bool
		wantErrMsg string
		validate   func(t *testing.T, s types.Storage)
	}{
		{
			name: "success with valid dsn",
			setup: func(t *testing.T) string {
				_, dsn := setupMiniRedis(t)
				return dsn
			},
			opts: func(dsn string) []types.Option {
				return []types.Option{
					func(s types.Storage) {
						if rs, ok := s.(*Storage); ok {
							rs.WithDSN(dsn)
							rs.WithAppID("test-app")
						}
					},
				}
			},
			wantErr: false,
			validate: func(t *testing.T, s types.Storage) {
				assert.NotNil(t, s)
				rs := s.(*Storage)
				assert.Equal(t, "test-app", rs.appID)
			},
		},
		{
			name: "success with database number",
			setup: func(t *testing.T) string {
				_, dsn := setupMiniRedis(t)
				return dsn + "/1"
			},
			opts: func(dsn string) []types.Option {
				return []types.Option{
					func(s types.Storage) {
						if rs, ok := s.(*Storage); ok {
							rs.WithDSN(dsn)
						}
					},
				}
			},
			wantErr: false,
		},
		{
			name: "success with password",
			setup: func(t *testing.T) string {
				mr, _ := setupMiniRedis(t)
				mr.RequireAuth("secret")
				return fmt.Sprintf("redis://:secret@%s", mr.Addr())
			},
			opts: func(dsn string) []types.Option {
				return []types.Option{
					func(s types.Storage) {
						if rs, ok := s.(*Storage); ok {
							rs.WithDSN(dsn)
						}
					},
				}
			},
			wantErr: false,
		},
		{
			name: "success with maintnotifications disabled",
			setup: func(t *testing.T) string {
				_, dsn := setupMiniRedis(t)
				return dsn + "?maintnotifications=disabled"
			},
			opts: func(dsn string) []types.Option {
				return []types.Option{
					func(s types.Storage) {
						if rs, ok := s.(*Storage); ok {
							rs.WithDSN(dsn)
						}
					},
				}
			},
			wantErr: false,
		},
		{
			name: "error with invalid dsn",
			setup: func(t *testing.T) string {
				return "://invalid"
			},
			opts: func(dsn string) []types.Option {
				return []types.Option{
					func(s types.Storage) {
						if rs, ok := s.(*Storage); ok {
							rs.WithDSN(dsn)
						}
					},
				}
			},
			wantErr:    true,
			wantErrMsg: "failed to parse redis dsn",
		},
		{
			name: "error with invalid database number",
			setup: func(t *testing.T) string {
				_, dsn := setupMiniRedis(t)
				return dsn + "/invalid"
			},
			opts: func(dsn string) []types.Option {
				return []types.Option{
					func(s types.Storage) {
						if rs, ok := s.(*Storage); ok {
							rs.WithDSN(dsn)
						}
					},
				}
			},
			wantErr:    true,
			wantErrMsg: "invalid syntax",
		},
		{
			name: "error with unreachable redis",
			setup: func(t *testing.T) string {
				return "redis://localhost:99999"
			},
			opts: func(dsn string) []types.Option {
				return []types.Option{
					func(s types.Storage) {
						if rs, ok := s.(*Storage); ok {
							rs.WithDSN(dsn)
						}
					},
				}
			},
			wantErr:    true,
			wantErrMsg: "failed to connect to redis",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dsn := tt.setup(t)
			opts := tt.opts(dsn)

			storage, err := New(context.Background(), opts...)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrMsg != "" {
					assert.Contains(t, err.Error(), tt.wantErrMsg)
				}
				assert.Nil(t, storage)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, storage)
				if tt.validate != nil {
					tt.validate(t, storage)
				}
				// Cleanup
				if storage != nil {
					_ = storage.Close()
				}
			}
		})
	}
}

func TestStorage_WithAppID(t *testing.T) {
	s := &Storage{}
	s.WithAppID("test-app")
	assert.Equal(t, "test-app", s.appID)
}

func TestStorage_WithDSN(t *testing.T) {
	s := &Storage{}
	s.WithDSN("redis://localhost:6379")
	assert.Equal(t, "redis://localhost:6379", s.dsn)
}

func TestStorage_SaveKeys(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	now := time.Now()
	expire := now.Add(24 * time.Hour).Unix()

	tests := []struct {
		name       string
		keys       map[string]types.DomainKey
		wantErr    bool
		wantErrMsg string
		validate   func(t *testing.T, mr *miniredis.Miniredis)
	}{
		{
			name: "success single key",
			keys: map[string]types.DomainKey{
				"example.com": {
					Date:       &now,
					DomainName: "example.com",
					Expire:     expire,
					File:       "test.json",
					Fqdn:       "www.example.com",
					Key:        "test-key-data",
				},
			},
			wantErr: false,
			validate: func(t *testing.T, mr *miniredis.Miniredis) {
				hash := "test.json:www.example.com:test-app"
				assert.True(t, mr.Exists(hash))
				key := mr.HGet(hash, "key")
				assert.Equal(t, "test-key-data", key)
			},
		},
		{
			name: "success multiple keys",
			keys: map[string]types.DomainKey{
				"example1.com": {
					Date:       &now,
					DomainName: "example1.com",
					Expire:     expire,
					File:       "test.json",
					Fqdn:       "www.example1.com",
					Key:        "key1",
				},
				"example2.com": {
					Date:       &now,
					DomainName: "example2.com",
					Expire:     expire,
					File:       "test.json",
					Fqdn:       "www.example2.com",
					Key:        "key2",
				},
			},
			wantErr: false,
			validate: func(t *testing.T, mr *miniredis.Miniredis) {
				hash1 := "test.json:www.example1.com:test-app"
				hash2 := "test.json:www.example2.com:test-app"
				assert.True(t, mr.Exists(hash1))
				assert.True(t, mr.Exists(hash2))
			},
		},
		{
			name: "skips empty keys",
			keys: map[string]types.DomainKey{
				"example.com": {
					Date:       &now,
					DomainName: "example.com",
					Expire:     expire,
					File:       "test.json",
					Fqdn:       "www.example.com",
					Key:        "", // Empty key
				},
			},
			wantErr: false,
			validate: func(t *testing.T, mr *miniredis.Miniredis) {
				// Key should not exist since it was empty
				hash := "test.json:www.example.com:test-app"
				assert.False(t, mr.Exists(hash))
			},
		},
		{
			name: "saves key with last_error",
			keys: map[string]types.DomainKey{
				"example.com": {
					Date:       &now,
					DomainName: "example.com",
					Expire:     expire,
					File:       "test.json",
					Fqdn:       "www.example.com",
					Key:        "test-key",
					LastError:  "some error",
				},
			},
			wantErr: false,
			validate: func(t *testing.T, mr *miniredis.Miniredis) {
				hash := "test.json:www.example.com:test-app"
				lastError := mr.HGet(hash, "last_error")
				assert.Equal(t, "some error", lastError)
			},
		},
		{
			name:    "success with empty map",
			keys:    map[string]types.DomainKey{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mr, dsn := setupMiniRedis(t)

			storage, err := New(context.Background(), func(s types.Storage) {
				if rs, ok := s.(*Storage); ok {
					rs.WithDSN(dsn)
					rs.WithAppID("test-app")
				}
			})
			require.NoError(t, err)
			defer storage.Close()

			err = storage.SaveKeys(tt.keys)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrMsg != "" {
					assert.Contains(t, err.Error(), tt.wantErrMsg)
				}
			} else {
				assert.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, mr)
				}
			}
		})
	}
}

func TestStorage_GetByFile(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	now := time.Now()
	expire := now.Add(24 * time.Hour).Unix()

	tests := []struct {
		name     string
		file     string
		setup    func(t *testing.T, s types.Storage)
		wantKeys int
		validate func(t *testing.T, keys []types.DomainKey)
	}{
		{
			name: "success with matching keys",
			file: "test.json",
			setup: func(t *testing.T, s types.Storage) {
				keys := map[string]types.DomainKey{
					"example.com": {
						Date:       &now,
						DomainName: "example.com",
						Expire:     expire,
						File:       "test.json",
						Fqdn:       "www.example.com",
						Key:        "key1",
					},
				}
				err := s.SaveKeys(keys)
				require.NoError(t, err)
			},
			wantKeys: 1,
			validate: func(t *testing.T, keys []types.DomainKey) {
				assert.Equal(t, "key1", keys[0].Key)
				assert.Equal(t, "www.example.com", keys[0].Fqdn)
			},
		},
		{
			name: "selects best key by earliest expire",
			file: "test.json",
			setup: func(t *testing.T, s types.Storage) {
				// Manually insert two keys with same FQDN but different hashes
				// to simulate multiple versions of the same domain
				rs := s.(*Storage)

				// Key with later expire
				hash1 := "test.json:www.example.com:test-app:1"
				err := rs.client.HSet(rs.ctx, hash1,
					"date", now.Format(time.RFC3339Nano),
					"domainName", "example.com",
					"expire", expire+1000,
					"file", "test.json",
					"fqdn", "www.example.com",
					"key", "key-later",
				).Err()
				require.NoError(t, err)

				// Key with earlier expire - should be selected
				hash2 := "test.json:www.example.com:test-app:2"
				err = rs.client.HSet(rs.ctx, hash2,
					"date", now.Format(time.RFC3339Nano),
					"domainName", "example.com",
					"expire", expire,
					"file", "test.json",
					"fqdn", "www.example.com",
					"key", "key-earlier",
				).Err()
				require.NoError(t, err)
			},
			wantKeys: 1,
			validate: func(t *testing.T, keys []types.DomainKey) {
				// Should get the key with earliest expire
				assert.Equal(t, "key-earlier", keys[0].Key)
			},
		},
		{
			name: "no matching keys",
			file: "nonexistent.json",
			setup: func(t *testing.T, s types.Storage) {
				keys := map[string]types.DomainKey{
					"example.com": {
						Date:       &now,
						DomainName: "example.com",
						Expire:     expire,
						File:       "other.json",
						Fqdn:       "www.example.com",
						Key:        "key1",
					},
				}
				err := s.SaveKeys(keys)
				require.NoError(t, err)
			},
			wantKeys: 0,
		},
		{
			name: "filters empty keys",
			file: "test.json",
			setup: func(t *testing.T, s types.Storage) {
				// Manually insert a key with empty "key" field
				rs := s.(*Storage)
				hash := "test.json:www.example.com:test-app"
				err := rs.client.HSet(rs.ctx, hash,
					"date", now.Format(time.RFC3339Nano),
					"domainName", "example.com",
					"expire", expire,
					"file", "test.json",
					"fqdn", "www.example.com",
					"key", "", // Empty key
				).Err()
				require.NoError(t, err)
			},
			wantKeys: 0,
		},
		{
			name:     "empty redis",
			file:     "test.json",
			setup:    func(t *testing.T, s types.Storage) {},
			wantKeys: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, dsn := setupMiniRedis(t)

			storage, err := New(context.Background(), func(s types.Storage) {
				if rs, ok := s.(*Storage); ok {
					rs.WithDSN(dsn)
					rs.WithAppID("test-app")
				}
			})
			require.NoError(t, err)
			defer storage.Close()

			tt.setup(t, storage)

			keys, data, err := storage.GetByFile(tt.file)

			assert.NoError(t, err)
			assert.Nil(t, data)
			assert.Len(t, keys, tt.wantKeys)

			if tt.validate != nil && len(keys) > 0 {
				tt.validate(t, keys)
			}
		})
	}
}

func TestStorage_Close(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	_, dsn := setupMiniRedis(t)

	storage, err := New(context.Background(), func(s types.Storage) {
		if rs, ok := s.(*Storage); ok {
			rs.WithDSN(dsn)
		}
	})
	require.NoError(t, err)

	err = storage.Close()
	assert.NoError(t, err)
}

func TestStorage_ProbeLiveness(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	now := time.Now()
	staleTime := now.Add(-20 * time.Second)
	expire := now.Add(24 * time.Hour).Unix()

	tests := []struct {
		name             string
		setup            func(t *testing.T, s types.Storage)
		wantStatusCode   int
		wantBodyContains string
	}{
		{
			name: "healthy with fresh keys",
			setup: func(t *testing.T, s types.Storage) {
				keys := map[string]types.DomainKey{
					"example.com": {
						Date:       &now,
						DomainName: "example.com",
						Expire:     expire,
						File:       "test.json",
						Fqdn:       "www.example.com",
						Key:        "test-key",
					},
				}
				err := s.SaveKeys(keys)
				require.NoError(t, err)
			},
			wantStatusCode: http.StatusOK,
		},
		{
			name:             "unhealthy with no keys",
			setup:            func(t *testing.T, s types.Storage) {},
			wantStatusCode:   http.StatusServiceUnavailable,
			wantBodyContains: "no redis keys found for app",
		},
		{
			name: "unhealthy with stale keys",
			setup: func(t *testing.T, s types.Storage) {
				keys := map[string]types.DomainKey{
					"example.com": {
						Date:       &staleTime,
						DomainName: "example.com",
						Expire:     expire,
						File:       "test.json",
						Fqdn:       "www.example.com",
						Key:        "test-key",
					},
				}
				err := s.SaveKeys(keys)
				require.NoError(t, err)
			},
			wantStatusCode:   http.StatusServiceUnavailable,
			wantBodyContains: "appears stale",
		},
		{
			name: "unhealthy with empty key",
			setup: func(t *testing.T, s types.Storage) {
				rs := s.(*Storage)
				hash := "test.json:www.example.com:test-app"
				err := rs.client.HSet(rs.ctx, hash,
					"date", now.Format(time.RFC3339Nano),
					"domainName", "example.com",
					"fqdn", "www.example.com",
					"key", "",
				).Err()
				require.NoError(t, err)
			},
			wantStatusCode:   http.StatusServiceUnavailable,
			wantBodyContains: "empty key",
		},
		{
			name: "unhealthy with last_error",
			setup: func(t *testing.T, s types.Storage) {
				rs := s.(*Storage)
				hash := "test.json:www.example.com:test-app"
				err := rs.client.HSet(rs.ctx, hash,
					"date", now.Format(time.RFC3339Nano),
					"domainName", "example.com",
					"fqdn", "www.example.com",
					"key", "test-key",
					"last_error", "connection timeout",
				).Err()
				require.NoError(t, err)
			},
			wantStatusCode:   http.StatusServiceUnavailable,
			wantBodyContains: "has last_error",
		},
		{
			name: "unhealthy with missing date",
			setup: func(t *testing.T, s types.Storage) {
				rs := s.(*Storage)
				hash := "test.json:www.example.com:test-app"
				err := rs.client.HSet(rs.ctx, hash,
					"domainName", "example.com",
					"fqdn", "www.example.com",
					"key", "test-key",
				).Err()
				require.NoError(t, err)
			},
			wantStatusCode:   http.StatusServiceUnavailable,
			wantBodyContains: "missing date",
		},
		{
			name: "unhealthy with invalid date format",
			setup: func(t *testing.T, s types.Storage) {
				rs := s.(*Storage)
				hash := "test.json:www.example.com:test-app"
				err := rs.client.HSet(rs.ctx, hash,
					"date", "invalid-date",
					"domainName", "example.com",
					"fqdn", "www.example.com",
					"key", "test-key",
				).Err()
				require.NoError(t, err)
			},
			wantStatusCode:   http.StatusServiceUnavailable,
			wantBodyContains: "invalid date",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, dsn := setupMiniRedis(t)

			storage, err := New(context.Background(), func(s types.Storage) {
				if rs, ok := s.(*Storage); ok {
					rs.WithDSN(dsn)
					rs.WithAppID("test-app")
				}
			})
			require.NoError(t, err)
			defer storage.Close()

			tt.setup(t, storage)

			rs := storage.(*Storage)
			handler := rs.ProbeLiveness()
			req := httptest.NewRequest(http.MethodGet, "/live", nil)
			w := httptest.NewRecorder()

			handler(w, req)

			assert.Equal(t, tt.wantStatusCode, w.Code)
			if tt.wantBodyContains != "" {
				assert.Contains(t, w.Body.String(), tt.wantBodyContains)
			}
		})
	}
}

func TestStorage_ProbeReadiness(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	now := time.Now()
	expire := now.Add(24 * time.Hour).Unix()

	tests := []struct {
		name             string
		setup            func(t *testing.T, s types.Storage)
		wantStatusCode   int
		wantBodyContains string
	}{
		{
			name: "ready with valid keys",
			setup: func(t *testing.T, s types.Storage) {
				keys := map[string]types.DomainKey{
					"example.com": {
						Date:       &now,
						DomainName: "example.com",
						Expire:     expire,
						File:       "test.json",
						Fqdn:       "www.example.com",
						Key:        "test-key",
					},
				}
				err := s.SaveKeys(keys)
				require.NoError(t, err)
			},
			wantStatusCode: http.StatusOK,
		},
		{
			name:             "not ready with no keys",
			setup:            func(t *testing.T, s types.Storage) {},
			wantStatusCode:   http.StatusServiceUnavailable,
			wantBodyContains: "no redis keys found for app",
		},
		{
			name: "not ready with empty key",
			setup: func(t *testing.T, s types.Storage) {
				rs := s.(*Storage)
				hash := "test.json:www.example.com:test-app"
				err := rs.client.HSet(rs.ctx, hash,
					"date", now.Format(time.RFC3339Nano),
					"domainName", "example.com",
					"fqdn", "www.example.com",
					"key", "",
				).Err()
				require.NoError(t, err)
			},
			wantStatusCode:   http.StatusServiceUnavailable,
			wantBodyContains: "redis key missing 'key' field",
		},
		{
			name: "not ready with missing fqdn",
			setup: func(t *testing.T, s types.Storage) {
				rs := s.(*Storage)
				hash := "test.json:www.example.com:test-app"
				err := rs.client.HSet(rs.ctx, hash,
					"date", now.Format(time.RFC3339Nano),
					"domainName", "example.com",
					"key", "test-key",
				).Err()
				require.NoError(t, err)
			},
			wantStatusCode:   http.StatusServiceUnavailable,
			wantBodyContains: "redis key missing 'fqdn'",
		},
		{
			name: "not ready with missing date",
			setup: func(t *testing.T, s types.Storage) {
				rs := s.(*Storage)
				hash := "test.json:www.example.com:test-app"
				err := rs.client.HSet(rs.ctx, hash,
					"domainName", "example.com",
					"fqdn", "www.example.com",
					"key", "test-key",
				).Err()
				require.NoError(t, err)
			},
			wantStatusCode:   http.StatusServiceUnavailable,
			wantBodyContains: "redis key missing 'date'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, dsn := setupMiniRedis(t)

			storage, err := New(context.Background(), func(s types.Storage) {
				if rs, ok := s.(*Storage); ok {
					rs.WithDSN(dsn)
					rs.WithAppID("test-app")
				}
			})
			require.NoError(t, err)
			defer storage.Close()

			tt.setup(t, storage)

			rs := storage.(*Storage)
			handler := rs.ProbeReadiness()
			req := httptest.NewRequest(http.MethodGet, "/ready", nil)
			w := httptest.NewRecorder()

			handler(w, req)

			assert.Equal(t, tt.wantStatusCode, w.Code)
			if tt.wantBodyContains != "" {
				assert.Contains(t, w.Body.String(), tt.wantBodyContains)
			}
		})
	}
}

func TestStorage_ProbeStartup(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	_, dsn := setupMiniRedis(t)

	storage, err := New(context.Background(), func(s types.Storage) {
		if rs, ok := s.(*Storage); ok {
			rs.WithDSN(dsn)
		}
	})
	require.NoError(t, err)
	defer storage.Close()

	rs := storage.(*Storage)
	handler := rs.ProbeStartup()
	req := httptest.NewRequest(http.MethodGet, "/startup", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
