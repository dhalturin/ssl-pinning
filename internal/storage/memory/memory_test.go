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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	logger "gopkg.in/slog-handler.v1"

	"ssl-pinning/internal/storage/types"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		opts    []types.Option
		wantErr bool
	}{
		{
			name:    "success without options",
			opts:    nil,
			wantErr: false,
		},
		{
			name: "success with app id option",
			opts: []types.Option{
				func(s types.Storage) {
					if ms, ok := s.(*Storage); ok {
						ms.WithAppID("test-app")
					}
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage, err := New(context.Background(), tt.opts...)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, storage)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, storage)
			}
		})
	}
}

func TestStorage_WithAppID(t *testing.T) {
	tests := []struct {
		name  string
		appID string
	}{
		{
			name:  "set app id",
			appID: "test-app",
		},
		{
			name:  "empty app id",
			appID: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Storage{}
			s.WithAppID(tt.appID)
			assert.Equal(t, tt.appID, s.appID)
		})
	}
}

func TestStorage_Close(t *testing.T) {
	s := &Storage{}
	err := s.Close()
	assert.NoError(t, err)
}

func TestStorage_SaveKeys(t *testing.T) {
	now := time.Now()
	expire := now.Add(24 * time.Hour).Unix()

	tests := []struct {
		name       string
		keys       map[string]types.DomainKey
		wantErr    bool
		wantErrMsg string
		validate   func(t *testing.T, s *Storage)
	}{
		{
			name: "success single key",
			keys: map[string]types.DomainKey{
				"example.com": {
					Date:       &now,
					DomainName: "example.com",
					Expire:     expire,
					File:       "test-file.json",
					Fqdn:       "www.example.com",
					Key:        "test-key-data",
				},
			},
			wantErr: false,
			validate: func(t *testing.T, s *Storage) {
				assert.Len(t, s.keys, 1)
				key, exists := s.keys["www.example.com"]
				assert.True(t, exists)
				assert.Equal(t, "test-key-data", key.Key)
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
			validate: func(t *testing.T, s *Storage) {
				assert.Len(t, s.keys, 2)
				assert.Contains(t, s.keys, "www.example1.com")
				assert.Contains(t, s.keys, "www.example2.com")
			},
		},
		{
			name: "error with empty key",
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
			wantErr:    true,
			wantErrMsg: "empty key",
		},
		{
			name:    "success with empty map",
			keys:    map[string]types.DomainKey{},
			wantErr: false,
			validate: func(t *testing.T, s *Storage) {
				assert.Len(t, s.keys, 0)
			},
		},
		{
			name: "replaces existing keys",
			keys: map[string]types.DomainKey{
				"example.com": {
					Date:       &now,
					DomainName: "example.com",
					Expire:     expire,
					File:       "test.json",
					Fqdn:       "www.example.com",
					Key:        "new-key",
				},
			},
			wantErr: false,
			validate: func(t *testing.T, s *Storage) {
				assert.Len(t, s.keys, 1)
				key := s.keys["www.example.com"]
				assert.Equal(t, "new-key", key.Key)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Storage{
				keys: make(map[string]types.DomainKey),
			}

			// For "replaces existing keys" test, pre-populate with old data
			if tt.name == "replaces existing keys" {
				s.keys["www.example.com"] = types.DomainKey{
					Fqdn: "www.example.com",
					Key:  "old-key",
				}
			}

			err := s.SaveKeys(tt.keys)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrMsg != "" {
					assert.Contains(t, err.Error(), tt.wantErrMsg)
				}
			} else {
				assert.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, s)
				}
			}
		})
	}
}

func TestStorage_GetByFile(t *testing.T) {
	now := time.Now()
	expire := now.Add(24 * time.Hour).Unix()

	tests := []struct {
		name     string
		file     string
		setup    func(t *testing.T) *Storage
		wantKeys int
		validate func(t *testing.T, keys []types.DomainKey)
	}{
		{
			name: "success with matching keys",
			file: "test.json",
			setup: func(t *testing.T) *Storage {
				s := &Storage{
					keys: map[string]types.DomainKey{
						"www.example.com": {
							Date:       &now,
							DomainName: "example.com",
							Expire:     expire,
							File:       "test.json",
							Fqdn:       "www.example.com",
							Key:        "key1",
						},
						"www.test.com": {
							Date:       &now,
							DomainName: "test.com",
							Expire:     expire,
							File:       "test.json",
							Fqdn:       "www.test.com",
							Key:        "key2",
						},
					},
				}
				return s
			},
			wantKeys: 2,
			validate: func(t *testing.T, keys []types.DomainKey) {
				// File field should be cleared
				for _, key := range keys {
					assert.Empty(t, key.File)
				}
			},
		},
		{
			name: "no matching keys",
			file: "nonexistent.json",
			setup: func(t *testing.T) *Storage {
				s := &Storage{
					keys: map[string]types.DomainKey{
						"www.example.com": {
							File: "other.json",
							Fqdn: "www.example.com",
							Key:  "key1",
						},
					},
				}
				return s
			},
			wantKeys: 0,
		},
		{
			name: "filters empty keys",
			file: "test.json",
			setup: func(t *testing.T) *Storage {
				s := &Storage{
					keys: map[string]types.DomainKey{
						"www.example.com": {
							File: "test.json",
							Fqdn: "www.example.com",
							Key:  "", // Empty key
						},
						"www.test.com": {
							File: "test.json",
							Fqdn: "www.test.com",
							Key:  "valid-key",
						},
					},
				}
				return s
			},
			wantKeys: 1,
			validate: func(t *testing.T, keys []types.DomainKey) {
				assert.Equal(t, "valid-key", keys[0].Key)
			},
		},
		{
			name: "empty storage",
			file: "test.json",
			setup: func(t *testing.T) *Storage {
				return &Storage{
					keys: map[string]types.DomainKey{},
				}
			},
			wantKeys: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.setup(t)

			keys, data, err := s.GetByFile(tt.file)

			assert.NoError(t, err)
			assert.Nil(t, data) // memory always returns nil for data
			assert.Len(t, keys, tt.wantKeys)

			if tt.validate != nil && len(keys) > 0 {
				tt.validate(t, keys)
			}
		})
	}
}

func TestStorage_ProbeLiveness(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	now := time.Now()
	staleTime := now.Add(-20 * time.Second)
	expire := now.Add(24 * time.Hour).Unix()

	tests := []struct {
		name             string
		setup            func(t *testing.T) *Storage
		wantStatusCode   int
		wantBodyContains string
	}{
		{
			name: "healthy with fresh keys",
			setup: func(t *testing.T) *Storage {
				return &Storage{
					appID: "test-app",
					keys: map[string]types.DomainKey{
						"www.example.com": {
							Date:       &now,
							DomainName: "example.com",
							Expire:     expire,
							File:       "test.json",
							Fqdn:       "www.example.com",
							Key:        "test-key",
						},
					},
				}
			},
			wantStatusCode: http.StatusOK,
		},
		{
			name: "unhealthy with no keys",
			setup: func(t *testing.T) *Storage {
				return &Storage{
					appID: "test-app",
					keys:  map[string]types.DomainKey{},
				}
			},
			wantStatusCode:   http.StatusServiceUnavailable,
			wantBodyContains: "no keys in memory",
		},
		{
			name: "unhealthy with stale keys",
			setup: func(t *testing.T) *Storage {
				return &Storage{
					appID: "test-app",
					keys: map[string]types.DomainKey{
						"www.example.com": {
							Date:       &staleTime,
							DomainName: "example.com",
							Expire:     expire,
							File:       "test.json",
							Fqdn:       "www.example.com",
							Key:        "test-key",
						},
					},
				}
			},
			wantStatusCode:   http.StatusServiceUnavailable,
			wantBodyContains: "appears stale",
		},
		{
			name: "unhealthy with empty key",
			setup: func(t *testing.T) *Storage {
				return &Storage{
					appID: "test-app",
					keys: map[string]types.DomainKey{
						"www.example.com": {
							Date:       &now,
							DomainName: "example.com",
							Fqdn:       "www.example.com",
							Key:        "", // Empty key
						},
					},
				}
			},
			wantStatusCode:   http.StatusServiceUnavailable,
			wantBodyContains: "empty key",
		},
		{
			name: "unhealthy with missing date",
			setup: func(t *testing.T) *Storage {
				return &Storage{
					appID: "test-app",
					keys: map[string]types.DomainKey{
						"www.example.com": {
							Date:       nil, // Missing date
							DomainName: "example.com",
							Fqdn:       "www.example.com",
							Key:        "test-key",
						},
					},
				}
			},
			wantStatusCode:   http.StatusServiceUnavailable,
			wantBodyContains: "missing date",
		},
		{
			name: "unhealthy when no fresh keys",
			setup: func(t *testing.T) *Storage {
				return &Storage{
					appID: "test-app",
					keys: map[string]types.DomainKey{
						"www.example.com": {
							Date:       &staleTime,
							DomainName: "example.com",
							Fqdn:       "www.example.com",
							Key:        "test-key",
						},
					},
				}
			},
			wantStatusCode:   http.StatusServiceUnavailable,
			wantBodyContains: "no fresh keys found in memory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.setup(t)

			handler := s.ProbeLiveness()
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
		setup            func(t *testing.T) *Storage
		wantStatusCode   int
		wantBodyContains string
	}{
		{
			name: "ready with valid keys",
			setup: func(t *testing.T) *Storage {
				return &Storage{
					appID: "test-app",
					keys: map[string]types.DomainKey{
						"www.example.com": {
							Date:       &now,
							DomainName: "example.com",
							Expire:     expire,
							File:       "test.json",
							Fqdn:       "www.example.com",
							Key:        "test-key",
						},
					},
				}
			},
			wantStatusCode: http.StatusOK,
		},
		{
			name: "not ready with no keys",
			setup: func(t *testing.T) *Storage {
				return &Storage{
					appID: "test-app",
					keys:  map[string]types.DomainKey{},
				}
			},
			wantStatusCode:   http.StatusServiceUnavailable,
			wantBodyContains: "no keys in memory",
		},
		{
			name: "not ready with empty key",
			setup: func(t *testing.T) *Storage {
				return &Storage{
					appID: "test-app",
					keys: map[string]types.DomainKey{
						"www.example.com": {
							Date:       &now,
							DomainName: "example.com",
							Fqdn:       "www.example.com",
							Key:        "", // Empty key
						},
					},
				}
			},
			wantStatusCode:   http.StatusServiceUnavailable,
			wantBodyContains: "empty key",
		},
		{
			name: "not ready with missing date",
			setup: func(t *testing.T) *Storage {
				return &Storage{
					appID: "test-app",
					keys: map[string]types.DomainKey{
						"www.example.com": {
							Date:       nil, // Missing date
							DomainName: "example.com",
							Fqdn:       "www.example.com",
							Key:        "test-key",
						},
					},
				}
			},
			wantStatusCode:   http.StatusServiceUnavailable,
			wantBodyContains: "missing date",
		},
		{
			name: "not ready with no valid keys",
			setup: func(t *testing.T) *Storage {
				return &Storage{
					appID: "test-app",
					keys: map[string]types.DomainKey{
						"www.example.com": {
							Date:       nil,
							DomainName: "example.com",
							Fqdn:       "www.example.com",
							Key:        "test-key",
						},
					},
				}
			},
			wantStatusCode:   http.StatusServiceUnavailable,
			wantBodyContains: "no valid keys in memory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.setup(t)

			handler := s.ProbeReadiness()
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
	s := &Storage{}

	handler := s.ProbeStartup()
	req := httptest.NewRequest(http.MethodGet, "/startup", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestStorage_Concurrent_SaveKeys(t *testing.T) {
	s := &Storage{
		keys: make(map[string]types.DomainKey),
	}

	now := time.Now()
	expire := now.Add(24 * time.Hour).Unix()

	const numGoroutines = 10
	done := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
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
			done <- err
		}(i)
	}

	for i := 0; i < numGoroutines; i++ {
		err := <-done
		assert.NoError(t, err)
	}

	// After all concurrent operations, storage should have exactly 1 key
	assert.Len(t, s.keys, 1)
}

func TestStorage_Concurrent_GetByFile(t *testing.T) {
	now := time.Now()
	expire := now.Add(24 * time.Hour).Unix()

	s := &Storage{
		keys: map[string]types.DomainKey{
			"www.example.com": {
				Date:       &now,
				DomainName: "example.com",
				Expire:     expire,
				File:       "test.json",
				Fqdn:       "www.example.com",
				Key:        "test-key",
			},
		},
	}

	const numGoroutines = 10
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			keys, _, err := s.GetByFile("test.json")
			require.NoError(t, err)
			require.Len(t, keys, 1)
			done <- true
		}()
	}

	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}
