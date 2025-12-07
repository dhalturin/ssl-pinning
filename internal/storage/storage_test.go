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
package storage

import (
	"context"
	"testing"

	"ssl-pinning/internal/storage/types"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		errContains string
		opts        []types.Option
		skipError   bool
		storageType types.StorageType
		wantErr     bool
	}{
		{
			name:        "memory storage",
			storageType: types.StorageMemory,
			opts:        []types.Option{},
			wantErr:     false,
		},
		{
			name:        "filesystem storage",
			storageType: types.StorageFS,
			opts: []types.Option{
				types.WithDumpDir(t.TempDir()),
			},
			wantErr: false,
		},
		{
			name:        "redis storage type",
			storageType: types.StorageRedis,
			opts:        []types.Option{types.WithDSN("redis://localhost:6379/0")},
			skipError:   true, // May fail without Redis server, but factory shouldn't panic
		},
		{
			name:        "postgres storage type",
			storageType: types.StoragePostgres,
			opts:        []types.Option{types.WithDSN("postgres://user:pass@localhost:5432/test?sslmode=disable")},
			skipError:   true, // May fail without Postgres server, but factory shouldn't panic
		},
		{
			name:        "invalid storage type",
			storageType: types.StorageType("invalid"),
			opts:        []types.Option{},
			wantErr:     true,
			errContains: "invalid storage type",
		},
		{
			name:        "empty storage type",
			storageType: types.StorageType(""),
			opts:        []types.Option{},
			wantErr:     true,
			errContains: "invalid storage type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage, err := New(ctx, tt.storageType, tt.opts...)

			if tt.skipError {
				// For external services (Redis, Postgres), we only verify no panic
				// Connection errors are expected without running infrastructure
				return
			}

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, storage)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, storage)
			}
		})
	}
}

func TestNew_WithOptions(t *testing.T) {
	ctx := context.Background()

	t.Run("memory with app ID", func(t *testing.T) {
		s, err := New(ctx, types.StorageMemory, types.WithAppID("test-app"))
		assert.NoError(t, err)
		assert.NotNil(t, s)
	})

	t.Run("filesystem with app ID and dump dir", func(t *testing.T) {
		s, err := New(ctx, types.StorageFS,
			types.WithAppID("test-app"),
			types.WithDumpDir(t.TempDir()),
		)
		assert.NoError(t, err)
		assert.NotNil(t, s)
	})
}

func TestNew_Concurrent(t *testing.T) {
	ctx := context.Background()
	const numGoroutines = 10

	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			s, err := New(ctx, types.StorageMemory)
			assert.NoError(t, err)
			assert.NotNil(t, s)
			done <- true
		}()
	}

	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

func BenchmarkNew_Memory(b *testing.B) {
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = New(ctx, types.StorageMemory)
	}
}

func BenchmarkNew_Filesystem(b *testing.B) {
	ctx := context.Background()
	tmpDir := b.TempDir()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = New(ctx, types.StorageFS, types.WithDumpDir(tmpDir))
	}
}

func BenchmarkNew_WithOptions(b *testing.B) {
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = New(ctx, types.StorageMemory,
			types.WithAppID("bench-app"),
		)
	}
}
