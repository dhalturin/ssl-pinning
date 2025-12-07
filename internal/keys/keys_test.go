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
	"sync"
	"testing"
	"time"

	logger "gopkg.in/slog-handler.v1"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"ssl-pinning/internal/metrics"
	"ssl-pinning/internal/storage/types"
)

func TestNewKeys(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	tests := []struct {
		name     string
		keys     []types.DomainKey
		opts     []Option
		validate func(t *testing.T, k *Keys)
	}{
		{
			name: "empty keys",
			keys: []types.DomainKey{},
			opts: []Option{},
			validate: func(t *testing.T, k *Keys) {
				assert.NotNil(t, k)
				assert.NotNil(t, k.store)
				assert.Empty(t, k.store)
			},
		},
		{
			name: "single domain key",
			keys: []types.DomainKey{
				{
					Fqdn: "example.com",
					File: "example.json",
					Key:  "test-key",
				},
			},
			opts: []Option{
				WithCollector(metrics.NewCollector()),
			},
			validate: func(t *testing.T, k *Keys) {
				assert.NotNil(t, k)
				assert.Len(t, k.store, 1)
				val, ok := k.Get("example.com")
				assert.True(t, ok)
				assert.Equal(t, "example.com", val.Fqdn)
				assert.Equal(t, "test-key", val.Key)
			},
		},
		{
			name: "multiple domain keys",
			keys: []types.DomainKey{
				{Fqdn: "example.com", File: "example.json", Key: "key1"},
				{Fqdn: "test.com", File: "test.json", Key: "key2"},
			},
			opts: []Option{
				WithCollector(metrics.NewCollector()),
			},
			validate: func(t *testing.T, k *Keys) {
				assert.Len(t, k.store, 2)
				_, ok1 := k.Get("example.com")
				_, ok2 := k.Get("test.com")
				assert.True(t, ok1)
				assert.True(t, ok2)
			},
		},
		{
			name: "with timeout option",
			keys: []types.DomainKey{},
			opts: []Option{
				WithTimeout(5 * time.Second),
			},
			validate: func(t *testing.T, k *Keys) {
				assert.Equal(t, 5*time.Second, k.timeout)
			},
		},
		{
			name: "with dump interval option",
			keys: []types.DomainKey{},
			opts: []Option{
				WithDumpInterval(10 * time.Second),
			},
			validate: func(t *testing.T, k *Keys) {
				assert.Equal(t, 10*time.Second, k.dumpInterval)
			},
		},
		{
			name: "with collector option",
			keys: []types.DomainKey{},
			opts: []Option{
				WithCollector(metrics.NewCollector()),
			},
			validate: func(t *testing.T, k *Keys) {
				assert.NotNil(t, k.collector)
			},
		},
		{
			name: "with flush func option",
			keys: []types.DomainKey{},
			opts: []Option{
				WithFlushFunc(func(m map[string]types.DomainKey) error {
					return nil
				}),
			},
			validate: func(t *testing.T, k *Keys) {
				assert.NotNil(t, k.flushFunc)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			k := NewKeys(ctx, tt.keys, tt.opts...)
			tt.validate(t, k)
		})
	}
}

func TestKeys_SetAndGet(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	tests := []struct {
		name     string
		key      string
		value    types.DomainKey
		getKey   string
		wantOk   bool
		validate func(t *testing.T, got types.DomainKey)
	}{
		{
			name:   "set and get existing key",
			key:    "example.com",
			value:  types.DomainKey{Fqdn: "example.com", Key: "test-key", File: "example.json"},
			getKey: "example.com",
			wantOk: true,
			validate: func(t *testing.T, got types.DomainKey) {
				assert.Equal(t, "example.com", got.Fqdn)
				assert.Equal(t, "test-key", got.Key)
			},
		},
		{
			name:   "get non-existing key",
			key:    "example.com",
			value:  types.DomainKey{Fqdn: "example.com", Key: "test-key"},
			getKey: "missing.com",
			wantOk: false,
			validate: func(t *testing.T, got types.DomainKey) {
				assert.Empty(t, got.Fqdn)
			},
		},
		{
			name:   "update existing key",
			key:    "example.com",
			value:  types.DomainKey{Fqdn: "example.com", Key: "updated-key", Expire: 3600},
			getKey: "example.com",
			wantOk: true,
			validate: func(t *testing.T, got types.DomainKey) {
				assert.Equal(t, "updated-key", got.Key)
				assert.Equal(t, int64(3600), got.Expire)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			k := NewKeys(ctx, []types.DomainKey{},
				WithCollector(metrics.NewCollector()),
			)

			k.Set(tt.key, tt.value)

			got, ok := k.Get(tt.getKey)
			assert.Equal(t, tt.wantOk, ok)
			tt.validate(t, got)
		})
	}
}

func TestKeys_Snapshot(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	tests := []struct {
		name     string
		keys     []types.DomainKey
		validate func(t *testing.T, snapshot map[string]types.DomainKey)
	}{
		{
			name: "empty snapshot",
			keys: []types.DomainKey{},
			validate: func(t *testing.T, snapshot map[string]types.DomainKey) {
				assert.Empty(t, snapshot)
			},
		},
		{
			name: "snapshot with single key",
			keys: []types.DomainKey{
				{Fqdn: "example.com", Key: "key1", File: "example.json"},
			},
			validate: func(t *testing.T, snapshot map[string]types.DomainKey) {
				assert.Len(t, snapshot, 1)
				val, ok := snapshot["example.com"]
				assert.True(t, ok)
				assert.Equal(t, "key1", val.Key)
			},
		},
		{
			name: "snapshot with multiple keys",
			keys: []types.DomainKey{
				{Fqdn: "example.com", Key: "key1", File: "example.json"},
				{Fqdn: "test.com", Key: "key2", File: "test.json"},
				{Fqdn: "demo.com", Key: "key3", File: "demo.json"},
			},
			validate: func(t *testing.T, snapshot map[string]types.DomainKey) {
				assert.Len(t, snapshot, 3)
				assert.Contains(t, snapshot, "example.com")
				assert.Contains(t, snapshot, "test.com")
				assert.Contains(t, snapshot, "demo.com")
			},
		},
		{
			name: "snapshot is independent copy",
			keys: []types.DomainKey{
				{Fqdn: "example.com", Key: "key1", File: "example.json"},
			},
			validate: func(t *testing.T, snapshot map[string]types.DomainKey) {
				// Modify snapshot
				snapshot["example.com"] = types.DomainKey{
					Fqdn: "example.com",
					Key:  "modified-key",
				}
				// Original value should remain unchanged
				assert.Equal(t, "modified-key", snapshot["example.com"].Key)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			k := NewKeys(ctx, tt.keys,
				WithCollector(metrics.NewCollector()),
			)
			snapshot := k.Snapshot()
			tt.validate(t, snapshot)
		})
	}
}

func TestKeys_AddKey(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	k := NewKeys(ctx, []types.DomainKey{},
		WithCollector(metrics.NewCollector()),
	)

	// Add first key
	key1 := types.DomainKey{Fqdn: "example.com", Key: "key1", File: "example.json"}
	k.AddKey("example.com", &key1)

	val, ok := k.Get("example.com")
	require.True(t, ok)
	assert.Equal(t, "key1", val.Key)

	// Add second key
	key2 := types.DomainKey{Fqdn: "test.com", Key: "key2", File: "test.json"}
	k.AddKey("test.com", &key2)

	val2, ok2 := k.Get("test.com")
	require.True(t, ok2)
	assert.Equal(t, "key2", val2.Key)

	// Verify workers are created
	assert.Len(t, k.workers, 2)
	assert.Contains(t, k.workers, "example.com")
	assert.Contains(t, k.workers, "test.com")
}

func TestKeys_ConcurrentAccess(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	k := NewKeys(ctx, []types.DomainKey{},
		WithCollector(metrics.NewCollector()),
	)

	var wg sync.WaitGroup
	numGoroutines := 10
	numOperations := 100

	// Concurrent Set operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := types.DomainKey{
					Fqdn:   "example.com",
					Key:    "key",
					File:   "example.json",
					Expire: time.UnixMicro(0).Unix(),
				}
				k.Set("example.com", key)
			}
		}(i)
	}

	// Concurrent Get operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				k.Get("example.com")
			}
		}(i)
	}

	// Concurrent Snapshot operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				k.Snapshot()
			}
		}(i)
	}

	wg.Wait()

	// Verify final state
	val, ok := k.Get("example.com")
	assert.True(t, ok)
	assert.Equal(t, "example.com", val.Fqdn)
}

func TestKeys_StartPeriodicFlush(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	flushCount := 0
	var mu sync.Mutex

	flushFunc := func(m map[string]types.DomainKey) error {
		mu.Lock()
		flushCount++
		mu.Unlock()
		return nil
	}

	keys := []types.DomainKey{
		{Fqdn: "example.com", Key: "key1", File: "example.json"},
	}

	k := NewKeys(ctx, keys,
		WithCollector(metrics.NewCollector()),
		WithDumpInterval(50*time.Millisecond),
		WithFlushFunc(flushFunc),
	)

	go k.StartPeriodicFlush()

	// Wait for context to expire
	<-ctx.Done()

	// Give a small buffer for the last flush to complete
	time.Sleep(10 * time.Millisecond)

	mu.Lock()
	count := flushCount
	mu.Unlock()

	// Should have flushed at least 2 times in 150ms with 50ms interval
	assert.GreaterOrEqual(t, count, 2, "expected at least 2 flush operations")
}

func TestKeys_FetchDomainKey(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	tests := []struct {
		name      string
		fqdn      string
		timeout   time.Duration
		wantError bool
	}{
		{
			name:      "invalid domain",
			fqdn:      "invalid-domain-that-does-not-exist.com",
			timeout:   2 * time.Second,
			wantError: true,
		},
		{
			name:      "empty fqdn",
			fqdn:      "",
			timeout:   2 * time.Second,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			k := NewKeys(ctx, []types.DomainKey{}, WithTimeout(tt.timeout))

			result, err := k.fetchDomainKey(tt.fqdn)

			if tt.wantError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.NotEmpty(t, result.Key)
				assert.NotZero(t, result.Expire)
			}
		})
	}
}
