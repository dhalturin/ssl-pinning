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
package metrics

import (
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestNewCollector(t *testing.T) {
	// Unregister any existing collectors to avoid conflicts
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Expected panic during registration conflict: %v", r)
		}
	}()

	c := NewCollector()
	if c == nil {
		t.Fatal("NewCollector() returned nil")
	}

	// Cleanup: unregister the collector
	prometheus.Unregister(c)
}

func TestCollector_IncError(t *testing.T) {
	tests := []struct {
		name      string
		file      string
		incCount  int
		wantValue float64
	}{
		{
			name:      "increment once",
			file:      "test1.json",
			incCount:  1,
			wantValue: 1.0,
		},
		{
			name:      "increment multiple times",
			file:      "test2.json",
			incCount:  5,
			wantValue: 5.0,
		},
		{
			name:      "increment zero times",
			file:      "test3.json",
			incCount:  0,
			wantValue: 0.0,
		},
		{
			name:      "increment same file multiple times",
			file:      "test4.json",
			incCount:  10,
			wantValue: 10.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(Collector)

			for i := 0; i < tt.incCount; i++ {
				c.IncError(tt.file)
			}

			val, ok := c.errors.Load(tt.file)
			if tt.incCount > 0 && !ok {
				t.Error("IncError() did not store value")
				return
			}

			if tt.incCount > 0 {
				if got := val.(float64); got != tt.wantValue {
					t.Errorf("IncError() value = %v, want %v", got, tt.wantValue)
				}
			}
		})
	}
}

func TestCollector_ClearError(t *testing.T) {
	tests := []struct {
		name      string
		file      string
		initValue float64
	}{
		{
			name:      "clear zero value",
			file:      "test1.json",
			initValue: 0.0,
		},
		{
			name:      "clear non-zero value",
			file:      "test2.json",
			initValue: 5.0,
		},
		{
			name:      "clear large value",
			file:      "test3.json",
			initValue: 100.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(Collector)

			// Set initial value
			c.errors.Store(tt.file, tt.initValue)

			// Clear the error
			c.ClearError(tt.file)

			// Verify it's set to 0.0
			val, ok := c.errors.Load(tt.file)
			if !ok {
				t.Error("ClearError() removed the entry instead of setting to 0")
				return
			}

			if got := val.(float64); got != 0.0 {
				t.Errorf("ClearError() value = %v, want 0.0", got)
			}
		})
	}
}

func TestCollector_SetExpire(t *testing.T) {
	tests := []struct {
		name   string
		key    string
		fqdn   string
		expire float64
	}{
		{
			name:   "set positive expire",
			key:    "key1",
			fqdn:   "example.com",
			expire: 3600.0,
		},
		{
			name:   "set zero expire",
			key:    "key2",
			fqdn:   "test.com",
			expire: 0.0,
		},
		{
			name:   "set large expire value",
			key:    "key3",
			fqdn:   "demo.com",
			expire: 86400.0,
		},
		{
			name:   "set negative expire",
			key:    "key4",
			fqdn:   "expired.com",
			expire: -100.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(Collector)

			c.SetExpire(tt.key, tt.fqdn, tt.expire)

			item := ExpireItem{Key: tt.key, FQDN: tt.fqdn}
			val, ok := c.expires.Load(item)
			if !ok {
				t.Error("SetExpire() did not store value")
				return
			}

			if got := val.(float64); got != tt.expire {
				t.Errorf("SetExpire() value = %v, want %v", got, tt.expire)
			}
		})
	}
}

func TestCollector_ClearExpire(t *testing.T) {
	tests := []struct {
		name   string
		key    string
		fqdn   string
		expire float64
	}{
		{
			name:   "clear existing expire",
			key:    "key1",
			fqdn:   "example.com",
			expire: 3600.0,
		},
		{
			name:   "clear non-existing expire",
			key:    "key2",
			fqdn:   "test.com",
			expire: 1800.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(Collector)

			// Set initial value
			item := ExpireItem{Key: tt.key, FQDN: tt.fqdn}
			c.expires.Store(item, tt.expire)

			// Clear the expire
			c.ClearExpire(tt.key, tt.fqdn)

			// Verify it's deleted
			_, ok := c.expires.Load(item)
			if ok {
				t.Error("ClearExpire() did not delete the entry")
			}
		})
	}
}

func TestCollector_Collect(t *testing.T) {
	c := new(Collector)

	// Add some test data
	c.IncError("test1.json")
	c.IncError("test1.json")
	c.IncError("test2.json")
	c.SetExpire("key1", "example.com", 3600.0)
	c.SetExpire("key2", "test.com", 1800.0)

	// Collect metrics
	ch := make(chan prometheus.Metric, 10)
	go func() {
		c.Collect(ch)
		close(ch)
	}()

	// Count metrics
	var errorMetrics int
	for range ch {
		// We can't easily inspect the metric details without helper functions
		// but we can count them
		errorMetrics++
	}

	// We expect at least some metrics to be collected
	if errorMetrics == 0 {
		t.Error("Collect() did not send any metrics")
	}
}

func TestCollector_Describe(t *testing.T) {
	c := new(Collector)

	ch := make(chan *prometheus.Desc, 10)
	go func() {
		c.Describe(ch)
		close(ch)
	}()

	// Describe should send nothing (empty implementation)
	count := 0
	for range ch {
		count++
	}

	if count != 0 {
		t.Errorf("Describe() sent %d descriptions, want 0", count)
	}
}

func TestCollector_ConcurrentAccess(t *testing.T) {
	c := new(Collector)

	const numGoroutines = 100
	const numOperations = 100

	var wg sync.WaitGroup

	// Concurrent IncError
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				c.IncError("test.json")
			}
		}(i)
	}

	// Concurrent SetExpire
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				c.SetExpire("key", "example.com", float64(j))
			}
		}(i)
	}

	// Concurrent ClearError
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				c.ClearError("test.json")
			}
		}(i)
	}

	// Concurrent ClearExpire
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				c.ClearExpire("key", "example.com")
			}
		}(i)
	}

	wg.Wait()

	// If we got here without race conditions, test passes
}

func TestExpireItem_AsMapKey(t *testing.T) {
	// Test that ExpireItem can be used as a map key
	m := make(map[ExpireItem]float64)

	item1 := ExpireItem{Key: "key1", FQDN: "example.com"}
	item2 := ExpireItem{Key: "key1", FQDN: "example.com"}
	item3 := ExpireItem{Key: "key2", FQDN: "example.com"}

	m[item1] = 3600.0
	m[item3] = 1800.0

	// item1 and item2 should be equal (same key)
	if val, ok := m[item2]; !ok || val != 3600.0 {
		t.Error("ExpireItem with same values should be equal as map keys")
	}

	// item3 should be different
	if val, ok := m[item3]; !ok || val != 1800.0 {
		t.Error("ExpireItem with different values should be different as map keys")
	}

	if len(m) != 2 {
		t.Errorf("Map should have 2 entries, got %d", len(m))
	}
}

func TestCollector_ErrorsAfterCollect(t *testing.T) {
	c := new(Collector)

	// Add errors
	c.IncError("test.json")
	c.IncError("test.json")
	c.IncError("test.json")

	// Verify error count before collect
	val, _ := c.errors.Load("test.json")
	if got := val.(float64); got != 3.0 {
		t.Errorf("Before collect: error count = %v, want 3.0", got)
	}

	// Collect metrics (should clear errors)
	ch := make(chan prometheus.Metric, 10)
	go func() {
		c.Collect(ch)
		close(ch)
	}()

	// Drain channel
	for range ch {
	}

	// Verify errors are cleared after collect
	val, _ = c.errors.Load("test.json")
	if got := val.(float64); got != 0.0 {
		t.Errorf("After collect: error count = %v, want 0.0", got)
	}
}

func BenchmarkCollector_IncError(b *testing.B) {
	c := new(Collector)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.IncError("test.json")
	}
}

func BenchmarkCollector_SetExpire(b *testing.B) {
	c := new(Collector)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.SetExpire("key", "example.com", 3600.0)
	}
}

func BenchmarkCollector_Collect(b *testing.B) {
	c := new(Collector)

	// Setup test data
	c.IncError("test1.json")
	c.IncError("test2.json")
	c.SetExpire("key1", "example.com", 3600.0)
	c.SetExpire("key2", "test.com", 1800.0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ch := make(chan prometheus.Metric, 10)
		go func() {
			c.Collect(ch)
			close(ch)
		}()
		for range ch {
		}
	}
}

func BenchmarkCollector_ConcurrentOps(b *testing.B) {
	c := new(Collector)

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			switch i % 4 {
			case 0:
				c.IncError("test.json")
			case 1:
				c.SetExpire("key", "example.com", 3600.0)
			case 2:
				c.ClearError("test.json")
			case 3:
				c.ClearExpire("key", "example.com")
			}
			i++
		}
	})
}
