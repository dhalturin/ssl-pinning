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
package version

import (
	"encoding/json"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetVersion(t *testing.T) {
	tests := []struct {
		name          string
		setupVersion  string
		expectedEmpty bool
	}{
		{
			name:          "default version (empty)",
			setupVersion:  "",
			expectedEmpty: true,
		},
		{
			name:          "version set via ldflags",
			setupVersion:  "1.0.0",
			expectedEmpty: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original value
			originalVersion := version
			defer func() { version = originalVersion }()

			// Setup test version
			version = tt.setupVersion

			result := GetVersion()

			if tt.expectedEmpty {
				assert.Empty(t, result, "version should be empty")
			} else {
				assert.Equal(t, tt.setupVersion, result, "version should match setup value")
			}
		})
	}
}

func TestGet(t *testing.T) {
	tests := []struct {
		name            string
		setupVersion    string
		setupGitCommit  string
		validateGoVer   bool
		validateVersion bool
		validateCommit  bool
	}{
		{
			name:            "default values (empty)",
			setupVersion:    "",
			setupGitCommit:  "",
			validateGoVer:   true,
			validateVersion: false,
			validateCommit:  false,
		},
		{
			name:            "version and commit set",
			setupVersion:    "1.2.3",
			setupGitCommit:  "abc123def456",
			validateGoVer:   true,
			validateVersion: true,
			validateCommit:  true,
		},
		{
			name:            "only version set",
			setupVersion:    "2.0.0",
			setupGitCommit:  "",
			validateGoVer:   true,
			validateVersion: true,
			validateCommit:  false,
		},
		{
			name:            "only commit set",
			setupVersion:    "",
			setupGitCommit:  "fedcba987654",
			validateGoVer:   true,
			validateVersion: false,
			validateCommit:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original values
			originalVersion := version
			originalGitCommit := gitCommit
			defer func() {
				version = originalVersion
				gitCommit = originalGitCommit
			}()

			// Setup test values
			version = tt.setupVersion
			gitCommit = tt.setupGitCommit

			info := Get()

			// Validate BuildInfo structure
			assert.IsType(t, BuildInfo{}, info, "should return BuildInfo type")

			// Validate Version field
			if tt.validateVersion {
				assert.Equal(t, tt.setupVersion, info.Version, "version should match")
				assert.NotEmpty(t, info.Version, "version should not be empty")
			} else {
				assert.Empty(t, info.Version, "version should be empty")
			}

			// Validate GitCommit field
			if tt.validateCommit {
				assert.Equal(t, tt.setupGitCommit, info.GitCommit, "git commit should match")
				assert.NotEmpty(t, info.GitCommit, "git commit should not be empty")
			} else {
				assert.Empty(t, info.GitCommit, "git commit should be empty")
			}

			// Validate GoVersion field (always present)
			if tt.validateGoVer {
				assert.NotEmpty(t, info.GoVersion, "Go version should not be empty")
				assert.Equal(t, runtime.Version(), info.GoVersion, "Go version should match runtime")
				assert.Contains(t, info.GoVersion, "go", "Go version should contain 'go' prefix")
			}
		})
	}
}

func TestBuildInfo_JSONMarshaling(t *testing.T) {
	tests := []struct {
		name      string
		buildInfo BuildInfo
		wantJSON  string
	}{
		{
			name: "all fields populated",
			buildInfo: BuildInfo{
				Version:   "1.0.0",
				GitCommit: "abc123",
				GoVersion: "go1.21.0",
			},
			wantJSON: `{"version":"1.0.0","git_commit":"abc123","go_version":"go1.21.0"}`,
		},
		{
			name: "empty fields (omitempty)",
			buildInfo: BuildInfo{
				Version:   "",
				GitCommit: "",
				GoVersion: "",
			},
			wantJSON: `{}`,
		},
		{
			name: "partial fields",
			buildInfo: BuildInfo{
				Version:   "2.0.0",
				GitCommit: "",
				GoVersion: "go1.22.0",
			},
			wantJSON: `{"version":"2.0.0","go_version":"go1.22.0"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal to JSON
			jsonData, err := json.Marshal(tt.buildInfo)
			require.NoError(t, err, "should marshal without error")

			assert.JSONEq(t, tt.wantJSON, string(jsonData), "JSON should match expected")

			// Unmarshal back
			var decoded BuildInfo
			err = json.Unmarshal(jsonData, &decoded)
			require.NoError(t, err, "should unmarshal without error")

			if tt.buildInfo.Version != "" {
				assert.Equal(t, tt.buildInfo.Version, decoded.Version, "version should match after round-trip")
			}
			if tt.buildInfo.GitCommit != "" {
				assert.Equal(t, tt.buildInfo.GitCommit, decoded.GitCommit, "git commit should match after round-trip")
			}
			if tt.buildInfo.GoVersion != "" {
				assert.Equal(t, tt.buildInfo.GoVersion, decoded.GoVersion, "go version should match after round-trip")
			}
		})
	}
}

func TestBuildInfo_StructFields(t *testing.T) {
	info := BuildInfo{
		Version:   "3.0.0",
		GitCommit: "def456",
		GoVersion: "go1.23.0",
	}

	assert.Equal(t, "3.0.0", info.Version, "Version field should be accessible")
	assert.Equal(t, "def456", info.GitCommit, "GitCommit field should be accessible")
	assert.Equal(t, "go1.23.0", info.GoVersion, "GoVersion field should be accessible")
}

func TestGet_Concurrent(t *testing.T) {
	// Save original values
	originalVersion := version
	originalGitCommit := gitCommit
	defer func() {
		version = originalVersion
		gitCommit = originalGitCommit
	}()

	version = "1.0.0"
	gitCommit = "concurrent-test"

	const numGoroutines = 100
	done := make(chan BuildInfo, numGoroutines)

	// Call Get() concurrently
	for i := 0; i < numGoroutines; i++ {
		go func() {
			info := Get()
			done <- info
		}()
	}

	// Collect results
	for i := 0; i < numGoroutines; i++ {
		info := <-done
		assert.Equal(t, "1.0.0", info.Version, "version should be consistent")
		assert.Equal(t, "concurrent-test", info.GitCommit, "git commit should be consistent")
		assert.NotEmpty(t, info.GoVersion, "go version should not be empty")
	}
}

func TestGetVersion_Concurrent(t *testing.T) {
	// Save original value
	originalVersion := version
	defer func() { version = originalVersion }()

	version = "2.0.0"

	const numGoroutines = 100
	done := make(chan string, numGoroutines)

	// Call GetVersion() concurrently
	for i := 0; i < numGoroutines; i++ {
		go func() {
			ver := GetVersion()
			done <- ver
		}()
	}

	// Collect results
	for i := 0; i < numGoroutines; i++ {
		ver := <-done
		assert.Equal(t, "2.0.0", ver, "version should be consistent across goroutines")
	}
}

func BenchmarkGetVersion(b *testing.B) {
	version = "1.0.0"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = GetVersion()
	}
}

func BenchmarkGet(b *testing.B) {
	version = "1.0.0"
	gitCommit = "abc123"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Get()
	}
}

func BenchmarkGet_Parallel(b *testing.B) {
	version = "1.0.0"
	gitCommit = "abc123"

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = Get()
		}
	})
}

func BenchmarkBuildInfo_JSONMarshal(b *testing.B) {
	info := BuildInfo{
		Version:   "1.0.0",
		GitCommit: "abc123",
		GoVersion: runtime.Version(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(info)
	}
}
