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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	logger "gopkg.in/slog-handler.v1"

	"ssl-pinning/internal/signer"
	"ssl-pinning/internal/storage/types"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name       string
		dumpDir    string
		wantErr    bool
		wantErrMsg string
	}{
		{
			name:    "success with valid directory",
			dumpDir: filepath.Join(t.TempDir(), "test-dump"),
			wantErr: false,
		},
		{
			name:    "success creates nested directories",
			dumpDir: filepath.Join(t.TempDir(), "level1", "level2", "level3"),
			wantErr: false,
		},
		{
			name:       "error with invalid path",
			dumpDir:    "/proc/invalid/path",
			wantErr:    true,
			wantErrMsg: "failed to create dump directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := []types.Option{
				func(s types.Storage) {
					if fs, ok := s.(*Storage); ok {
						fs.WithDumpDir(tt.dumpDir)
					}
				},
			}

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

				// Verify directory was created
				_, err := os.Stat(tt.dumpDir)
				assert.NoError(t, err)
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

func TestStorage_WithDumpDir(t *testing.T) {
	tests := []struct {
		name    string
		dumpDir string
	}{
		{
			name:    "valid path",
			dumpDir: "/tmp/test-dump",
		},
		{
			name:    "relative path",
			dumpDir: "./test-dump",
		},
		{
			name:    "empty path",
			dumpDir: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Storage{}
			s.WithDumpDir(tt.dumpDir)
			assert.Equal(t, tt.dumpDir, s.dumpDir)
		})
	}
}

func TestStorage_WithSigner(t *testing.T) {
	tests := []struct {
		name   string
		signer *signer.Signer
	}{
		{
			name:   "valid signer",
			signer: &signer.Signer{},
		},
		{
			name:   "nil signer",
			signer: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Storage{}
			s.WithSigner(tt.signer)
			assert.Equal(t, tt.signer, s.signer)
		})
	}
}

func TestStorage_Close(t *testing.T) {
	s := &Storage{}
	err := s.Close()
	assert.NoError(t, err)
}

func TestStorage_SaveKeys(t *testing.T) {
	// Setup test signer
	testSigner := createTestSigner(t)

	now := time.Now()
	expire := now.Add(24 * time.Hour).Unix()

	tests := []struct {
		name       string
		keys       map[string]types.DomainKey
		wantErr    bool
		wantErrMsg string
		validate   func(t *testing.T, dumpDir string)
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
					LastError:  "",
				},
			},
			wantErr: false,
			validate: func(t *testing.T, dumpDir string) {
				// Verify file was created
				filePath := filepath.Join(dumpDir, "test-file.json")
				_, err := os.Stat(filePath)
				assert.NoError(t, err)

				// Verify file content is valid JSON
				data, err := os.ReadFile(filePath)
				assert.NoError(t, err)

				var fileStruct types.FileStructure
				err = json.Unmarshal(data, &fileStruct)
				assert.NoError(t, err)
				assert.Len(t, fileStruct.Payload.Keys, 1)
				assert.Equal(t, "www.example.com", fileStruct.Payload.Keys[0].Fqdn)
			},
		},
		{
			name: "success multiple keys same file",
			keys: map[string]types.DomainKey{
				"example1.com": {
					Date:       &now,
					DomainName: "example1.com",
					Expire:     expire,
					File:       "test-file.json",
					Fqdn:       "www.example1.com",
					Key:        "key1",
				},
				"example2.com": {
					Date:       &now,
					DomainName: "example2.com",
					Expire:     expire,
					File:       "test-file.json",
					Fqdn:       "www.example2.com",
					Key:        "key2",
				},
			},
			wantErr: false,
			validate: func(t *testing.T, dumpDir string) {
				filePath := filepath.Join(dumpDir, "test-file.json")
				data, err := os.ReadFile(filePath)
				assert.NoError(t, err)

				var fileStruct types.FileStructure
				err = json.Unmarshal(data, &fileStruct)
				assert.NoError(t, err)
				assert.Len(t, fileStruct.Payload.Keys, 2)
			},
		},
		{
			name: "error with empty key",
			keys: map[string]types.DomainKey{
				"example.com": {
					Date:       &now,
					DomainName: "example.com",
					Expire:     expire,
					File:       "test-file.json",
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
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dumpDir := t.TempDir()

			s := &Storage{
				appID:   "test-app",
				dumpDir: dumpDir,
				signer:  testSigner,
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
					tt.validate(t, dumpDir)
				}
			}
		})
	}
}

func TestStorage_GetByFile(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	tests := []struct {
		name       string
		file       string
		setup      func(t *testing.T, dumpDir string)
		wantErr    bool
		wantErrMsg string
		validate   func(t *testing.T, data []byte)
	}{
		{
			name: "success read existing file",
			file: "test-file.json",
			setup: func(t *testing.T, dumpDir string) {
				testData := []byte(`{"test": "data"}`)
				err := os.WriteFile(filepath.Join(dumpDir, "test-file.json"), testData, 0600)
				require.NoError(t, err)
			},
			wantErr: false,
			validate: func(t *testing.T, data []byte) {
				assert.Contains(t, string(data), "test")
			},
		},
		{
			name:       "error file not found",
			file:       "nonexistent.json",
			setup:      func(t *testing.T, dumpDir string) {},
			wantErr:    true,
			wantErrMsg: "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dumpDir := t.TempDir()

			s := &Storage{
				dumpDir: dumpDir,
			}

			tt.setup(t, dumpDir)

			keys, data, err := s.GetByFile(tt.file)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrMsg != "" {
					assert.Contains(t, err.Error(), tt.wantErrMsg)
				}
				assert.Nil(t, keys)
				assert.Nil(t, data)
			} else {
				assert.NoError(t, err)
				assert.Nil(t, keys) // filesystem always returns nil for keys
				assert.NotNil(t, data)
				if tt.validate != nil {
					tt.validate(t, data)
				}
			}
		})
	}
}

func TestStorage_ProbeLiveness(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	testSigner := createTestSigner(t)
	now := time.Now()
	staleTime := now.Add(-20 * time.Second)
	expire := now.Add(24 * time.Hour).Unix()

	tests := []struct {
		name             string
		setup            func(t *testing.T, dumpDir string, s *Storage)
		wantStatusCode   int
		wantBodyContains string
	}{
		{
			name: "healthy with fresh keys",
			setup: func(t *testing.T, dumpDir string, s *Storage) {
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
			name: "unhealthy with stale keys",
			setup: func(t *testing.T, dumpDir string, s *Storage) {
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
			name: "unhealthy with no files",
			setup: func(t *testing.T, dumpDir string, s *Storage) {
				// Don't create any files
			},
			wantStatusCode:   http.StatusServiceUnavailable,
			wantBodyContains: "no dump files found",
		},
		{
			name: "unhealthy with key errors",
			setup: func(t *testing.T, dumpDir string, s *Storage) {
				// Create file with keys that have errors
				fileStruct := types.FileStructure{
					Payload: types.FileKeys{
						Keys: []types.DomainKey{
							{
								Date:       &now,
								DomainName: "example.com",
								Expire:     expire,
								Fqdn:       "www.example.com",
								Key:        "test-key",
								LastError:  "some error",
							},
						},
					},
				}
				data, err := json.Marshal(fileStruct)
				require.NoError(t, err)
				err = os.WriteFile(filepath.Join(dumpDir, "test.json"), data, 0600)
				require.NoError(t, err)
			},
			wantStatusCode:   http.StatusServiceUnavailable,
			wantBodyContains: "has last_error",
		},
		{
			name: "unhealthy with missing date",
			setup: func(t *testing.T, dumpDir string, s *Storage) {
				fileStruct := types.FileStructure{
					Payload: types.FileKeys{
						Keys: []types.DomainKey{
							{
								Date:       nil, // Missing date
								DomainName: "example.com",
								Expire:     expire,
								Fqdn:       "www.example.com",
								Key:        "test-key",
							},
						},
					},
				}
				data, err := json.Marshal(fileStruct)
				require.NoError(t, err)
				err = os.WriteFile(filepath.Join(dumpDir, "test.json"), data, 0600)
				require.NoError(t, err)
			},
			wantStatusCode:   http.StatusServiceUnavailable,
			wantBodyContains: "missing date",
		},
		{
			name: "unhealthy with invalid json",
			setup: func(t *testing.T, dumpDir string, s *Storage) {
				err := os.WriteFile(filepath.Join(dumpDir, "test.json"), []byte("invalid json"), 0600)
				require.NoError(t, err)
			},
			wantStatusCode:   http.StatusServiceUnavailable,
			wantBodyContains: "failed to unmarshal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dumpDir := t.TempDir()

			s := &Storage{
				appID:   "test-app",
				dumpDir: dumpDir,
				signer:  testSigner,
			}

			tt.setup(t, dumpDir, s)

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

	testSigner := createTestSigner(t)
	now := time.Now()
	expire := now.Add(24 * time.Hour).Unix()

	tests := []struct {
		name             string
		setup            func(t *testing.T, dumpDir string, s *Storage)
		wantStatusCode   int
		wantBodyContains string
	}{
		{
			name: "ready with fresh files",
			setup: func(t *testing.T, dumpDir string, s *Storage) {
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
			name: "not ready with no files",
			setup: func(t *testing.T, dumpDir string, s *Storage) {
				// Don't create any files
			},
			wantStatusCode:   http.StatusServiceUnavailable,
			wantBodyContains: "no dump files found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dumpDir := t.TempDir()

			s := &Storage{
				appID:   "test-app",
				dumpDir: dumpDir,
				signer:  testSigner,
			}

			tt.setup(t, dumpDir, s)

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

func TestStorage_SaveFile_Atomic(t *testing.T) {
	dumpDir := t.TempDir()
	s := &Storage{
		dumpDir: dumpDir,
	}

	testData := []byte("test data")

	err := s.saveFile("test.txt", testData)
	assert.NoError(t, err)

	// Verify file was created
	filePath := filepath.Join(dumpDir, "test.txt")
	data, err := os.ReadFile(filePath)
	assert.NoError(t, err)
	assert.Equal(t, testData, data)

	// Verify no temp files left behind
	entries, err := os.ReadDir(dumpDir)
	assert.NoError(t, err)
	for _, entry := range entries {
		assert.NotContains(t, entry.Name(), ".tmp-")
	}
}

// createTestSigner creates a test signer with RSA keys for testing
func createTestSigner(t *testing.T) *signer.Signer {
	t.Helper()

	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create temp directory for keys
	keyDir := t.TempDir()

	// Write private key in PKCS8 format
	privateKeyPath := filepath.Join(keyDir, "private.pem")
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	err = os.WriteFile(privateKeyPath, privateKeyPEM, 0600)
	require.NoError(t, err)

	// Create signer
	s, err := signer.NewSigner(privateKeyPath)
	require.NoError(t, err)

	return s
}
