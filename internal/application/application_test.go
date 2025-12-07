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
package application

import (
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

	"ssl-pinning/internal/server"
	"ssl-pinning/internal/signer"
	"ssl-pinning/internal/storage/types"
)

// mockStorage is a simple in-memory storage for testing
type mockStorage struct {
	keys        map[string][]types.DomainKey
	data        map[string][]byte
	closeCalled bool
	saveKeys    map[string]types.DomainKey
}

func newMockStorage() *mockStorage {
	return &mockStorage{
		keys:     make(map[string][]types.DomainKey),
		data:     make(map[string][]byte),
		saveKeys: make(map[string]types.DomainKey),
	}
}

func (m *mockStorage) GetByFile(file string) ([]types.DomainKey, []byte, error) {
	keys, keysOk := m.keys[file]
	data, dataOk := m.data[file]

	if !keysOk && !dataOk {
		return nil, nil, nil
	}

	return keys, data, nil
}

func (m *mockStorage) SaveKeys(keys map[string]types.DomainKey) error {
	for k, v := range keys {
		m.saveKeys[k] = v
	}
	return nil
}

func (m *mockStorage) Close() error {
	m.closeCalled = true
	return nil
}

func (m *mockStorage) WithAppID(appID string)              {}
func (m *mockStorage) WithDSN(dsn string)                  {}
func (m *mockStorage) WithDumpDir(dumpDir string)          {}
func (m *mockStorage) WithSigner(signer *signer.Signer)    {}
func (m *mockStorage) WithConnMaxIdleTime(d time.Duration) {}
func (m *mockStorage) WithConnMaxLifetime(d time.Duration) {}
func (m *mockStorage) WithMaxIdleConns(n int)              {}
func (m *mockStorage) WithMaxOpenConns(n int)              {}
func (m *mockStorage) ProbeLiveness() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
}
func (m *mockStorage) ProbeReadiness() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
}
func (m *mockStorage) ProbeStartup() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
}

// setupTestSigner creates a test RSA key pair and signer
func setupTestSigner(t *testing.T) (*signer.Signer, string) {
	t.Helper()

	tmpDir := t.TempDir()
	privKeyPath := filepath.Join(tmpDir, "prv.pem")

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Marshal private key to PKCS8
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)

	// Write private key to file
	privKeyFile, err := os.Create(privKeyPath)
	require.NoError(t, err)

	err = pem.Encode(privKeyFile, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyBytes,
	})
	require.NoError(t, err)
	privKeyFile.Close()

	// Create signer
	signer, err := signer.NewSigner(privKeyPath)
	require.NoError(t, err)

	return signer, tmpDir
}

func TestApp_handleFileJSON(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	now := time.Now()
	expire := now.Add(24 * time.Hour).Unix()

	testSigner, _ := setupTestSigner(t)

	tests := []struct {
		name           string
		file           string
		setupStorage   func(m *mockStorage)
		setupSigner    bool
		wantStatusCode int
		wantBody       string
		validate       func(t *testing.T, body string)
	}{
		{
			name: "success with single key returns data",
			file: "test.json",
			setupStorage: func(m *mockStorage) {
				m.data["test.json"] = []byte(`{"test":"data"}`)
				m.keys["test.json"] = []types.DomainKey{
					{
						Date:       &now,
						DomainName: "example.com",
						Expire:     expire,
						Fqdn:       "www.example.com",
						Key:        "test-key",
					},
				}
			},
			setupSigner:    true,
			wantStatusCode: http.StatusOK,
			validate: func(t *testing.T, body string) {
				assert.Equal(t, `{"test":"data"}`, body)
			},
		},
		{
			name: "success with multiple keys returns signed data",
			file: "test.json",
			setupStorage: func(m *mockStorage) {
				m.keys["test.json"] = []types.DomainKey{
					{
						Date:       &now,
						DomainName: "example1.com",
						Expire:     expire,
						Fqdn:       "www.example1.com",
						Key:        "key1",
					},
					{
						Date:       &now,
						DomainName: "example2.com",
						Expire:     expire,
						Fqdn:       "www.example2.com",
						Key:        "key2",
					},
				}
			},
			setupSigner:    true,
			wantStatusCode: http.StatusOK,
			validate: func(t *testing.T, body string) {
				var result types.FileStructure
				err := json.Unmarshal([]byte(body), &result)
				require.NoError(t, err)
				assert.NotEmpty(t, result.Signature)
				assert.Len(t, result.Payload.Keys, 2)
			},
		},
		{
			name: "error missing file parameter",
			file: "",
			setupStorage: func(m *mockStorage) {
				// No setup needed
			},
			setupSigner:    true,
			wantStatusCode: http.StatusBadRequest,
			wantBody:       "file required",
		},
		{
			name: "error file not found",
			file: "nonexistent.json",
			setupStorage: func(m *mockStorage) {
				// No data for this file
			},
			setupSigner:    true,
			wantStatusCode: http.StatusNotFound,
			wantBody:       "file nonexistent.json not found",
		},
		{
			name: "success with no keys and no data",
			file: "empty.json",
			setupStorage: func(m *mockStorage) {
				m.keys["empty.json"] = []types.DomainKey{}
			},
			setupSigner:    true,
			wantStatusCode: http.StatusNotFound,
			wantBody:       "file empty.json not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := newMockStorage()
			tt.setupStorage(storage)

			var appSigner *signer.Signer
			if tt.setupSigner {
				appSigner = testSigner
			}

			app := &App{
				storage: storage,
				signer:  appSigner,
			}

			// Create request
			path := "/api/v1/" + tt.file
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.SetPathValue("file", tt.file)
			w := httptest.NewRecorder()

			// Call handler
			app.handleFileJSON(w, req)

			// Validate response
			assert.Equal(t, tt.wantStatusCode, w.Code)

			if tt.wantBody != "" {
				assert.Contains(t, w.Body.String(), tt.wantBody)
			}

			if tt.validate != nil {
				tt.validate(t, w.Body.String())
			}
		})
	}
}

func TestApp_Down(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() *App
		wantErr  bool
		validate func(t *testing.T, app *App)
	}{
		{
			name: "success closes storage",
			setup: func() *App {
				storage := newMockStorage()
				// Create minimal servers with context
				srvHttp := server.NewServer(server.WithAddr("127.0.0.1:0"))
				srvMetrics := server.NewServer(server.WithAddr("127.0.0.1:0"))
				return &App{
					storage:       storage,
					serverHttp:    srvHttp,
					serverMetrics: srvMetrics,
				}
			},
			wantErr: false,
			validate: func(t *testing.T, app *App) {
				mockStore := app.storage.(*mockStorage)
				assert.True(t, mockStore.closeCalled)
			},
		},
		{
			name: "success with nil storage",
			setup: func() *App {
				srvHttp := server.NewServer(server.WithAddr("127.0.0.1:0"))
				srvMetrics := server.NewServer(server.WithAddr("127.0.0.1:0"))
				return &App{
					storage:       nil,
					serverHttp:    srvHttp,
					serverMetrics: srvMetrics,
				}
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := tt.setup()

			err := app.Down()

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.validate != nil {
				tt.validate(t, app)
			}
		})
	}
}

func TestApp_handleFileJSON_WithRealStorage(t *testing.T) {
	// Test with actual storage integration
	now := time.Now()
	expire := now.Add(24 * time.Hour).Unix()

	testSigner, _ := setupTestSigner(t)

	// Create a mock storage with real data
	storage := newMockStorage()
	storage.keys["domains.json"] = []types.DomainKey{
		{
			Date:       &now,
			DomainName: "example.com",
			Expire:     expire,
			Fqdn:       "www.example.com",
			Key:        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA",
		},
		{
			Date:       &now,
			DomainName: "test.com",
			Expire:     expire,
			Fqdn:       "api.test.com",
			Key:        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEB",
		},
	}

	app := &App{
		storage: storage,
		signer:  testSigner,
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/domains.json", nil)
	req.SetPathValue("file", "domains.json")
	w := httptest.NewRecorder()

	app.handleFileJSON(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var result types.FileStructure
	err := json.Unmarshal(w.Body.Bytes(), &result)
	require.NoError(t, err)

	assert.NotEmpty(t, result.Signature)
	assert.Len(t, result.Payload.Keys, 2)

	// Verify keys are present
	fqdns := make([]string, len(result.Payload.Keys))
	for i, key := range result.Payload.Keys {
		fqdns[i] = key.Fqdn
	}
	assert.Contains(t, fqdns, "www.example.com")
	assert.Contains(t, fqdns, "api.test.com")
}

// mockStorageWithError simulates storage errors
type mockStorageWithError struct {
	*mockStorage
	getByFileError bool
}

func (m *mockStorageWithError) GetByFile(file string) ([]types.DomainKey, []byte, error) {
	if m.getByFileError {
		return nil, nil, assert.AnError
	}
	return m.mockStorage.GetByFile(file)
}

func TestApp_handleFileJSON_StorageErrors(t *testing.T) {
	testSigner, _ := setupTestSigner(t)

	storage := &mockStorageWithError{
		mockStorage:    newMockStorage(),
		getByFileError: true,
	}

	app := &App{
		storage: storage,
		signer:  testSigner,
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/test.json", nil)
	req.SetPathValue("file", "test.json")
	w := httptest.NewRecorder()

	app.handleFileJSON(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestApp_Down_Integration(t *testing.T) {
	// Test Down with all components
	storage := newMockStorage()

	srvHttp := server.NewServer(server.WithAddr("127.0.0.1:0"))
	srvMetrics := server.NewServer(server.WithAddr("127.0.0.1:0"))

	app := &App{
		storage:       storage,
		serverHttp:    srvHttp,
		serverMetrics: srvMetrics,
	}

	err := app.Down()
	assert.NoError(t, err)

	// Verify storage was closed
	assert.True(t, storage.closeCalled)
}

func BenchmarkApp_handleFileJSON_SingleKey(b *testing.B) {
	now := time.Now()
	expire := now.Add(24 * time.Hour).Unix()

	testSigner, _ := setupTestSigner(&testing.T{})

	storage := newMockStorage()
	storage.data["test.json"] = []byte(`{"test":"data"}`)
	storage.keys["test.json"] = []types.DomainKey{
		{
			Date:       &now,
			DomainName: "example.com",
			Expire:     expire,
			Fqdn:       "www.example.com",
			Key:        "test-key",
		},
	}

	app := &App{
		storage: storage,
		signer:  testSigner,
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/test.json", nil)
	req.SetPathValue("file", "test.json")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		app.handleFileJSON(w, req)
	}
}

func BenchmarkApp_handleFileJSON_MultipleKeys(b *testing.B) {
	now := time.Now()
	expire := now.Add(24 * time.Hour).Unix()

	testSigner, _ := setupTestSigner(&testing.T{})

	storage := newMockStorage()
	storage.keys["test.json"] = []types.DomainKey{
		{
			Date:       &now,
			DomainName: "example1.com",
			Expire:     expire,
			Fqdn:       "www.example1.com",
			Key:        "key1",
		},
		{
			Date:       &now,
			DomainName: "example2.com",
			Expire:     expire,
			Fqdn:       "www.example2.com",
			Key:        "key2",
		},
	}

	app := &App{
		storage: storage,
		signer:  testSigner,
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/test.json", nil)
	req.SetPathValue("file", "test.json")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		app.handleFileJSON(w, req)
	}
}
