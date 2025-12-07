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
package types

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	logger "gopkg.in/slog-handler.v1"

	"ssl-pinning/internal/signer"
)

func setupTestSigner(t *testing.T) *signer.Signer {
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

	return signer
}

func TestDomainKey_JSON(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	now := time.Now()
	expire := now.Add(24 * time.Hour).Unix()

	tests := []struct {
		name     string
		key      DomainKey
		validate func(t *testing.T, data []byte)
	}{
		{
			name: "complete domain key",
			key: DomainKey{
				AppID:      "test-app",
				Date:       &now,
				DomainName: "example.com",
				Expire:     expire,
				File:       "test.json",
				Fqdn:       "www.example.com",
				Key:        "test-key-data",
				LastError:  "",
			},
			validate: func(t *testing.T, data []byte) {
				var decoded DomainKey
				err := json.Unmarshal(data, &decoded)
				require.NoError(t, err)
				assert.Equal(t, "test-app", decoded.AppID)
				assert.Equal(t, "example.com", decoded.DomainName)
				assert.Equal(t, "www.example.com", decoded.Fqdn)
				assert.Equal(t, "test-key-data", decoded.Key)
			},
		},
		{
			name: "domain key with last error",
			key: DomainKey{
				DomainName: "example.com",
				Fqdn:       "www.example.com",
				Key:        "test-key",
				LastError:  "connection timeout",
			},
			validate: func(t *testing.T, data []byte) {
				var decoded DomainKey
				err := json.Unmarshal(data, &decoded)
				require.NoError(t, err)
				assert.Equal(t, "connection timeout", decoded.LastError)
			},
		},
		{
			name: "minimal domain key",
			key: DomainKey{
				Fqdn: "www.example.com",
				Key:  "key",
			},
			validate: func(t *testing.T, data []byte) {
				var decoded DomainKey
				err := json.Unmarshal(data, &decoded)
				require.NoError(t, err)
				assert.Equal(t, "www.example.com", decoded.Fqdn)
				assert.Equal(t, "key", decoded.Key)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.key)
			require.NoError(t, err)
			assert.NotEmpty(t, data)

			if tt.validate != nil {
				tt.validate(t, data)
			}
		})
	}
}

func TestFileStructure_JSON(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	tests := []struct {
		name      string
		structure FileStructure
		validate  func(t *testing.T, data []byte)
	}{
		{
			name: "complete file structure",
			structure: FileStructure{
				Payload: FileKeys{
					Keys: []DomainKey{
						{
							Fqdn: "www.example.com",
							Key:  "key1",
						},
					},
				},
				Signature: "test-signature",
			},
			validate: func(t *testing.T, data []byte) {
				var decoded FileStructure
				err := json.Unmarshal(data, &decoded)
				require.NoError(t, err)
				assert.Equal(t, "test-signature", decoded.Signature)
				assert.Len(t, decoded.Payload.Keys, 1)
				assert.Equal(t, "www.example.com", decoded.Payload.Keys[0].Fqdn)
			},
		},
		{
			name: "empty payload",
			structure: FileStructure{
				Signature: "sig",
			},
			validate: func(t *testing.T, data []byte) {
				var decoded FileStructure
				err := json.Unmarshal(data, &decoded)
				require.NoError(t, err)
				assert.Equal(t, "sig", decoded.Signature)
				assert.Len(t, decoded.Payload.Keys, 0)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.structure)
			require.NoError(t, err)
			assert.NotEmpty(t, data)

			if tt.validate != nil {
				tt.validate(t, data)
			}
		})
	}
}

func TestStorageType_Constants(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	tests := []struct {
		name     string
		storType StorageType
		want     string
	}{
		{
			name:     "filesystem storage",
			storType: StorageFS,
			want:     "fs",
		},
		{
			name:     "memory storage",
			storType: StorageMemory,
			want:     "memory",
		},
		{
			name:     "redis storage",
			storType: StorageRedis,
			want:     "redis",
		},
		{
			name:     "postgres storage",
			storType: StoragePostgres,
			want:     "postgres",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, string(tt.storType))
		})
	}
}

func TestOption_WithAppID(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	// Mock storage for testing options
	mockStorage := &mockStorageImpl{}

	opt := WithAppID("test-app-123")
	opt(mockStorage)

	assert.Equal(t, "test-app-123", mockStorage.appID)
}

func TestOption_WithDSN(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	mockStorage := &mockStorageImpl{}

	opt := WithDSN("postgres://localhost:5432/db")
	opt(mockStorage)

	assert.Equal(t, "postgres://localhost:5432/db", mockStorage.dsn)
}

func TestOption_WithDumpDir(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	mockStorage := &mockStorageImpl{}

	opt := WithDumpDir("/tmp/dumps")
	opt(mockStorage)

	assert.Equal(t, "/tmp/dumps", mockStorage.dumpDir)
}

func TestOption_WithSigner(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	mockStorage := &mockStorageImpl{}
	testSigner := setupTestSigner(t)

	opt := WithSigner(testSigner)
	opt(mockStorage)

	assert.NotNil(t, mockStorage.signer)
}

func TestOption_WithConnMaxIdleTime(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	mockStorage := &mockStorageImpl{}

	opt := WithConnMaxIdleTime(5 * time.Minute)
	opt(mockStorage)

	assert.Equal(t, 5*time.Minute, mockStorage.connMaxIdleTime)
}

func TestOption_WithConnMaxLifetime(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	mockStorage := &mockStorageImpl{}

	opt := WithConnMaxLifetime(10 * time.Minute)
	opt(mockStorage)

	assert.Equal(t, 10*time.Minute, mockStorage.connMaxLifetime)
}

func TestOption_WithMaxIdleConns(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	mockStorage := &mockStorageImpl{}

	opt := WithMaxIdleConns(10)
	opt(mockStorage)

	assert.Equal(t, 10, mockStorage.maxIdleConns)
}

func TestOption_WithMaxOpenConns(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	mockStorage := &mockStorageImpl{}

	opt := WithMaxOpenConns(100)
	opt(mockStorage)

	assert.Equal(t, 100, mockStorage.maxOpenConns)
}

func TestSignedKeys(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	now := time.Now()
	expire := now.Add(24 * time.Hour).Unix()

	testSigner := setupTestSigner(t)

	tests := []struct {
		name       string
		file       string
		keys       []DomainKey
		signer     *signer.Signer
		wantErr    bool
		wantErrMsg string
		validate   func(t *testing.T, result []byte)
	}{
		{
			name: "success with single key",
			file: "test.json",
			keys: []DomainKey{
				{
					Date:       &now,
					DomainName: "example.com",
					Expire:     expire,
					Fqdn:       "www.example.com",
					Key:        "test-key",
				},
			},
			signer:  testSigner,
			wantErr: false,
			validate: func(t *testing.T, result []byte) {
				var structure FileStructure
				err := json.Unmarshal(result, &structure)
				require.NoError(t, err)
				assert.NotEmpty(t, structure.Signature)
				assert.Len(t, structure.Payload.Keys, 1)
				assert.Equal(t, "www.example.com", structure.Payload.Keys[0].Fqdn)
			},
		},
		{
			name: "success with multiple keys sorted by expire",
			file: "domains.json",
			keys: []DomainKey{
				{
					Date:       &now,
					DomainName: "example2.com",
					Expire:     expire + 1000, // Later expire
					Fqdn:       "www.example2.com",
					Key:        "key2",
				},
				{
					Date:       &now,
					DomainName: "example1.com",
					Expire:     expire, // Earlier expire
					Fqdn:       "www.example1.com",
					Key:        "key1",
				},
			},
			signer:  testSigner,
			wantErr: false,
			validate: func(t *testing.T, result []byte) {
				var structure FileStructure
				err := json.Unmarshal(result, &structure)
				require.NoError(t, err)
				assert.NotEmpty(t, structure.Signature)
				assert.Len(t, structure.Payload.Keys, 2)
				// Should be sorted by expire (ascending)
				assert.Equal(t, "www.example1.com", structure.Payload.Keys[0].Fqdn)
				assert.Equal(t, "www.example2.com", structure.Payload.Keys[1].Fqdn)
			},
		},
		{
			name:       "returns nil with empty keys",
			file:       "empty.json",
			keys:       []DomainKey{},
			signer:     testSigner,
			wantErr:    false,
			wantErrMsg: "",
			validate: func(t *testing.T, result []byte) {
				assert.Nil(t, result)
			},
		},
		{
			name:    "returns nil with nil keys",
			file:    "nil.json",
			keys:    nil,
			signer:  testSigner,
			wantErr: false,
			validate: func(t *testing.T, result []byte) {
				assert.Nil(t, result)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SignedKeys(tt.file, tt.keys, tt.signer)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrMsg != "" {
					assert.Contains(t, err.Error(), tt.wantErrMsg)
				}
			} else {
				assert.NoError(t, err)
			}

			if tt.validate != nil {
				tt.validate(t, result)
			}
		})
	}
}

func TestSignedKeys_JSONFormatting(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	now := time.Now()
	expire := now.Add(24 * time.Hour).Unix()

	testSigner := setupTestSigner(t)

	keys := []DomainKey{
		{
			Date:       &now,
			DomainName: "example.com",
			Expire:     expire,
			Fqdn:       "www.example.com",
			Key:        "test-key",
		},
	}

	result, err := SignedKeys("test.json", keys, testSigner)
	require.NoError(t, err)

	// Verify it's valid indented JSON
	assert.Contains(t, string(result), "  ")
	assert.Contains(t, string(result), "payload")
	assert.Contains(t, string(result), "signature")

	// Verify it can be unmarshaled
	var structure FileStructure
	err = json.Unmarshal(result, &structure)
	require.NoError(t, err)
}

func TestSignedKeys_SignatureVerification(t *testing.T) {
	logger.SetGlobalLogger(logger.Options{Null: true})

	now := time.Now()
	expire := now.Add(24 * time.Hour).Unix()

	testSigner := setupTestSigner(t)

	keys := []DomainKey{
		{
			Date:       &now,
			DomainName: "example.com",
			Expire:     expire,
			Fqdn:       "www.example.com",
			Key:        "test-key",
		},
	}

	result1, err := SignedKeys("test.json", keys, testSigner)
	require.NoError(t, err)

	result2, err := SignedKeys("test.json", keys, testSigner)
	require.NoError(t, err)

	// Signatures should be identical for same input
	var struct1, struct2 FileStructure
	json.Unmarshal(result1, &struct1)
	json.Unmarshal(result2, &struct2)

	assert.Equal(t, struct1.Signature, struct2.Signature)
}

// mockStorageImpl is a mock implementation for testing Option functions
type mockStorageImpl struct {
	appID           string
	dsn             string
	dumpDir         string
	signer          *signer.Signer
	connMaxIdleTime time.Duration
	connMaxLifetime time.Duration
	maxIdleConns    int
	maxOpenConns    int
}

func (m *mockStorageImpl) Close() error                                  { return nil }
func (m *mockStorageImpl) GetByFile(string) ([]DomainKey, []byte, error) { return nil, nil, nil }
func (m *mockStorageImpl) ProbeLiveness() func(w http.ResponseWriter, r *http.Request) {
	return nil
}
func (m *mockStorageImpl) ProbeReadiness() func(w http.ResponseWriter, r *http.Request) {
	return nil
}
func (m *mockStorageImpl) ProbeStartup() func(w http.ResponseWriter, r *http.Request) { return nil }
func (m *mockStorageImpl) SaveKeys(map[string]DomainKey) error                        { return nil }
func (m *mockStorageImpl) WithAppID(appID string)                                     { m.appID = appID }
func (m *mockStorageImpl) WithDSN(dsn string)                                         { m.dsn = dsn }
func (m *mockStorageImpl) WithDumpDir(dir string)                                     { m.dumpDir = dir }
func (m *mockStorageImpl) WithSigner(s *signer.Signer)                                { m.signer = s }
func (m *mockStorageImpl) WithConnMaxIdleTime(d time.Duration)                        { m.connMaxIdleTime = d }
func (m *mockStorageImpl) WithConnMaxLifetime(d time.Duration)                        { m.connMaxLifetime = d }
func (m *mockStorageImpl) WithMaxIdleConns(n int)                                     { m.maxIdleConns = n }
func (m *mockStorageImpl) WithMaxOpenConns(n int)                                     { m.maxOpenConns = n }

func BenchmarkSignedKeys_SingleKey(b *testing.B) {
	now := time.Now()
	expire := now.Add(24 * time.Hour).Unix()

	testSigner := setupTestSigner(&testing.T{})

	keys := []DomainKey{
		{
			Date:       &now,
			DomainName: "example.com",
			Expire:     expire,
			Fqdn:       "www.example.com",
			Key:        "test-key",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SignedKeys("test.json", keys, testSigner)
	}
}

func BenchmarkSignedKeys_MultipleKeys(b *testing.B) {
	now := time.Now()
	expire := now.Add(24 * time.Hour).Unix()

	testSigner := setupTestSigner(&testing.T{})

	keys := make([]DomainKey, 10)
	for i := 0; i < 10; i++ {
		keys[i] = DomainKey{
			Date:       &now,
			DomainName: "example.com",
			Expire:     expire + int64(i*1000),
			Fqdn:       "www.example.com",
			Key:        "test-key",
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SignedKeys("test.json", keys, testSigner)
	}
}

func BenchmarkDomainKey_Marshal(b *testing.B) {
	now := time.Now()
	expire := now.Add(24 * time.Hour).Unix()

	key := DomainKey{
		AppID:      "test-app",
		Date:       &now,
		DomainName: "example.com",
		Expire:     expire,
		File:       "test.json",
		Fqdn:       "www.example.com",
		Key:        "test-key-data",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(key)
	}
}

func BenchmarkDomainKey_Unmarshal(b *testing.B) {
	data := []byte(`{"app_id":"test-app","domainName":"example.com","expire":1735689600,"file":"test.json","fqdn":"www.example.com","key":"test-key-data"}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var key DomainKey
		_ = json.Unmarshal(data, &key)
	}
}
