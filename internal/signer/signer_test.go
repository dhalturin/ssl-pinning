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
package signer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestKeyPair generates RSA key pair for testing
func generateTestKeyPair(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "failed to generate RSA key pair")
	return privateKey, &privateKey.PublicKey
}

// createTestPrivateKeyFile creates a temporary PEM file with private key
func createTestPrivateKeyFile(t *testing.T, privateKey *rsa.PrivateKey) string {
	t.Helper()

	privDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err, "failed to marshal private key")

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privDER,
	})

	tmpFile := filepath.Join(t.TempDir(), "test_private.pem")
	err = os.WriteFile(tmpFile, privPEM, 0600)
	require.NoError(t, err, "failed to write private key file")

	return tmpFile
}

func TestNewSigner(t *testing.T) {
	privateKey, _ := generateTestKeyPair(t)
	validKeyPath := createTestPrivateKeyFile(t, privateKey)

	tests := []struct {
		name        string
		keyPath     string
		setupFunc   func(t *testing.T) string
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid private key",
			keyPath: validKeyPath,
			wantErr: false,
		},
		{
			name:        "non-existent file",
			keyPath:     "/nonexistent/path/key.pem",
			wantErr:     true,
			errContains: "failed to read private key file",
		},
		{
			name: "invalid PEM format",
			setupFunc: func(t *testing.T) string {
				tmpFile := filepath.Join(t.TempDir(), "invalid.pem")
				err := os.WriteFile(tmpFile, []byte("not a valid PEM file"), 0600)
				require.NoError(t, err)
				return tmpFile
			},
			wantErr:     true,
			errContains: "failed to decode PEM block",
		},
		{
			name: "wrong PEM type",
			setupFunc: func(t *testing.T) string {
				tmpFile := filepath.Join(t.TempDir(), "wrong_type.pem")
				wrongPEM := pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: []byte("some data"),
				})
				err := os.WriteFile(tmpFile, wrongPEM, 0600)
				require.NoError(t, err)
				return tmpFile
			},
			wantErr:     true,
			errContains: "failed to decode PEM block",
		},
		{
			name: "invalid private key data",
			setupFunc: func(t *testing.T) string {
				tmpFile := filepath.Join(t.TempDir(), "invalid_key.pem")
				invalidPEM := pem.EncodeToMemory(&pem.Block{
					Type:  "PRIVATE KEY",
					Bytes: []byte("invalid key data"),
				})
				err := os.WriteFile(tmpFile, invalidPEM, 0600)
				require.NoError(t, err)
				return tmpFile
			},
			wantErr:     true,
			errContains: "failed to parse private key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPath := tt.keyPath
			if tt.setupFunc != nil {
				keyPath = tt.setupFunc(t)
			}

			signer, err := NewSigner(keyPath)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, signer)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, signer)
				assert.NotNil(t, signer.privateKey)
			}
		})
	}
}

func TestSigner_Sign(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)
	keyPath := createTestPrivateKeyFile(t, privateKey)

	signer, err := NewSigner(keyPath)
	require.NoError(t, err)
	require.NotNil(t, signer)

	tests := []struct {
		name        string
		data        []byte
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid JSON object",
			data:    []byte(`{"key":"value","number":123}`),
			wantErr: false,
		},
		{
			name:    "valid JSON array",
			data:    []byte(`[1,2,3,4,5]`),
			wantErr: false,
		},
		{
			name:    "valid JSON with nested objects",
			data:    []byte(`{"user":{"name":"John","age":30},"active":true}`),
			wantErr: false,
		},
		{
			name:    "empty JSON object",
			data:    []byte(`{}`),
			wantErr: false,
		},
		{
			name:    "empty JSON array",
			data:    []byte(`[]`),
			wantErr: false,
		},
		{
			name:        "invalid JSON",
			data:        []byte(`{invalid json}`),
			wantErr:     true,
			errContains: "failed to canonicalize JSON",
		},
		{
			name:        "empty data",
			data:        []byte(``),
			wantErr:     true,
			errContains: "failed to canonicalize JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signature, err := signer.Sign(tt.data)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Empty(t, signature)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, signature)

				// Verify signature is valid base64
				decoded, err := base64.StdEncoding.DecodeString(signature)
				assert.NoError(t, err, "signature should be valid base64")
				assert.NotEmpty(t, decoded)

				// Verify signature can be verified with public key
				// We need to canonicalize the data first
				canonical, err := jsoncanonicalizer.Transform(tt.data)
				require.NoError(t, err)

				hashed := sha512.Sum512(canonical)
				err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA512, hashed[:], decoded)
				assert.NoError(t, err, "signature should be valid and verifiable")
			}
		})
	}
}

func TestSigner_Sign_Canonicalization(t *testing.T) {
	privateKey, _ := generateTestKeyPair(t)
	keyPath := createTestPrivateKeyFile(t, privateKey)

	signer, err := NewSigner(keyPath)
	require.NoError(t, err)

	// Different JSON representations of the same data
	data1 := []byte(`{"b":2,"a":1}`)
	data2 := []byte(`{"a":1,"b":2}`)
	data3 := []byte(`{"a": 1, "b": 2}`) // with spaces

	sig1, err := signer.Sign(data1)
	require.NoError(t, err)

	sig2, err := signer.Sign(data2)
	require.NoError(t, err)

	sig3, err := signer.Sign(data3)
	require.NoError(t, err)

	// All signatures should be identical due to canonicalization
	assert.Equal(t, sig1, sig2, "signatures should be identical for reordered keys")
	assert.Equal(t, sig1, sig3, "signatures should be identical regardless of whitespace")
}

func TestSigner_Sign_DifferentData(t *testing.T) {
	privateKey, _ := generateTestKeyPair(t)
	keyPath := createTestPrivateKeyFile(t, privateKey)

	signer, err := NewSigner(keyPath)
	require.NoError(t, err)

	data1 := []byte(`{"key":"value1"}`)
	data2 := []byte(`{"key":"value2"}`)

	sig1, err := signer.Sign(data1)
	require.NoError(t, err)

	sig2, err := signer.Sign(data2)
	require.NoError(t, err)

	// Different data should produce different signatures
	assert.NotEqual(t, sig1, sig2, "different data should produce different signatures")
}

func TestSigner_Sign_Concurrent(t *testing.T) {
	privateKey, _ := generateTestKeyPair(t)
	keyPath := createTestPrivateKeyFile(t, privateKey)

	signer, err := NewSigner(keyPath)
	require.NoError(t, err)

	const numGoroutines = 10
	const numIterations = 100

	data := []byte(`{"test":"data","concurrent":true}`)

	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			for j := 0; j < numIterations; j++ {
				sig, err := signer.Sign(data)
				assert.NoError(t, err)
				assert.NotEmpty(t, sig)
			}
			done <- true
		}()
	}

	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

func BenchmarkNewSigner(b *testing.B) {
	privateKey, _ := generateTestKeyPair(&testing.T{})
	tmpFile := filepath.Join(b.TempDir(), "bench_private.pem")

	privDER, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privDER,
	})
	os.WriteFile(tmpFile, privPEM, 0600)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewSigner(tmpFile)
	}
}

func BenchmarkSigner_Sign(b *testing.B) {
	privateKey, _ := generateTestKeyPair(&testing.T{})
	tmpFile := filepath.Join(b.TempDir(), "bench_private.pem")

	privDER, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privDER,
	})
	os.WriteFile(tmpFile, privPEM, 0600)

	signer, _ := NewSigner(tmpFile)
	data := []byte(`{"key":"value","number":123,"nested":{"field":"data"}}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = signer.Sign(data)
	}
}

func BenchmarkSigner_Sign_Parallel(b *testing.B) {
	privateKey, _ := generateTestKeyPair(&testing.T{})
	tmpFile := filepath.Join(b.TempDir(), "bench_private.pem")

	privDER, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privDER,
	})
	os.WriteFile(tmpFile, privPEM, 0600)

	signer, _ := NewSigner(tmpFile)
	data := []byte(`{"key":"value","number":123,"nested":{"field":"data"}}`)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = signer.Sign(data)
		}
	})
}
