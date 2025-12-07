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
package config

import (
	"testing"
	"time"

	"ssl-pinning/internal/storage/types"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name         string
		setupViper   func()
		wantErr      bool
		validateFunc func(t *testing.T, cfg Config)
	}{
		{
			name: "valid config with all fields",
			setupViper: func() {
				viper.Reset()
				viper.Set("keys", []map[string]interface{}{
					{
						"fqdn": "example.com",
					},
				})
				viper.Set("log.format", "json")
				viper.Set("log.level", "info")
				viper.Set("log.pretty", false)
				viper.Set("server.listen", "127.0.0.1:8080")
				viper.Set("server.read_timeout", "5s")
				viper.Set("server.write_timeout", "10s")
				viper.Set("storage.conn_max_idle_time", "30s")
				viper.Set("storage.conn_max_lifetime", "1h")
				viper.Set("storage.dsn", "redis://localhost:6379/0?maintnotifications=disabled")
				viper.Set("storage.dump_dir", "/tmp")
				viper.Set("storage.max_idle_conns", 10)
				viper.Set("storage.max_open_conns", 100)
				viper.Set("storage.type", "memory")
				viper.Set("tls.dir", "/etc/ssl")
				viper.Set("tls.dump_interval", "15s")
				viper.Set("tls.timeout", "5s")
			},
			wantErr: false,
			validateFunc: func(t *testing.T, cfg Config) {
				assert.Equal(t, "/etc/ssl", cfg.TLS.Dir)
				assert.Equal(t, "/tmp", cfg.Storage.DumpDir)
				assert.Equal(t, "127.0.0.1:8080", cfg.Server.Listen)
				assert.Equal(t, "example.com", cfg.Keys[0].Fqdn)
				assert.Equal(t, "info", cfg.Log.Level)
				assert.Equal(t, "json", cfg.Log.Format)
				assert.Equal(t, "redis://localhost:6379/0?maintnotifications=disabled", cfg.Storage.DSN)
				assert.Equal(t, 1*time.Hour, cfg.Storage.ConnMaxLifetime)
				assert.Equal(t, 10*time.Second, cfg.Server.WriteTimeout)
				assert.Equal(t, 10, cfg.Storage.MaxIdleConns)
				assert.Equal(t, 100, cfg.Storage.MaxOpenConns)
				assert.Equal(t, 30*time.Second, cfg.Storage.ConnMaxIdleTime)
				assert.Equal(t, 15*time.Second, cfg.TLS.DumpInterval)
				assert.Equal(t, 5*time.Second, cfg.Server.ReadTimeout)
				assert.Equal(t, 5*time.Second, cfg.TLS.Timeout)
				assert.Equal(t, types.StorageMemory, cfg.Storage.Type)
				assert.False(t, cfg.Log.Pretty)
				assert.NotEqual(t, "", cfg.UUID.String())
				require.Len(t, cfg.Keys, 1)
			},
		},
		{
			name: "auto-generate File field from Fqdn",
			setupViper: func() {
				viper.Reset()
				viper.Set("keys", []map[string]interface{}{
					{
						"fqdn": "test.com",
					},
				})
			},
			wantErr: false,
			validateFunc: func(t *testing.T, cfg Config) {
				require.Len(t, cfg.Keys, 1)
				assert.Equal(t, "test.com", cfg.Keys[0].Fqdn)
				assert.Equal(t, "test.com.json", cfg.Keys[0].File)
			},
		},
		{
			name: "auto-generate DomainName field from Fqdn",
			setupViper: func() {
				viper.Reset()
				viper.Set("keys", []map[string]interface{}{
					{
						"fqdn": "example.org",
					},
				})
			},
			wantErr: false,
			validateFunc: func(t *testing.T, cfg Config) {
				require.Len(t, cfg.Keys, 1)
				assert.Equal(t, "example.org", cfg.Keys[0].Fqdn)
				assert.Equal(t, "*.example.org", cfg.Keys[0].DomainName)
			},
		},
		{
			name: "preserve existing File and DomainName",
			setupViper: func() {
				viper.Reset()
				viper.Set("keys", []map[string]interface{}{
					{
						"fqdn":       "custom.com",
						"file":       "custom-file.json",
						"domainName": "custom.domain.com",
					},
				})
			},
			wantErr: false,
			validateFunc: func(t *testing.T, cfg Config) {
				require.Len(t, cfg.Keys, 1)
				assert.Equal(t, "custom.com", cfg.Keys[0].Fqdn)
				assert.Equal(t, "custom-file.json", cfg.Keys[0].File)
				assert.Equal(t, "custom.domain.com", cfg.Keys[0].DomainName)
			},
		},
		{
			name: "multiple keys",
			setupViper: func() {
				viper.Reset()
				viper.Set("keys", []map[string]interface{}{
					{"fqdn": "first.com"},
					{"fqdn": "second.com", "file": "second.json"},
					{"fqdn": "third.com", "domainName": "*.custom.third.com"},
				})
			},
			wantErr: false,
			validateFunc: func(t *testing.T, cfg Config) {
				require.Len(t, cfg.Keys, 3)

				// First key
				assert.Equal(t, "first.com", cfg.Keys[0].Fqdn)
				assert.Equal(t, "first.com.json", cfg.Keys[0].File)
				assert.Equal(t, "*.first.com", cfg.Keys[0].DomainName)

				// Second key
				assert.Equal(t, "second.com", cfg.Keys[1].Fqdn)
				assert.Equal(t, "second.json", cfg.Keys[1].File)
				assert.Equal(t, "*.second.com", cfg.Keys[1].DomainName)

				// Third key
				assert.Equal(t, "third.com", cfg.Keys[2].Fqdn)
				assert.Equal(t, "third.com.json", cfg.Keys[2].File)
				assert.Equal(t, "*.custom.third.com", cfg.Keys[2].DomainName)
			},
		},
		{
			name: "empty config",
			setupViper: func() {
				viper.Reset()
			},
			wantErr: false,
			validateFunc: func(t *testing.T, cfg Config) {
				assert.NotEqual(t, "", cfg.UUID.String())
				assert.Len(t, cfg.Keys, 0)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			tt.setupViper()

			// Execute
			cfg, err := New()

			// Assert
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.validateFunc != nil {
					tt.validateFunc(t, cfg)
				}
			}
		})
	}
}

func TestConfig_UUIDGeneration(t *testing.T) {
	viper.Reset()

	cfg1, err1 := New()
	require.NoError(t, err1)

	cfg2, err2 := New()
	require.NoError(t, err2)

	// UUIDs should be different for each instance
	assert.NotEqual(t, cfg1.UUID, cfg2.UUID)
	assert.NotEmpty(t, cfg1.UUID.String())
	assert.NotEmpty(t, cfg2.UUID.String())
}
