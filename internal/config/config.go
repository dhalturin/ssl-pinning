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
	"fmt"
	"log/slog"
	"time"

	"ssl-pinning/internal/storage/types"

	"github.com/google/uuid"
	"github.com/spf13/viper"
)

// Config represents the main application configuration structure.
// It contains all settings including domain keys, logging, server, storage, and TLS configuration.
// UUID is generated automatically for each application instance.
type Config struct {
	Keys    []types.DomainKey `mapstructure:"keys"`
	Log     ConfigLog         `mapstructure:"log"`
	Server  ConfigServer      `mapstructure:"server"`
	Storage ConfigStorage     `mapstructure:"storage"`
	TLS     ConfigTLS         `mapstructure:"tls"`
	UUID    uuid.UUID
}

// ConfigLog defines logging configuration for the application.
// It controls log output format, verbosity level, and pretty-printing options.
type ConfigLog struct {
	Format string `mapstructure:"format"`
	Level  string `mapstructure:"level"`
	Pretty bool   `mapstructure:"pretty"`
}

// ConfigServer defines HTTP server configuration parameters.
// It specifies the listen address, read timeout, and write timeout for the server.
type ConfigServer struct {
	Listen       string        `mapstructure:"listen"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
}

// ConfigStorage defines storage backend configuration.
// It includes connection parameters (DSN), dump directory for file-based persistence,
// periodic dump interval, and storage type (filesystem, memory, redis, postgres).
type ConfigStorage struct {
	ConnMaxIdleTime time.Duration     `mapstructure:"conn_max_idle_time"`
	ConnMaxLifetime time.Duration     `mapstructure:"conn_max_lifetime"`
	DSN             string            `mapstructure:"dsn"`
	DumpDir         string            `mapstructure:"dump_dir"`
	MaxIdleConns    int               `mapstructure:"max_idle_conns"`
	MaxOpenConns    int               `mapstructure:"max_open_conns"`
	Type            types.StorageType `mapstructure:"type"`
}

// ConfigTLS defines TLS/cryptographic configuration.
// Dir specifies the directory containing TLS certificate files (prv.pem, pub.pem).
// Timeout sets the duration for TLS operations.
type ConfigTLS struct {
	Dir          string        `mapstructure:"dir"`
	DumpInterval time.Duration `mapstructure:"dump_interval"`
	Timeout      time.Duration `mapstructure:"timeout"`
}

// New loads and validates application configuration from viper.
// It unmarshals configuration from file, validates storage type against allowed values,
// sets default values for domain keys (File and DomainName fields if not specified),
// and generates a unique UUID for the application instance.
// Returns an error if unmarshaling fails or storage type is invalid.
func New() (Config, error) {
	config := Config{
		UUID: uuid.New(),
	}

	if err := viper.Unmarshal(&config); err != nil {
		return config, fmt.Errorf("failed to unmarshal storage config: %w", err)
	}

	for i, k := range config.Keys {
		if k.File == "" {
			k.File = fmt.Sprintf("%s.json", k.Fqdn)
		}

		if k.DomainName == "" {
			k.DomainName = fmt.Sprintf("*.%s", k.Fqdn)
		}

		config.Keys[i] = k
	}

	slog.Debug("configuration loaded", "config", config)

	return config, nil
}
