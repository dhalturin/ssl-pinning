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
package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"log/slog"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	logger "gopkg.in/slog-handler.v1"

	"ssl-pinning/internal/version"
)

var (
	configFile = ""
	configPath = ""
	pkg        = "ssl-pinning"
	rootCmd    = &cobra.Command{
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
		Short:             "ssl pinning",
		Use:               pkg,
	}
)

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	logger.SetGlobalLogger(logger.Options{Format: "json"})

	ex, err := os.Executable()
	if err != nil {
		log.Fatal("failed get path name of executable " + err.Error())
	}

	ExecutableDir := filepath.Dir(ex)

	pathConf, _ := filepath.Abs(ExecutableDir + "/../../../etc/" + pkg)

	rootCmd.PersistentFlags().StringVar(&configFile, "config-file", "config.yaml", "Set the configuration file name")
	rootCmd.PersistentFlags().StringVar(&configPath, "config-path", pathConf, "Set the configuration file path")
	rootCmd.PersistentFlags().String("log-format", "json", "Set the log format: text, json")
	rootCmd.PersistentFlags().String("log-level", "info", "Set the log level: debug, info, warn, error")
	rootCmd.PersistentFlags().Bool("log-pretty", false, "Logs will be indented")
	rootCmd.SetVersionTemplate("{{.Version}}\n")

	if v, err := json.Marshal(version.Get()); err != nil {
		slog.Error("can't parse log level", "err", err)
		os.Exit(1)
	} else {
		rootCmd.Version = string(v)
	}

	cobra.OnInitialize(initConfig)
}

func initConfig() {
	viper.AutomaticEnv()
	viper.SetConfigFile(fmt.Sprintf("%s/%s", configPath, configFile))
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.SetEnvPrefix(pkg)

	viper.SetDefault("server.listen", "127.0.0.1:7500")
	viper.SetDefault("server.read_timeout", 5*time.Second)
	viper.SetDefault("server.write_timeout", 5*time.Second)
	viper.SetDefault("storage.conn_max_idle_time", 5*time.Minute)
	viper.SetDefault("storage.conn_max_lifetime", 30*time.Minute)
	viper.SetDefault("storage.dsn", "")
	viper.SetDefault("storage.dump_dir", "/tmp")
	viper.SetDefault("storage.max_idle_conns", 5)
	viper.SetDefault("storage.max_open_conns", 5)
	viper.SetDefault("storage.type", "memory")
	viper.SetDefault("tls.dir", fmt.Sprintf("%s/tls", configPath))
	viper.SetDefault("tls.dump_interval", 5*time.Second)
	viper.SetDefault("tls.timeout", 5*time.Second)

	if err := viper.ReadInConfig(); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Error("failed to read the configuration file", "err", err)
		os.Exit(1)
	}

	viper.BindPFlag("log.format", rootCmd.PersistentFlags().Lookup("log-format"))
	viper.BindPFlag("log.level", rootCmd.PersistentFlags().Lookup("log-level"))
	viper.BindPFlag("log.pretty", rootCmd.PersistentFlags().Lookup("log-pretty"))

	logger.SetGlobalLogger(
		logger.Options{
			Attr: []slog.Attr{
				slog.String("version", version.GetVersion()),
			},
			AddSource: true,
			Format:    viper.GetString("log.format"),
			Level:     viper.GetString("log.level"),
			Pretty:    viper.GetBool("log.pretty"),
		},
	)

	color.NoColor = false

	slog.Debug(fmt.Sprintf("using config file: %s", viper.ConfigFileUsed()))
}
