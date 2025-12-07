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
	"log/slog"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"ssl-pinning/internal/application"
)

// upCmd represents the up command
var upCmd = &cobra.Command{
	Use:   "up",
	Short: "Up certificates watcher",
	Run: func(cmd *cobra.Command, args []string) {
		app, err := application.New()
		if err != nil {
			slog.Error("failed to initialize application", "error", err)
			os.Exit(1)
		}

		app.Up()
	},
}

func init() {
	rootCmd.AddCommand(upCmd)

	upCmd.Flags().Duration("storage-conn-max-idle-time", 5*time.Minute, "Max idle time of storage connections")
	upCmd.Flags().Duration("storage-conn-max-lifetime", 30*time.Minute, "Max lifetime of storage connections")
	upCmd.Flags().Duration("tls-dump-interval", 5*time.Second, "Dump interval keys to storage")
	upCmd.Flags().Int("storage-max-idle-conns", 5, "Max idle connections to storage")
	upCmd.Flags().Int("storage-max-open-conns", 5, "Max open connections to storage")
	upCmd.Flags().String("storage-dsn", "", "Storage DSN connection string")
	upCmd.Flags().String("storage-dump-dir", "/tmp/"+pkg, "Directory for memory storage dumps")
	upCmd.Flags().StringP("storage-type", "s", "memory", "Storage type: fs, memory, redis, postgres")

	viper.BindPFlag("storage.conn_max_idle_time", upCmd.Flags().Lookup("storage-conn-max-idle-time"))
	viper.BindPFlag("storage.conn_max_lifetime", upCmd.Flags().Lookup("storage-conn-max-lifetime"))
	viper.BindPFlag("storage.dsn", upCmd.Flags().Lookup("storage-dsn"))
	viper.BindPFlag("storage.dump_dir", upCmd.Flags().Lookup("storage-dump-dir"))
	viper.BindPFlag("storage.max_idle_conns", upCmd.Flags().Lookup("storage-max-idle-conns"))
	viper.BindPFlag("storage.max_open_conns", upCmd.Flags().Lookup("storage-max-open-conns"))
	viper.BindPFlag("storage.type", upCmd.Flags().Lookup("storage-type"))
	viper.BindPFlag("tls.dump_interval", upCmd.Flags().Lookup("storage-dump-interval"))
}
