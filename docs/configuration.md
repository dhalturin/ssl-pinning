# Configuration

`ssl-pinning` application uses [Viper](https://github.com/spf13/viper) for configuration management and [Cobra](https://github.com/spf13/cobra) for CLI. Configuration is loaded from multiple sources with the following priority (from lowest to highest priority):

- Default values
- Configuration file
- Environment variables
- Command-line flags

All configuration is unmarshalled into a structured Go configuration located in the `config` package.

## Configuration Structure

The configuration is organized into the following sections:

| Section | Description |
|---------|-------------|
| `keys` | Domain key configurations |
| `log` | Logging settings |
| `server` | HTTP server parameters |
| `storage` | Storage backend configuration |
| `tls` | TLS/cryptographic settings |

## Configuration Parameters

### Log Configuration (`log.`)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `log.format` | `string` | `json` | Log output format (e.g., `json`, `text`) |
| `log.level` | `string` | `info` | Log verbosity level (e.g., `debug`, `info`, `warn`, `error`) |
| `log.pretty` | `boolean` | `false` | Enable pretty-printed log output |

### Server Configuration (`server.`)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `server.listen` | `string` | `127.0.0.1:7500` | HTTP server listen address and port |
| `server.read_timeout` | `duration` | `5s` | Maximum duration for reading the entire request |
| `server.write_timeout` | `duration` | `5s` | Maximum duration before timing out writes of the response |

### Storage Configuration (`storage.`)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `storage.type` | `string` | `memory` | Storage type: `memory`, `redis`, `postgres`, or `filesystem` |
| `storage.dsn` | `string` | *none* | Data source name for external storage<br><br>Redis<br>`redis://user:password@localhost:6379/0?maintnotifications=disabled`<br>PostgreSQL<br>`postgres://user:password@localhost:5432/ssl_pinning?sslmode=disable` |
| `storage.dump_dir` | `string` | `/tmp` | Directory for file-based persistence dumps |
| `storage.conn_max_idle_time` | `duration` | `5m` | Maximum idle time for database connections |
| `storage.conn_max_lifetime` | `duration` | `30m` | Maximum lifetime for database connections |
| `storage.max_idle_conns` | `integer` | 5 | Maximum number of idle database connections |
| `storage.max_open_conns` | `integer` | 5 | Maximum number of open database connections |

### TLS Configuration (`tls.`)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `tls.dir` | `string` | `{config-path}/tls` | Directory containing TLS certificates (`prv.pem`, `pub.pem`) |
| `tls.dump_interval` | `duration` | `5s` | Interval for periodic dumps to storage |
| `tls.timeout` | `duration` | `5s` | Timeout duration for TLS operations |

## Configuration Methods

### 1. Configuration File

Create a configuration file (e.g., `config.yaml`) in the `{config-path}`

Example `config.yaml`:
```yaml
keys:
  - fqdn: example.com

  - fqdn: foo.example.com
    domainName: foo.example.com
    file: example.com.json

  - fqdn: bar.example.com
    file: example.com.json

  - fqdn: zoo.example.com
    file: zoo.example.com.json

log:
  format: json
  level: info
  pretty: false

server:
  listen: 0.0.0.0:7500
  read_timeout: 5s
  write_timeout: 5s

storage:
  type: fs
  dump_dir: /var/lib/ssl-pinning/dumps

  type: memory

  type: redis
  dsn: redis://user:password@localhost:6379/0?maintnotifications=disabled

  type: postgres
  dsn: postgres://user:password@localhost:5432/ssl_pinning?sslmode=disable
  conn_max_idle_time: 5m
  conn_max_lifetime: 30m
  max_idle_conns: 5
  max_open_conns: 5

tls:
  dir: /etc/app/tls
  dump_interval: 30s
  timeout: 10s
```

### 2. Environment Variables

Environment variables use the `UPPER_SNAKE_CASE` format with `_` replacing `.` and with `SSL_PINNING_` prefix:

```bash
export SSL_PINNING_LOG_LEVEL=debug
export SSL_PINNING_SERVER_LISTEN=0.0.0.0:7500
export SSL_PINNING_SERVER_READ_TIMEOUT=5s
export SSL_PINNING_SERVER_WRITE_TIMEOUT=5s
export SSL_PINNING_STORAGE_CONN_MAX_IDLE_TIME=5m
export SSL_PINNING_STORAGE_CONN_MAX_LIFETIME=30m
export SSL_PINNING_STORAGE_DSN="postgres://user:pass@localhost:5432/db?sslmode=disable"
export SSL_PINNING_STORAGE_DUMP_DIR=/opt/ssl-pinning/storage-dump
export SSL_PINNING_STORAGE_MAX_IDLE_CONNS=5
export SSL_PINNING_STORAGE_MAX_OPEN_CONNS=5
export SSL_PINNING_STORAGE_TYPE=postgres
export SSL_PINNING_TLS_DIR=/opt/ssl-pinning/tls
export SSL_PINNING_TLS_DUMP_INTERVAL=1s
export SSL_PINNING_TLS_TIMEOUT=3s
```

### 3. Command-Line Flags

| Flag | Configuration Key | Description |
|------|------------------|-------------|
| `--config-file` | *none* | Configuration file name |
| `--config-path` | *none* | Configuration file path |
| `--log-format` | `log.format` | Log output format |
| `--log-level` | `log.level` | Log verbosity level |
| `--log-pretty` | `log.pretty` | Pretty-print logs |
| `--storage-conn-max-idle-time` | `storage.conn_max_idle_time` | Max idle time for DB connections |
| `--storage-conn-max-lifetime` | `storage.conn_max_lifetime` | Max lifetime for DB connections |
| `--storage-dsn` | `storage.dsn` | Storage DSN connection string |
| `--storage-dump-dir` | `storage.dump_dir` | Directory for persistence dumps |
| `--storage-dump-interval` | `storage.dump_interval` | Dump interval duration |
| `--storage-max-idle-conns` | `storage.max_idle_conns` | Max idle DB connections |
| `--storage-max-open-conns` | `storage.max_open_conns` | Max open DB connections |
| `--storage-type` | `storage.type` | Storage backend type |

Example:
```bash
ssl-pinning up --log-level=debug --storage-type=postgres --storage-dump-interval=30s
```
