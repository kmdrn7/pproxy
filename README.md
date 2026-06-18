# pproxy

A forward proxy that load-balances client traffic across a pool of upstream
proxies with active health checking and hot config reload.

`pproxy` is the single entry point your clients use; it picks an upstream from
the pool, forwards the request, and reuses the connection on a per-protocol
basis. Upstreams are validated continuously, so a failing proxy is dropped from
rotation within seconds and re-admitted when it recovers.

## Features

- **HTTP and HTTPS (CONNECT)** forwarding with absolute-URI request replay.
- **SOCKS5** forwarding (no-auth and username/password).
- **Per-protocol listeners** on configurable ports.
- **Round-robin selection** across upstreams of the same protocol.
- **Active health checks** per upstream; bad proxies are removed from
  rotation automatically.
- **Try-next on request-time failure** so a single flaky proxy does not fail
  the client request.
- **Hot config reload** via `SIGHUP` or `fsnotify` on the YAML file.
- **Graceful shutdown** on `SIGTERM`/`SIGINT` with a configurable drain
  timeout.
- **Per-client auth** with bcrypt-hashed passwords (`Proxy-Authorization`
  for HTTP, RFC 1929 subnegotiation for SOCKS5).
- **Prometheus** metrics on a separate port.
- **`slog` over `zap`** for structured JSON logging.

## Quick start

```bash
go build -o pproxy ./cmd/pproxy
cp config.example.yaml config.yaml
$EDITOR config.yaml    # set users, upstreams, listeners
./pproxy --config config.yaml
```

Generate a bcrypt password hash for the `auth.users` block:

```bash
htpasswd -bnBC 10 "" 'your-secret' | tr -d ':\n'
# paste the resulting $2y$10$... value into password_hash
```

## Configuration

`pproxy` reads a single YAML file (path via `--config` or `PPROXY_CONFIG`).
See [`config.example.yaml`](config.example.yaml) for a fully-commented
example. The top-level keys are:

| Key        | Purpose                                            |
| ---------- | -------------------------------------------------- |
| `logging`  | log level (`debug`/`info`/`warn`/`error`) and format (`json`/`text`) |
| `server`   | metrics bind address and shutdown drain timeout    |
| `health`   | probe interval, timeout, fail/success thresholds, optional `probe_url`/`probe_host` overrides |
| `auth`     | list of `{username, password_hash}` clients        |
| `listen`   | list of inbound listeners (`protocol` + `address` + `port`) |
| `pool`     | list of upstream proxies (`name` + `type` + `address` + ... ) |

Defaults applied when a key is omitted:

- `logging.level` = `info`, `logging.format` = `json`
- `server.metrics_address` = `0.0.0.0:9090`,
  `server.shutdown_timeout` = `30s`
- `health.interval` = `15s`, `health.timeout` = `5s`,
  `health.fail_threshold` = `2`, `health.success_threshold` = `2`
- `pool[*].dial_timeout` = `10s`

### Upstream fields

```yaml
- name: us-east-1         # unique within pool
  type: http              # http | socks5
  address: 1.2.3.4:3128
  username: ""            # optional, for upstream auth
  password: ""
  tls: false              # wrap the dial in TLS
  insecure_skip_verify: false
  ca_file: ""             # optional PEM bundle for private CAs
  dial_timeout: 10s
```

`http` upstreams accept both plain HTTP and `CONNECT` requests. SOCKS5
upstreams are negotiated with the configured credentials (or no-auth when
both fields are empty).

### Listener fields

```yaml
- protocol: http          # http | https | socks5
  address: 0.0.0.0        # default 0.0.0.0
  port: 8080
```

`http` and `https` use the same handler; HTTPS traffic is tunnelled via
`CONNECT`.

## Operations

### Signals

| Signal  | Effect                                                |
| ------- | ----------------------------------------------------- |
| `SIGHUP`  | reload config (atomic swap, listeners stay up)      |
| `SIGTERM` | graceful shutdown (drains in-flight within timeout) |
| `SIGINT`  | same as `SIGTERM`                                     |

### Health checks

`pproxy` probes every upstream on the configured interval. For `http`
upstreams it sends a `GET` through the proxy to `http://example.com/`
and expects a `2xx` response. For `socks5` it does a no-auth handshake
and a connect to `example.com:80`. A request-time failure also nudges
the upstream toward unhealthy so the next scheduled probe flips it
faster.

If your network cannot reach `example.com`, set `health.probe_url` and
`health.probe_host` to an internal endpoint. Avoid using a port that
mismatches the scheme (e.g. `http://...:443/`) — strict forward proxies
will reject the request with `400 Bad Request`.

When every upstream for a protocol is unhealthy, requests get a `503` (HTTP)
or a `Network unreachable` reply (SOCKS5).

### Metrics

`pproxy` exposes Prometheus metrics on `server.metrics_address` at
`/metrics`. Highlights:

- `pproxy_active_connections{protocol,listener}`
- `pproxy_upstream_healthy{upstream,type}`
- `pproxy_requests_total{protocol,upstream,outcome}`
- `pproxy_request_duration_seconds{protocol,upstream}`
- `pproxy_bytes_transferred_total{protocol,upstream,direction}`
- `pproxy_health_check_total{upstream,type,outcome}`
- `pproxy_health_check_duration_seconds{upstream,type}`
- `pproxy_upstream_failures_total{upstream,phase}`

### Logs

All logs are JSON by default and go to stdout. Fields are stable: `ts`,
`level`, `caller`, `msg`, plus any structured attributes. Use
`logging.format: text` for a human-readable form during local development.

## Architecture

```
cmd/pproxy/main.go              # wiring + signal handling
internal/logger                 # slog backed by zap/zapslog
internal/metrics                # Prometheus collectors
internal/config                 # YAML schema, validate, fsnotify+SIGHUP
internal/auth                   # bcrypt store, HTTP/SOCKS5 wire format
internal/pool                   # round-robin + atomic health state
internal/health                 # per-protocol prober, scheduler
internal/listener               # Server interface, Dependencies
internal/listener/dial.go       # shared upstream dialer
internal/listener/http.go       # HTTP + CONNECT forwarder
internal/listener/socks5.go     # SOCKS5 forwarder
```

The `Server` interface in `internal/listener` is the seam that lets the
`activeRuntime` in `main.go` swap listeners on config reload without
dropping in-flight traffic.

### Request lifecycle (HTTP)

1. Client connects, sends `GET http://example.com/ HTTP/1.1`.
2. `HTTPListener.handle` checks `Proxy-Authorization` against the auth
   store. Bad/missing → `407`.
3. Handler picks the next healthy HTTP upstream (round-robin, skipping
   unhealthy).
4. Dial upstream, replay the request bytes, read the response.
5. Stream the response back to the client; bump metrics.

If the picked upstream fails, the handler tries the next one in the same
request (up to 4 attempts) and marks the failed upstream as a
`RecordDown`, which nudges the health state.

### Request lifecycle (SOCKS5)

1. Client connects, sends method negotiation.
2. `SOCKS5Listener.handle` picks a method (`0x00` if no users configured,
   `0x02` otherwise).
3. Optional username/password subnegotiation via the auth store.
4. Client sends the connect request.
5. Handler dials the upstream, replays method negotiation, replays the
   connect request, then pumps bytes both ways.

## Development

```bash
go build ./...
go test ./...
go test -race -count=1 ./...
golangci-lint run ./...
```

Test layout:

- `internal/auth` — credential store, wire format, SOCKS5 subnegotiation.
- `internal/config` — schema, validation, defaults.
- `internal/pool` — round-robin, state machine, hot-replace.
- `internal/health` — probe helpers, parsePort, end-to-end probe against
  `httptest`.
- `internal/listener` — full HTTP and SOCKS5 forwarding through
  in-process upstream stand-ins.

## Security notes

- Passwords are stored as **bcrypt** hashes; never as plaintext.
- `insecure_skip_verify: true` is supported for operators who need it
  (e.g. private-CA providers that ship a self-signed leaf) but disables
  certificate validation. Prefer `ca_file` instead.
- The constant-time-equal call site in `auth.Verify` runs a fake bcrypt
  compare when the username is unknown, so a probing client cannot
  distinguish "no such user" from "wrong password" via timing.
- Graceful shutdown waits for in-flight requests but does not extend the
  timeout indefinitely; set `server.shutdown_timeout` to at least the
  longest expected upstream response time.
