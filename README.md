# SOCKS5 / HTTP CONNECT Proxy Server

A small Rust/Tokio proxy that accepts SOCKS5 and HTTP CONNECT clients on
the same listener, with configurable timeouts, graceful shutdown, and
privacy-preserving routine logs.

## Privacy Model

This is a raw TCP tunnel proxy. It can hide the client's source IP from the
destination when traffic is actually routed through the proxy, and it does not
inject HTTP headers such as `X-Forwarded-For`, `Forwarded`, or `Via`.

It does not hide or normalize the client's application fingerprint. The
destination can still observe things produced by the client itself, including
TLS fingerprints such as JA3/JA4, HTTP headers, cookies, logged-in accounts,
browser APIs, and SNI/target-host metadata where applicable. Changing those
requires controlling the client/browser stack or terminating TLS, not just
proxying TCP bytes.

Use `socks5h://` or the equivalent "remote DNS" setting in clients. Plain
`socks5://` clients may resolve DNS locally before connecting to the proxy.

Routine logs omit client IPs, attempted usernames, byte counts, and timing patterns. Target hosts and ports are included in logs via `tracing` spans to help debug background connections (e.g., from IDE extensions).

## How It Works

1. Reads configuration from environment variables or a local `.env` file.
2. Accepts TCP clients on the configured bind address.
3. Detects SOCKS5 vs HTTP CONNECT from the first byte.
4. Authenticates both SOCKS5 and HTTP CONNECT requests using the configured
   username and password.
5. Connects to the requested upstream address.
6. Relays bytes in both directions until either side closes or the idle timeout
   is reached.

## Configuration

Required:

- `PROXY_USER`: SOCKS5 username.
- `PROXY_PASS`: SOCKS5 password.

Optional:

- `PROXY_HOST`: Bind address. Default: `0.0.0.0`.
- `PROXY_PORT`: Bind port. Default: `1080`.
- `IDLE_TIMEOUT_SECS`: Idle timeout in seconds. Default: `300`.
- `UPSTREAM_CONNECTION_TIMEOUT_SEC`: Upstream connect timeout. Default: `30`.
- `RUST_LOG`: Tracing filter. Default: `info`.
- `LOG_FORMAT`: `pretty` or `json`. Default: `pretty`.

## Run With Cargo

```bash
cp .env.example .env
cargo run --release
```

If you already have `target/debug/socks5-proxy.exe` running on Windows, run
tests with a separate target directory so Cargo does not try to replace the
active executable:

```powershell
$env:CARGO_TARGET_DIR='target-test'
$env:CARGO_BUILD_JOBS='1'
cargo test
```

Otherwise:

```bash
cargo test
```

## Run With Docker

```bash
docker build -t proxy .

docker run -d \
  --name proxy \
  --restart unless-stopped \
  -p 1080:1080 \
  --env-file .env \
  proxy
```

## Using with CLI Tools

Because the proxy supports both SOCKS5 and HTTP CONNECT, you can easily route command-line tools (like `codex`, `curl`, `git`, or scripts) through it locally.

For HTTP CONNECT:
```bash
export HTTP_PROXY="http://myuser:mypassword@127.0.0.1:1080"
export HTTPS_PROXY="http://myuser:mypassword@127.0.0.1:1080"
```

For SOCKS5 (with auth):
```bash
export ALL_PROXY="socks5://myuser:mypassword@127.0.0.1:1080"
```

## Test

SOCKS5:

```bash
curl -x socks5h://myuser:mypassword@127.0.0.1:1080 https://ifconfig.me
```

HTTP CONNECT:

```bash
curl -x http://myuser:mypassword@127.0.0.1:1080 https://ifconfig.me
```
