# SOCKS5 Proxy Server

A small Rust/Tokio SOCKS5 proxy with username/password authentication,
configurable timeouts, graceful shutdown, and privacy-preserving routine logs.

## Privacy Model

This is a raw TCP SOCKS5 proxy. It can hide the client's source IP from the
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

Routine logs intentionally omit client IPs, target hosts, target ports,
attempted usernames, byte counts, and timing patterns.

## How It Works

1. Reads configuration from environment variables or a local `.env` file.
2. Accepts TCP clients on the configured bind address.
3. Performs a SOCKS5 username/password handshake.
4. Connects to the requested upstream address.
5. Relays bytes in both directions until either side closes or the idle timeout
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

## Run With Docker

```bash
docker build -t socks5-proxy .

docker run -d \
  --name socks5-proxy \
  -p 1080:1080 \
  -e PROXY_USER=myuser \
  -e PROXY_PASS=mypassword \
  socks5-proxy
```

## Test

```bash
curl -x socks5h://myuser:mypassword@127.0.0.1:1080 https://ifconfig.me
```
