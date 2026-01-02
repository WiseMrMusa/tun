# Tun - Secure Port Tunneling Service

A production-grade, self-hosted tunneling solution in Rust that securely exposes local ports to the internet.

## Features

- **Secure Communication**: TLS-encrypted WebSocket connection between client and server
- **Token Authentication**: Token-based authentication with configurable expiration
- **Custom Subdomains**: Request specific subdomains for your tunnels
- **Multi-Port Support**: Route different paths to different local ports
- **WebSocket Pass-through**: Proxy WebSocket connections through tunnels
- **Raw TCP Tunneling**: Support for raw TCP data forwarding
- **PostgreSQL Persistence**: Optional database storage for horizontal scaling
- **Rate Limiting**: Protect against abuse with configurable rate limits
- **Prometheus Metrics**: Full observability with metrics endpoint
- **TLS on Proxy**: Optional TLS termination on the public proxy port
- **Single-Port Mode**: Run control and proxy on a single port
- **Auto-Reconnect**: Client automatically reconnects on connection loss
- **Streaming Support**: Efficient handling of large request/response bodies
- **Graceful Shutdown**: Clean shutdown with database cleanup

## Architecture

```
┌─────────────────────┐         ┌─────────────────────┐
│   Local Machine     │         │    Public VPS       │
│                     │         │                     │
│  ┌───────────────┐  │         │  ┌───────────────┐  │
│  │ Local Service │  │         │  │  tun-server   │  │
│  │   :3000       │  │         │  │               │  │
│  └───────┬───────┘  │         │  │  Control:8080 │◄─────── Tunnel Clients
│          │          │         │  │  HTTP:8000    │◄─────── Internet Traffic
│  ┌───────▼───────┐  │         │  │  Metrics:9090 │◄─────── Prometheus
│  │  tun-client   │──────WSS────►│  PostgreSQL ───│──────── Database
│  └───────────────┘  │         │  └───────────────┘  │
└─────────────────────┘         └─────────────────────┘
```

## Quick Start

### 1. Build the Project

```bash
cargo build --release
```

### 2. Start the Server (on your VPS)

```bash
# Start the server - it will generate an auth secret
./target/release/tun-server --domain tunnel.yourdomain.com

# Or with a specific secret
./target/release/tun-server --domain tunnel.yourdomain.com --auth-secret your-hex-encoded-secret
```

The server will output the authentication secret on first run. Save this for generating client tokens.

### 3. Generate a Client Token

```bash
# Use the tun-token utility
./target/release/tun-token --secret your-hex-encoded-secret
```

### 4. Start the Client (on your local machine)

```bash
./target/release/tun-client \
  --server tunnel.yourdomain.com:8080 \
  --local-port 3000 \
  --token your-auth-token
```

Your local service on port 3000 is now accessible at `https://abc123.tunnel.yourdomain.com`!

## Configuration

### Server Options

| Option | Environment Variable | Default | Description |
|--------|---------------------|---------|-------------|
| `--domain` | `TUN_DOMAIN` | `localhost` | Domain for tunnel subdomains |
| `--control-port` | `TUN_CONTROL_PORT` | `8080` | Port for client connections |
| `--http-port` | `TUN_HTTP_PORT` | `8000` | Port for public HTTP traffic |
| `--cert-path` | `TUN_CERT_PATH` | - | Path to TLS certificate |
| `--key-path` | `TUN_KEY_PATH` | - | Path to TLS private key |
| `--auth-secret` | `TUN_AUTH_SECRET` | (generated) | Hex-encoded auth secret |
| `--max-tunnels` | `TUN_MAX_TUNNELS` | `100` | Max concurrent tunnels |
| `--request-timeout` | `TUN_REQUEST_TIMEOUT` | `30` | Request timeout (seconds) |
| `--token-ttl` | `TUN_TOKEN_TTL` | `604800` | Token TTL in seconds (default: 7 days) |
| `--body-size-limit` | `TUN_BODY_SIZE_LIMIT` | `104857600` | Max body size (default: 100MB) |
| `--auth-timeout` | `TUN_AUTH_TIMEOUT` | `10` | Auth timeout (seconds) |
| `--rate-limit-rps` | `TUN_RATE_LIMIT_RPS` | `100` | Rate limit (req/sec/IP) |
| `--rate-limit-burst` | `TUN_RATE_LIMIT_BURST` | `200` | Rate limit burst size |
| `--database-url` | `TUN_DATABASE_URL` | - | PostgreSQL connection URL |
| `--server-id` | `TUN_SERVER_ID` | (auto) | Server ID for horizontal scaling |
| `--proxy-tls` | `TUN_PROXY_TLS` | `false` | Enable TLS on proxy port |
| `--metrics-port` | `TUN_METRICS_PORT` | - | Port for Prometheus metrics |
| `--single-port` | `TUN_SINGLE_PORT` | `false` | Run on single port |
| `--debug` | `TUN_DEBUG` | `false` | Enable debug logging |

### Client Options

| Option | Environment Variable | Default | Description |
|--------|---------------------|---------|-------------|
| `--server` | `TUN_SERVER` | `localhost:8080` | Server address |
| `--local-port` | `TUN_LOCAL_PORT` | - | Local port to expose (legacy) |
| `--ports` | - | - | Port mappings (e.g., `3000`, `3001:/api`) |
| `--local-host` | `TUN_LOCAL_HOST` | `127.0.0.1` | Local host to forward to |
| `--token` | `TUN_TOKEN` | (required) | Authentication token |
| `--subdomain` | `TUN_SUBDOMAIN` | - | Request custom subdomain |
| `--tls` | `TUN_TLS` | `false` | Use TLS for server connection |
| `--insecure` | `TUN_INSECURE` | `false` | Skip TLS verification |
| `--reconnect-delay` | `TUN_RECONNECT_DELAY` | `5` | Reconnect delay (seconds) |
| `--max-reconnects` | `TUN_MAX_RECONNECTS` | `0` | Max reconnect attempts (0=infinite) |
| `--debug` | `TUN_DEBUG` | `false` | Enable debug logging |

## Advanced Features

### Multi-Port Routing

Route different paths to different local services:

```bash
./target/release/tun-client \
  --server tunnel.yourdomain.com:8080 \
  --token your-token \
  --ports 3000 \
  --ports 3001:/api \
  --ports 3002:/ws
```

This routes:
- `/api/*` → localhost:3001
- `/ws/*` → localhost:3002
- Everything else → localhost:3000

### Custom Subdomains

Request a specific subdomain:

```bash
./target/release/tun-client \
  --server tunnel.yourdomain.com:8080 \
  --token your-token \
  --local-port 3000 \
  --subdomain my-app
```

Your tunnel will be available at `my-app.tunnel.yourdomain.com`.

### PostgreSQL Persistence

Enable horizontal scaling and persistence:

```bash
# Start with PostgreSQL
./target/release/tun-server \
  --domain tunnel.yourdomain.com \
  --database-url "postgres://user:pass@localhost/tun"
```

Run migrations:
```bash
psql -d tun -f tun-server/migrations/001_initial.sql
```

### Prometheus Metrics

Enable metrics endpoint:

```bash
./target/release/tun-server \
  --domain tunnel.yourdomain.com \
  --metrics-port 9090
```

Available metrics:
- `tun_tunnels_connected_total` - Total tunnels connected
- `tun_active_tunnels` - Currently active tunnels
- `tun_requests_total` - Total requests processed
- `tun_request_duration_ms` - Request latency histogram
- `tun_bytes_in_total` / `tun_bytes_out_total` - Traffic counters
- `tun_auth_success_total` / `tun_auth_failure_total` - Auth attempts

### Single-Port Mode

Run control plane and proxy on the same port:

```bash
./target/release/tun-server \
  --domain tunnel.yourdomain.com \
  --single-port \
  --http-port 443
```

In this mode:
- `/ws` → Control plane (WebSocket)
- Everything else → Proxy traffic

## DNS Setup

For production use, configure your DNS:

1. Add an A record for your tunnel domain pointing to your VPS IP:
   ```
   tunnel.yourdomain.com -> YOUR_VPS_IP
   ```

2. Add a wildcard A record for subdomains:
   ```
   *.tunnel.yourdomain.com -> YOUR_VPS_IP
   ```

## TLS Setup

For HTTPS support, obtain certificates (e.g., from Let's Encrypt):

```bash
# Using certbot
sudo certbot certonly --standalone -d tunnel.yourdomain.com -d *.tunnel.yourdomain.com

# Start server with TLS
./target/release/tun-server \
  --domain tunnel.yourdomain.com \
  --cert-path /etc/letsencrypt/live/tunnel.yourdomain.com/fullchain.pem \
  --key-path /etc/letsencrypt/live/tunnel.yourdomain.com/privkey.pem
```

To also enable TLS on the proxy port:

```bash
./target/release/tun-server \
  --domain tunnel.yourdomain.com \
  --cert-path /path/to/fullchain.pem \
  --key-path /path/to/privkey.pem \
  --proxy-tls
```

## Local Development

### Testing without DNS

For local testing, add entries to `/etc/hosts`:

```
127.0.0.1 tunnel.localhost
127.0.0.1 abc123.tunnel.localhost
```

Or use the subdomain.localhost pattern which works automatically in most browsers.

### Running Tests

```bash
cargo test
```

### Running Both Server and Client Locally

Terminal 1 (Server):
```bash
cargo run --bin tun-server -- --domain localhost --debug
```

Terminal 2 (Client):
```bash
cargo run --bin tun-client -- --server localhost:8080 --local-port 3000 --token YOUR_TOKEN --debug
```

Terminal 3 (Local service):
```bash
# Start any HTTP service on port 3000
python3 -m http.server 3000
```

Then access `http://SUBDOMAIN.localhost:8000` to reach your local service.

## Security Considerations

- All tunnel traffic is encrypted with TLS 1.3 (when TLS is enabled)
- Token-based authentication with configurable expiration
- Tokens are signed with HMAC-SHA256
- Request size limits prevent memory exhaustion (100MB default)
- Rate limiting protects against abuse
- Connection timeouts prevent resource leaks
- Reserved subdomains prevent system subdomain hijacking

## Horizontal Scaling

With PostgreSQL enabled, you can run multiple tun-server instances behind a load balancer:

```
                    ┌─────────────────┐
                    │  Load Balancer  │
                    │   (HAProxy)     │
                    └────────┬────────┘
                             │
            ┌────────────────┼────────────────┐
            │                │                │
     ┌──────▼──────┐  ┌──────▼──────┐  ┌──────▼──────┐
     │ tun-server  │  │ tun-server  │  │ tun-server  │
     │   (srv-1)   │  │   (srv-2)   │  │   (srv-3)   │
     └──────┬──────┘  └──────┬──────┘  └──────┬──────┘
            │                │                │
            └────────────────┼────────────────┘
                             │
                    ┌────────▼────────┐
                    │   PostgreSQL    │
                    └─────────────────┘
```

Each server uses its `--server-id` to track its own tunnels in the database.

## License

MIT
