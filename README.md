# Tun - Secure Port Tunneling Service

A production-grade, self-hosted tunneling solution in Rust that securely exposes local ports to the internet.

## Features

- **Secure Communication**: TLS-encrypted WebSocket connection between client and server
- **Authentication**: Token-based authentication to prevent unauthorized tunnels
- **Subdomain Routing**: Each tunnel gets a unique subdomain
- **HTTP Support**: Full HTTP/1.1 request/response proxying
- **Connection Multiplexing**: Multiple concurrent requests over single tunnel
- **Auto-Reconnect**: Client automatically reconnects on connection loss
- **Graceful Shutdown**: Clean shutdown handling with Ctrl+C

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
│  ┌───────▼───────┐  │         │  └───────────────┘  │
│  │  tun-client   │──────WSS────►                    │
│  └───────────────┘  │         │                     │
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
# Use the auth secret from the server to generate tokens
# You can use the tun-core library or implement token generation
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
| `--debug` | `TUN_DEBUG` | `false` | Enable debug logging |

### Client Options

| Option | Environment Variable | Default | Description |
|--------|---------------------|---------|-------------|
| `--server` | `TUN_SERVER` | `localhost:8080` | Server address |
| `--local-port` | `TUN_LOCAL_PORT` | (required) | Local port to expose |
| `--local-host` | `TUN_LOCAL_HOST` | `127.0.0.1` | Local host to forward to |
| `--token` | `TUN_TOKEN` | (required) | Authentication token |
| `--tls` | `TUN_TLS` | `false` | Use TLS for server connection |
| `--insecure` | `TUN_INSECURE` | `false` | Skip TLS verification |
| `--reconnect-delay` | `TUN_RECONNECT_DELAY` | `5` | Reconnect delay (seconds) |
| `--max-reconnects` | `TUN_MAX_RECONNECTS` | `0` | Max reconnect attempts (0=infinite) |
| `--debug` | `TUN_DEBUG` | `false` | Enable debug logging |

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
- Token-based authentication prevents unauthorized tunnel creation
- Tokens are signed with HMAC-SHA256
- Request size limits prevent memory exhaustion (10MB default)
- Connection timeouts prevent resource leaks

## License

MIT

