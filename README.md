# Go WOL Proxy

A Wake-on-LAN proxy service written in Go that automatically wakes up servers when TCP/UDP connections are made to them. Uses sendfile(2) for efficient zero-copy packet forwarding.

## Features

- Forwards TCP and UDP packets to configured target servers at the network level
- Uses sendfile(2) syscall for zero-copy data transfer (Linux)
- Automatically sends Wake-on-LAN packets to wake up offline servers
- Monitors server health with configurable intervals via TCP connection checks
- Caches health status to minimize latency for frequent requests
- Packaged as a Docker container for easy deployment
- :star: Supports graceful shutdown of servers after a period of inactivity

## How It Works

Unlike HTTP proxies that work at the application layer, this proxy operates at the TCP/UDP level:

1. Listens on configured ports for incoming TCP or UDP connections
2. Checks if the target server is healthy via TCP health checks
3. If the server is down, sends Wake-on-LAN packets and waits for it to wake up
4. Once healthy, forwards packets bidirectionally between client and target
5. On Linux, uses sendfile(2) via splice syscall for efficient zero-copy transfer; automatically falls back to standard io.Copy on other platforms
6. Supports both TCP (connection-oriented) and UDP (connectionless) forwarding

## Configuration

The service is configured using a TOML file. Here's an example configuration:

```toml
timeout = "1m"                 # How long to wait for server to wake up
poll_interval = "5s"           # How often to check health during wake-up
health_check_interval = "30s"  # Background health check frequency
health_cache_duration = "10s"  # How long to trust cached health status

[[targets]]
name = "service"
listen_port = 8080                           # Port to listen on for this target
destination_host = "service.local"            # Target host (IP or hostname)
destination_port = 80                         # Target port
protocol = "tcp"                              # Protocol: "tcp" or "udp"
health_check_host = "service.local"           # Health check host
health_check_port = 80                        # Health check port (TCP connection check)
mac_address = "7c:8b:ad:da:be:51"             # MAC address for WOL
broadcast_ip = "10.0.0.255"                   # Broadcast IP for WOL
wol_port = 9                                  # Port for WOL packets

# Optional: Graceful shutdown configuration (SSH or HTTP)
inactivity_threshold = "1h"                   # Shut down after 1 hour of inactivity

# Option A: SSH-based shutdown (use either Option A or Option B, not both)
ssh_host = "service.local:22"                 # SSH host:port for shutdown
ssh_user = "wol-proxy"                        # SSH username for shutdown
ssh_key_path = "/app/private_key"             # Path to SSH private key
shutdown_command = "sudo systemctl suspend"   # Command to execute for shutdown
# ^ take care - wake from suspend / shutdown can be flaky on some systems.
# if your machine doesnt wake from your chosen "sleep" mode, try another.

# Option B: HTTP-based shutdown (use either Option A or Option B, not both)
#shutdown_http_url = "http://service.local/api/shutdown" # URL to trigger shutdown (final response validated)
#shutdown_http_method = "POST"                              # Optional; defaults to POST
#shutdown_http_ok_status = 0                                 # Optional; 0=accept any 2xx (default). Set e.g. 202 to require specific code

[[targets]]
name = "service2"
listen_port = 8081                            # Different port for second target
destination_host = "service2.local"
destination_port = 80
protocol = "tcp"
health_check_host = "service2.local"
health_check_port = 80
mac_address = "c9:69:45:d2:1e:12"
broadcast_ip = "10.0.0.255"
wol_port = 9
```

## Docker Usage

### Pull the Docker Image

```bash
docker pull ghcr.io/darksworm/go-wol-proxy:latest
```

### Run the Docker Container

```bash
# Note: network mode "host" is required for Wake-on-LAN packets to be sent correctly
docker run --network host -v /path/to/config.toml:/app/config.toml ghcr.io/darksworm/go-wol-proxy:latest
```

### Build the Docker Image Locally

```bash
docker build -t go-wol-proxy .
```

### Run the Locally Built Image

```bash
# Note: network mode "host" is required for Wake-on-LAN packets to be sent correctly
docker run --network host -v /path/to/config.toml:/app/config.toml go-wol-proxy
```

### Docker Compose Usage

Create a `docker-compose.yml` file with the following content:

```yaml
version: '3'

services:
  go-wol-proxy:
    image: ghcr.io/darksworm/go-wol-proxy:latest
    # Note: network mode "host" is required for Wake-on-LAN packets to be sent correctly
    network_mode: host
    restart: unless-stopped
    volumes:
      - ./config.toml:/app/config.toml
      # Optional: SSH private key for graceful shutdown
      - ./private_key:/app/private_key
```

Run the container with Docker Compose:

```bash
docker-compose up -d
```

## Graceful Shutdown Options

- Trigger a shutdown after a period of inactivity using SSH or HTTP.
- Exactly one mechanism must be configured per target: SSH or HTTP, not both.

### SSH-based Shutdown
- Use `ssh_host`, `ssh_user`, `ssh_key_path`, and `shutdown_command`.
- The proxy executes the command over SSH when the target is inactive.

### HTTP-based Shutdown
- Use `shutdown_http_url` to enable HTTP shutdown.
- `shutdown_http_method` defaults to `POST` if not specified.
- By default, any 2xx status code counts as success; set `shutdown_http_ok_status` to require a specific code.
- The HTTP client follows redirects and validates the final response code.
- The shutdown HTTP request uses a 10s timeout.

### Validation Rules
- You cannot set both `shutdown_http_url` and `shutdown_command` for the same target.
- If `shutdown_http_method` and/or `shutdown_http_ok_status` are set, `shutdown_http_url` must also be set.

### Similar projects:
1. traefik-wol: [traefiklabs](https://plugins.traefik.io/plugins/642498d26d4f66a5a8a59d25/wake-on-lan), [github](https://github.com/MarkusJx/traefik-wol)
2. caddy-wol: [github](https://github.com/dulli/caddy-wol)

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines and commit conventions.
