# Hosts CLI

A modern CLI tool to manage `/etc/hosts` file with backup and validation.

## Features

- Web UI
- CLI operations
- Search, filtering, validation, backup management

## Usage

### Web UI

Start without flags to launch web UI at http://localhost:3000
Requires elevated permissions (sudo/Administrator) for saving changes.

```
sudo ./hosts-ui                    (Linux/macOS)
./hosts-ui.exe                     (Windows as Administrator)
Open: http://localhost:3000
```

### CLI

```
sudo ./hosts-ui --add example.local                    # Add example.local -> 127.0.0.1
sudo ./hosts-ui --add example.local --ip 192.168.1.10  # Add with custom IP
sudo ./hosts-ui --remove example.local                 # Remove entry
sudo ./hosts-ui --list                                 # List all entries
sudo ./hosts-ui --disable example.local               # Disable entry
sudo ./hosts-ui --enable example.local                # Enable entry
sudo ./hosts-ui --backup                              # Create backup
sudo ./hosts-ui --restore backup-file.bak             # Restore backup
```

## CLI Usage

```
Hosts Editor Pro v2.0 - Advanced /etc/hosts management

USAGE:
    hosts-cli [flags]                           # Start web interface
    hosts-cli --add <hostname> [flags]          # Add hostname entry
    hosts-cli --remove <hostname>               # Remove hostname entry
    hosts-cli --list                            # List all entries
    hosts-cli --disable <hostname>              # Disable hostname entry
    hosts-cli --enable <hostname>               # Enable hostname entry
    hosts-cli --backup                          # Create backup
    hosts-cli --restore <backup-file>           # Restore from backup
    hosts-cli --caddy <hostname> [flags]        # Create Caddyfile for Caddy server
	hosts-cli --proxy <domain>  [flags]         # Local domain to proxy to (e.g. example.local)

FLAGS:
    --add <hostname>     Add hostname (defaults to 127.0.0.1)
    --ip <ip>           IP address for --add (default: 127.0.0.1)
    --comment <text>    Comment for --add
    --remove <hostname> Remove hostname
    --list              List all entries
    --disable <hostname> Disable hostname
    --enable <hostname>  Enable hostname
    --backup            Create backup
    --restore <file>    Restore from backup
    --port <port>       Web server port (default: 3000)
    --help              Show this help
    --caddy <hostname>  Create Caddyfile for Caddy server
	--proxy <domain>    Local domain to proxy to (e.g. example.local)
    --port <port>       Local port to bind to proxy server (default: 3000)

Caddyfile Usage:
    hosts-cli --caddy api.local                  # Create Caddyfile for reverse proxying to api.local (default port 3000)
    hosts-cli --caddy api.local --proxy  --port 5000  # Create Caddyfile for reverse proxying to api.local (port 5000) and run the caddy server
    hosts-cli --proxy api.local --port 3000       # 

EXAMPLES:
    hosts-cli                                   # Start web interface
    hosts-cli --add api.local                   # Add api.local -> 127.0.0.1
    hosts-cli --add db.local --ip 192.168.1.10  # Add db.local -> 192.168.1.10
    hosts-cli --add test.local --comment "Dev environment"
    hosts-cli --remove api.local                # Remove api.local
    hosts-cli --disable api.local               # Disable api.local
    hosts-cli --enable api.local                # Enable api.local
    hosts-cli --list                            # Show all entries
    hosts-cli --backup                          # Create backup
    hosts-cli --restore hosts.bak.20240101-120000  # Restore backup

WEB INTERFACE:
    Start without flags to launch web UI at http://localhost:3000
    Requires elevated permissions (sudo/Administrator) for saving changes.
```

## Caddy Usage

```
sudo ./hosts-cli --caddy api.local                  # Create Caddyfile for reverse proxying to api.local (default port 3000)
sudo ./hosts-cli --caddy api.local --proxy  --port 5000  # Create Caddyfile for reverse proxying to api.local (port 5000) and run the caddy server
sudo ./hosts-cli --proxy api.local --port 3000       # 
```
## Permissions
To run the CLI as a non-root user, you need to grant the `net_bind_service` capability to the binary. You can do this by running the following command:
```shell
 sudo setcap cap_net_bind_service=+ep $(which hosts-cli)
```
To check if you have the necessary permissions, run the following command:
```shell
sudo ./hosts-cli --check-privileges
```

## License

MIT License

Copyright (c) 2023 Levi Opunga

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.   