# hosts-cli Documentation

## Overview

`hosts-cli` is a powerful command-line tool and web UI for managing your system's hosts file. It simplifies adding, removing, enabling, disabling, and backing up hosts file entries. Additionally, it integrates with the Caddy web server to provide local HTTPS proxying.

## Features

*   **Web UI:** A user-friendly web interface for managing hosts file entries.
*   **CLI:** A comprehensive command-line interface for all operations.
*   **Backup and Restore:** Create and restore backups of your hosts file.
*   **Caddy Integration:** Automatically create Caddyfiles for local HTTPS proxying.
*   **Cross-Platform:** Works on Linux, macOS, and Windows.
*   **Validation:** Validates IP addresses and hostnames to prevent errors.
*   **Privilege Checking:** Ensures you have the necessary permissions to modify the hosts file.

## Installation

To use `hosts-cli`, you need to have Go installed on your system.

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/hosts-cli.git
    cd hosts-cli
    ```

2.  **Build the executable:**
    ```bash
    go build -o hosts-cli
    ```

3.  **Move the executable to a directory in your PATH (optional):**
    ```bash
    sudo mv hosts-cli /usr/local/bin/
    ```

## Web UI Usage

To start the web UI, run the following command:

```bash
sudo ./hosts-cli
```

Or on Windows (as Administrator):

```bash
./hosts-cli.exe
```

The web UI will be available at `http://localhost:3000`.

## CLI Usage

The `hosts-cli` provides a variety of flags for command-line operations.

### `init`

Initializes the hosts file.

**Usage:**

```bash
hosts-cli --init
```

### `add`

Adds a new entry to the hosts file.

**Usage:**

```bash
hosts-cli --add <hostname> [--ip <ip_address>] [--comment "<comment>"]
```

**Options:**

*   `--ip`: The IP address to map the hostname to. Defaults to `127.0.0.1`.
*   `--comment`: A comment to add to the entry.

**Example:**

```bash
hosts-cli --add example.local --ip 192.168.1.10 --comment "Development server"
```

### `remove`

Removes an entry from the hosts file.

**Usage:**

```bash
hosts-cli --remove <hostname>
```

**Example:**

```bash
hosts-cli --remove example.local
```

### `list`

Lists all entries in the hosts file.

**Usage:**

```bash
hosts-cli --list
```

### `enable`

Enables a disabled entry in the hosts file.

**Usage:**

```bash
hosts-cli --enable <hostname>
```

**Example:**

```bash
hosts-cli --enable example.local
```

### `disable`

Disables an entry in the hosts file by commenting it out.

**Usage:**

```bash
hosts-cli --disable <hostname>
```

**Example:**

```bash
hosts-cli --disable example.local
```

### `backup`

Creates a backup of the current hosts file.

**Usage:**

```bash
hosts-cli --backup
```

### `restore`

Restores the hosts file from a backup.

**Usage:**

```bash
hosts-cli --restore <backup_file>
```

**Example:**

```bash
hosts-cli --restore hosts.bak.20250816-120000
```

### `caddy`

Create a Caddyfile for use in local Caddy server.

**Usage:**

```bash
hosts-cli --caddy --proxy <hostname>
```

**Example:**

```bash
hosts-cli --caddy --proxy api.local
```

### `proxy`

Local domain to proxy to.

**Usage:**

```bash
hosts-cli --proxy <domain>
```

**Example:**

```bash
hosts-cli --proxy api.local
```

### `check`

Check if you have the necessary privileges to run the program.

**Usage:**

```bash
hosts-cli --check
```

### `version`

Show version information.

**Usage:**

```bash
hosts-cli --version
```

### `help`

Displays the help message.

**Usage:**

```bash
hosts-cli --help
```

## Backup and Restore

`hosts-cli` makes it easy to create and restore backups of your hosts file.

*   **Creating a backup:**
    ```bash
    hosts-cli --backup
    ```
    This will create a new backup file in the `hosts_backups` directory (located in the same directory as your hosts file).

*   **Restoring from a backup:**
    ```bash
    hosts-cli --restore <backup_file>
    ```
    Replace `<backup_file>` with the name of the backup file you want to restore.

## Caddy Integration

`hosts-cli` can generate a `Caddyfile` to easily set up a local HTTPS proxy.

**Usage:**

```bash
hosts-cli --caddy <hostname>
```

This will create a `Caddyfile` in the current directory that proxies requests for `<hostname>` to `127.0.0.1:3000`.

## Development

To build `hosts-cli` from source, you need to have Go installed.

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/levi-opunga/hosts-cli.git
    cd hosts-cli
    ```

2.  **Build the executable:**
    ```bash
    go build -o hosts-cli
    ```
