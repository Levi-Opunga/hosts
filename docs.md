# hosts Documentation

## Overview

`hosts` is a powerful command-line tool and web UI for managing your system's hosts file. It simplifies adding, removing, enabling, disabling, and backing up hosts file entries. Additionally, it integrates with the Caddy web server to provide local HTTPS proxying.

## Features

*   **Web UI:** A user-friendly web interface for managing hosts file entries.
*   **CLI:** A comprehensive command-line interface for all operations.
*   **Backup and Restore:** Create and restore backups of your hosts file.
*   **Caddy Integration:** Automatically create Caddyfiles for local HTTPS proxying.
*   **Cross-Platform:** Works on Linux, macOS, and Windows.
*   **Validation:** Validates IP addresses and hostnames to prevent errors.
*   **Privilege Checking:** Ensures you have the necessary permissions to modify the hosts file.

## Installation

To use `hosts`, you need to have Go installed on your system.

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/hosts.git
    cd hosts
    ```

2.  **Build the executable:**
    ```bash
    go build -o hosts
    ```

3.  **Move the executable to a directory in your PATH (optional):**
    ```bash
    sudo mv hosts /usr/local/bin/
    ```

## Web UI Usage

To start the web UI, run the following command:

```bash
sudo ./hosts
```

Or on Windows (as Administrator):

```bash
./hosts.exe
```

The web UI will be available at `http://localhost:3000`.

## CLI Usage

The `hosts` provides a variety of flags for command-line operations.

### `init`

Initializes the hosts file.

**Usage:**

```bash
hosts --init
```

### `add`

Adds a new entry to the hosts file.

**Usage:**

```bash
hosts --add <hostname> [--ip <ip_address>] [--comment "<comment>"]
```

**Options:**

*   `--ip`: The IP address to map the hostname to. Defaults to `127.0.0.1`.
*   `--comment`: A comment to add to the entry.

**Example:**

```bash
hosts --add example.local --ip 192.168.1.10 --comment "Development server"
```

### `remove`

Removes an entry from the hosts file.

**Usage:**

```bash
hosts --remove <hostname>
```

**Example:**

```bash
hosts --remove example.local
```

### `list`

Lists all entries in the hosts file.

**Usage:**

```bash
hosts --list
```

### `enable`

Enables a disabled entry in the hosts file.

**Usage:**

```bash
hosts --enable <hostname>
```

**Example:**

```bash
hosts --enable example.local
```

### `disable`

Disables an entry in the hosts file by commenting it out.

**Usage:**

```bash
hosts --disable <hostname>
```

**Example:**

```bash
hosts --disable example.local
```

### `backup`

Creates a backup of the current hosts file.

**Usage:**

```bash
hosts --backup
```

### `restore`

Restores the hosts file from a backup.

**Usage:**

```bash
hosts --restore <backup_file>
```

**Example:**

```bash
hosts --restore hosts.bak.20250816-120000
```

### `caddy`

Create a Caddyfile for use in local Caddy server.

**Usage:**

```bash
hosts --caddy --proxy <hostname>
```

**Example:**

```bash
hosts --caddy --proxy api.local
```

### `proxy`

Local domain to proxy to.

**Usage:**

```bash
hosts --proxy <domain>
```

**Example:**

```bash
hosts --proxy api.local
```

### `check`

Check if you have the necessary privileges to run the program.

**Usage:**

```bash
hosts --check
```

### `version`

Show version information.

**Usage:**

```bash
hosts --version
```

### `help`

Displays the help message.

**Usage:**

```bash
hosts --help
```

## Backup and Restore

`hosts` makes it easy to create and restore backups of your hosts file.

*   **Creating a backup:**
    ```bash
    hosts --backup
    ```
    This will create a new backup file in the `hosts_backups` directory (located in the same directory as your hosts file).

*   **Restoring from a backup:**
    ```bash
    hosts --restore <backup_file>
    ```
    Replace `<backup_file>` with the name of the backup file you want to restore.

## Caddy Integration

`hosts` can generate a `Caddyfile` to easily set up a local HTTPS proxy.

**Usage:**

```bash
hosts --caddy <hostname>
```

This will create a `Caddyfile` in the current directory that proxies requests for `<hostname>` to `127.0.0.1:3000`.

## Development

To build `hosts` from source, you need to have Go installed.

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/levi-opunga/hosts.git
    cd hosts
    ```

2.  **Build the executable:**
    ```bash
    go build -o hosts
    ```
