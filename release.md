
# Release Notes

## Summary

This is the first major release of the hosts tool, a powerful command-line interface and web UI for managing your system's hosts file. This release includes a wide range of features to simplify the process of adding, removing, and managing hosts file entries, as well as integrating with the Caddy web server for local HTTPS proxying.

## Features

*   **Web UI:** A user-friendly web interface for managing hosts file entries, available at `http://localhost:3010`.
*   **CLI:** A comprehensive command-line interface for all operations, including adding, removing, enabling, disabling, and listing hosts file entries.
*   **Backup and Restore:** Easily create and restore backups of your hosts file to prevent data loss.
*   **Caddy Integration:** Automatically generate Caddyfiles for local HTTPS proxying, making it simple to set up secure local development environments.
*   **Cross-Platform:** Works on Linux, macOS, and Windows.
*   **Validation:** Validates IP addresses and hostnames to prevent errors in your hosts file.
*   **Privilege Checking:** Ensures that you have the necessary permissions to modify the hosts file before making any changes.

## Bug Fixes & Improvements

*   **Refactored Codebase:** The project has been refactored to improve code organization and maintainability.
*   **Enhanced UI:** The web UI has been improved for a better user experience.
*   **Added CLI Capabilities:** The command-line interface has been expanded with more commands and options.
*   **Improved Documentation:** The documentation has been updated to provide more detailed information on how to use the tool.

## Installation

To install the hosts tool, you can either download the latest release from the releases page or build it from source.

### From Release

1.  Download the latest release from the [releases page](https://github.com/levi-opunga/hosts/releases).
2.  Place the executable in a directory in your PATH.

### From Source

1.  Clone the repository:
    ```bash
    git clone https://github.com/levi-opunga/hosts.git
    cd hosts
    ```

2.  Build the executable:
    ```bash
    go build -o hosts
    ```

3.  Move the executable to a directory in your PATH (optional):
    ```bash
    sudo mv hosts /usr/local/bin/
    ```

## What's Next

We are constantly working to improve the hosts tool. Future releases will include features such as:

*   A more advanced Caddy integration

We hope you enjoy using the hosts tool!
