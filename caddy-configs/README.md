# Caddy Configuration Directory

## Structure
- domains/     - Individual domain configuration files
- includes/    - Shared configuration snippets  
- logs/        - Caddy log files
- caddy.json   - Main generated configuration (auto-generated)

## Usage
Use caddy-manager commands to manage configurations.
The main caddy.json file is automatically generated from domain configs.

## Starting Caddy
caddy run --config caddy.json
