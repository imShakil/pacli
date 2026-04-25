# 🔐 pacli - Secrets Management CLI

___

![pacli-logo](https://github.com/user-attachments/assets/742d776d-107a-495e-8bcf-5f68f25a087f)
[![Build Status](https://github.com/imshakil/pacli/actions/workflows/release.yml/badge.svg)](https://github.com/imshakil/pacli/actions)
[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/imShakil/pacli/main.svg)](https://results.pre-commit.ci/latest/github/imShakil/pacli/main)
[![PyPI version](https://img.shields.io/pypi/v/pacli-tool.svg)](https://pypi.org/project/pacli-tool/)
[![PyPI Downloads](https://img.shields.io/pepy/dt/pacli-tool?style=flat)](https://pepy.tech/projects/pacli-tool)
[![Python Versions](https://img.shields.io/pypi/pyversions/pacli-tool.svg)](https://pypi.org/project/pacli-tool/)
[![License](https://img.shields.io/github/license/imshakil/pacli)](LICENSE)
[![security:bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/imShakil/pacli)

pacli is a secure, local-first secrets manager that stores your passwords, API keys, and SSH credentials with encryption and master password protection - no cloud dependencies required.

## Features

- Securely store and manage secrets locally
- Master password protection
- Support separate options for token, password, and SSH connections
- Add, retrieve, update, and delete secrets
- Copy secrets directly to your clipboard
- SSH connection management with key file support
- URL shortening with [LinklyHQ](https://linklyhq.com/?via=ShakilOps) integration
- Export list of secrets into JSON or CSV file
- Easy-to-use command-line interface
- **Web UI** for managing secrets through a modern web interface

## Sonarqube Code Quality Metrics

[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=imShakil_pacli&metric=ncloc)](https://sonarcloud.io/summary/new_code?id=imShakil_pacli)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=imShakil_pacli&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=imShakil_pacli)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=imShakil_pacli&metric=coverage)](https://sonarcloud.io/summary/new_code?id=imShakil_pacli)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=imShakil_pacli&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=imShakil_pacli)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=imShakil_pacli&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=imShakil_pacli)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=imShakil_pacli&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=imShakil_pacli)
[![Duplicated Lines (%)](https://sonarcloud.io/api/project_badges/measure?project=imShakil_pacli&metric=duplicated_lines_density)](https://sonarcloud.io/summary/new_code?id=imShakil_pacli)

## Installation

### Recommended: pipx (isolated, no conflicts)

[pipx](https://pipx.pypa.io/) installs CLI tools in their own isolated environments and makes them available system-wide. This is the safest and cleanest approach.

```sh
# Install pipx if you don't have it
pip install pipx
pipx ensurepath

# Install pacli
pipx install pacli-tool
```

### Standard pip

```sh
pip install pacli-tool
```

> **Note for Ubuntu 23+, Debian 12+, and other modern Linux distros:** Your system Python may be externally managed (PEP 668) and block pip installs by default. Use one of the alternatives below.

### Modern Linux (externally managed Python)

If you get an `externally-managed-environment` error, choose one of these:

```sh
# Use a virtual environment (safest for system Python)
python3 -m venv ~/.venv/pacli
~/.venv/pacli/bin/pip install pacli-tool

# Then add the binary to your PATH
echo 'export PATH="$HOME/.venv/pacli/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### Install from source

```sh
git clone https://github.com/imshakil/pacli.git
cd pacli
pip install -e .
```

Or directly from GitHub without cloning:

```sh
pip install git+https://github.com/imshakil/pacli.git
```

### Verify installation

```sh
pacli --help
```

## Usage

To see all available commands and options:

```sh
pacli --help
```

### Common Commands

| Command                | Description                                      |
|------------------------|--------------------------------------------------|
| `init`                 | Initialize pacli and set a master password       |
| `add`                  | Add a secret with a label                        |
| `get`                  | Retrieve secrets by label                        |
| `get-by-id`            | Retrieve a secret by its ID                      |
| `update`               | Update old secret by label                       |
| `update-by-id`         | Update old secret by its ID                      |
| `list`                 | List all saved secrets                           |
| `delete`               | Delete a secret by label                         |
| `delete-by-id`         | Delete a secret by its ID                        |
| `ssh`                  | Connect to SSH server using saved credentials    |
| `short`                | Shorten URLs using LinklyHQ service              |
| `cc`                   | Copy stdin content to clipboard                  |
| `change-master-key`    | Change the master password without losing data   |
| `export`               | Export secrets to JSON or CSV format             |
| `web`                  | Launch/manage the Web UI for managing secrets    |
| `version`              | Show the current version of pacli                |

### Examples

#### Adding and Retrieving Secrets

```sh
# Initialize pacli (run once)
pacli init

# Add a password
pacli add --pass github

# Add a token
pacli add --token api-key

# Add SSH connection
pacli add --ssh ec2-vm user:192.168.1.100

# Add SSH connection with key file
pacli add --ssh ec2-vm user:192.168.1.100 --key ~/.ssh/id_rsa

# Retrieve a secret
pacli get github

# Connect via SSH
pacli ssh ec2-vm

# Export secrets to JSON
pacli export --format json --output my_secrets.json

# Export secrets to CSV
pacli export --format csv --output my_secrets.csv

# Shorten a URL
pacli short https://example.com/very/long/url

# Shorten with custom name and copy to clipboard
pacli short https://example.com -n "My Link" --clip

# Copy file content to clipboard
cat file.txt | pacli cc

# Copy command output to clipboard
echo "Hello World" | pacli cc

# Copy API response to clipboard
curl -s https://api.example.com/data | pacli cc
```

## Web UI

[![Web UI](https://mhosen.com/projects/pacli/pacli-web-ui.png)](https://mhosen.com/projects/pacli---secrets-management-cli)

### Redesigned UI (1.4.0+)

<img width="1512" height="771" alt="Screenshot 2026-04-25 at 21 26 34" src="https://github.com/user-attachments/assets/af509b71-582e-4456-9032-d1fa67ba0eee" />


Launch the Web UI to manage your secrets through a modern, user-friendly interface:

```sh
# Start the Web UI (opens in your default browser)
pacli web

# Start in background mode
pacli web start

# Stop background mode
pacli web stop

# Check background status
pacli web status

# Start on a custom host and port
pacli web --host 0.0.0.0 --port 8080

# Start in background on custom host and port
pacli web start --host 0.0.0.0 --port 8080

# Start without opening browser
pacli web --no-browser

# Start in background without opening browser
pacli web start --no-browser
```

The Web UI provides:

- 🔐 Master password authentication
- 📋 View, add, edit, and delete secrets
- 🔍 Search and filter secrets by type
- 📋 Display secrets with creation/update timestamps
- 👁️ Toggle secret visibility
- 📋 Copy secrets to clipboard
- 🎨 Responsive design for desktop and mobile

## Display Format

- Credentials are shown as: `username:password`
- SSH connections are shown as: `user:ip` or `user:ip (Key: /path/to/key)`

## Copy to Clipboard

To copy a secret directly to your clipboard, use the `--clip` option:

```sh
pacli get google --clip
```

### Pipeline Usage

Use `pacli cc` to copy any command output or file content to clipboard:

```sh
# Copy file contents
cat ~/.ssh/id_rsa.pub | pacli cc

# Copy command output
ls -la | pacli cc

# Copy JSON response
curl -s https://api.github.com/user | pacli cc
```

For more information, use `pacli --help` or see the documentation.

## Tips

### Avoid Master Password Prompts

To avoid entering your master password repeatedly, you can set it as an environment variable:

```sh
# For current session only
export PACLI_MASTER_PASSWORD="your-master-password"

# Or add to your shell profile for permanent use
echo 'export PACLI_MASTER_PASSWORD="your-master-password"' >> ~/.bashrc  # For bash
echo 'export PACLI_MASTER_PASSWORD="your-master-password"' >> ~/.zshrc   # For zsh
```

**Security Note:** Adding the password to your shell profile makes it persistent but less secure. Use the session-only approach for better security.

### URL Shortening Setup

To use the URL shortening feature, set up your [LinklyHQ](https://linklyhq.com/?via=ShakilOps) credentials as environment variables:

```sh
# Set LinklyHQ credentials
export PACLI_LINKLYHQ_KEY="your_api_key"
export PACLI_LINKLYHQ_WID="your_workspace_id"

# Add to your shell profile for permanent use
echo 'export PACLI_LINKLYHQ_KEY="your_api_key"' >> ~/.bashrc
echo 'export PACLI_LINKLYHQ_WID="your_workspace_id"' >> ~/.bashrc
```

> [Visits here](https://linklyhq.com/?via=ShakilOps) to get your credentials.

## Demo

![demo](https://github.com/user-attachments/assets/be7ea309-9f5c-4f5a-a4f3-fdf065577d8b)
