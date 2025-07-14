![pacli-logo](https://github.com/user-attachments/assets/742d776d-107a-495e-8bcf-5f68f25a087f)

___

# 🔐 pacli - Secrets Management CLI

[![Build Status](https://github.com/imshakil/pacli/actions/workflows/release.yml/badge.svg)](https://github.com/imshakil/pacli/actions)
[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/imShakil/pacli/main.svg)](https://results.pre-commit.ci/latest/github/imShakil/pacli/main)
[![PyPI version](https://img.shields.io/pypi/v/pacli-tool.svg)](https://pypi.org/project/pacli-tool/)
[![PyPI Downloads](https://static.pepy.tech/badge/pacli-tool)](https://pepy.tech/projects/pacli-tool)
[![Python Versions](https://img.shields.io/pypi/pyversions/pacli-tool.svg)](https://pypi.org/project/pacli-tool/)
[![License](https://img.shields.io/github/license/imshakil/pacli)](LICENSE)
[![security:bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/imShakil/pacli)

pacli is a simple, privacy-focused CLI tool for managing your secrets locally. Unlike online password managers, pacli keeps your sensitive information on your device, reducing the risk of leaks from server breaches or hacks.

## Features

- Securely store and manage secrets locally
- Master password protection
- Support separate options for token, password, and SSH connections
- Add, retrieve, update, and delete secrets
- Copy secrets directly to your clipboard
- SSH connection management with key file support
- Export list of secrets into JSON or CSV file
- Easy-to-use command-line interface

## Installation

```sh
pip install pacli-tool
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
| `change-master-key`    | Change the master password without losing data   |
| `export`               | Export secrets to JSON or CSV format             |
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
pacli add --ssh ec2-vm user:192.168.1.100 --key-path ~/.ssh/id_rsa

# Retrieve a secret
pacli get github

# Connect via SSH
pacli ssh ec2-vm

# Export secrets to JSON
pacli export --format json --output my_secrets.json

# Export secrets to CSV
pacli export --format csv --output my_secrets.csv
```

## Display Format

- Credentials are shown as: `username:password`
- SSH connections are shown as: `user:ip` or `user:ip (Key: /path/to/key)`

## Copy to Clipboard

To copy a secret directly to your clipboard, use the `--clip` option:

```sh
pacli get google --clip
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

## Demo

![demo](https://github.com/user-attachments/assets/be7ea309-9f5c-4f5a-a4f3-fdf065577d8b)
