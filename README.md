# 🔐 pacli - Personal Secrets Management CLI

**pacli** is a simple, privacy-focused CLI tool for managing your secrets locally. Unlike online password managers, pacli keeps your sensitive information on your device, reducing the risk of leaks from server breaches or hacks.

## Features

- Securely store and manage secrets locally
- Master password protection
- support separate option for token and password
- Add, retrieve, update, and delete secrets
- Copy secrets directly to your clipboard
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
| `init`                 | Initialize pacli and set a master password        |
| `add`                  | Add a secret with a label                        |
| `get`                  | Retrieve secrets by label                        |
| `get-by-id`            | Retrieve a secret by its ID                      |
| `list`                 | List all saved secrets                           |
| `delete`               | Delete a secret by label                         |
| `delete-by-id`         | Delete a secret by its ID                        |
| `change-master-key`    | Change the master password without losing data   |
| `version`              | Show the current version of pacli                |

### Example: Adding and Retrieving a Secret

```sh
# Initialize pacli (run once)
pacli init

# Add a new secret
pacli add --pass github

# Retrieve a secret
pacli get github
```

## Display Format

- Credentials are shown as: `username:password`

## Copy to Clipboard

To copy a secret directly to your clipboard, use the `--clip` option:

```sh
pacli get google --clip
```

---

For more information, use `pacli --help` or see the documentation.
