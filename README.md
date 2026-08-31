# 🔐 pacli - Secrets Management CLI & Team Vaults

___

![pacli-logo](https://github.com/user-attachments/assets/742d776d-107a-495e-8bcf-5f68f25a087f)
[![Build Status](https://github.com/imshakil/pacli/actions/workflows/release.yml/badge.svg)](https://github.com/imshakil/pacli/actions)
[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/imShakil/pacli/main.svg)](https://results.pre-commit.ci/latest/github/imShakil/pacli/main)
[![PyPI version](https://img.shields.io/pypi/v/pacli-tool.svg)](https://pypi.org/project/pacli-tool/)
[![PyPI Downloads](https://img.shields.io/pepy/dt/pacli-tool?style=flat)](https://pepy.tech/projects/pacli-tool)
[![Python Versions](https://img.shields.io/pypi/pyversions/pacli-tool.svg)](https://pypi.org/project/pacli-tool/)
[![License](https://img.shields.io/github/license/imshakil/pacli)](LICENSE)
[![security:bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/imShakil/pacli)
![Badge](https://hitscounter.dev/api/hit?url=https%3A%2F%2Fgithub.com%2FimShakil%2Fpacli&label=&icon=github&color=%23198754&message=&style=flat&tz=UTC)

**pacli** is a secure, local-first secrets manager and team vault system designed for developers and DevOps teams. Store, retrieve, sync, and share passwords, API tokens, and SSH credentials with strong cryptography, master password verification, role-based permissions, and zero-knowledge synchronization.

---

## 🌟 Key Features

- 🔒 **Local-First & Zero-Knowledge**: Secrets are encrypted at rest with PBKDF2-HMAC-SHA256 and Fernet (AES-128-CBC + HMAC). Plaintext never touches the network unencrypted.
- 👥 **Team Vaults & RBAC**: Create isolated team vaults (`dev-infra`, `prod-keys`) with granular roles (`viewer`, `editor`, `admin`) and encrypted key-wrapping per member.
- 🔄 **Multi-Target Vault Sync**: Push and pull encrypted vault bundles across team members using a shared directory (Dropbox, Google Drive, NAS, Git) or via the built-in self-hosted server.
- 🖥️ **Self-Hosted Zero-Knowledge Relay Server**: Run your own team sync server (`pacli server start`) with token authentication and audit logging. The server never has access to encryption keys or secrets.
- 📦 **Encrypted Backups**: Export and import full encrypted vault backups with master password protection.
- 💻 **Modern Web UI**: Interactive browser dashboard (`pacli web`) featuring a Vault Switcher, Secrets CRUD, Team Member Management, Audit Log Viewer, and an in-browser SSH Terminal.
- 🔑 **SSH Key Management**: Store and auto-connect to SSH servers using credentials or key files.
- 📋 **Clipboard & Pipeline Integration**: Copy secrets directly to clipboard (`--clip`) or pipe command outputs (`pacli cc`).
- 🔗 **LinklyHQ URL Shortening**: Built-in shortlink generator with click tracking.

---

## 📊 Code Quality & Security

[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=imShakil_pacli&metric=ncloc)](https://sonarcloud.io/summary/new_code?id=imShakil_pacli)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=imShakil_pacli&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=imShakil_pacli)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=imShakil_pacli&metric=coverage)](https://sonarcloud.io/summary/new_code?id=imShakil_pacli)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=imShakil_pacli&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=imShakil_pacli)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=imShakil_pacli&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=imShakil_pacli)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=imShakil_pacli&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=imShakil_pacli)

---

## 🚀 Installation

### Recommended: pipx (isolated environment)
```sh
pip install pipx
pipx ensurepath
pipx install pacli-tool
```

### Standard pip
```sh
pip install pacli-tool
```

### Install from source
```sh
git clone https://github.com/imshakil/pacli.git
cd pacli
pip install -e .
```

Verify installation:
```sh
pacli version
pacli --help
```

---

## 📖 Command Reference

| Command / Group | Description |
|---|---|
| `init` | Set or reset your master password |
| `add` | Add a secret (`--pass`, `--token`, `--ssh`) with optional `--vault` |
| `get` / `get-by-id` | Retrieve secrets by label or ID (`--clip` to copy) |
| `list` | List all saved secrets (supports `--vault`) |
| `update` / `update-by-id` | Update an existing secret value |
| `delete` / `delete-by-id` | Delete a secret |
| `team` | 👥 Team vault management (create vaults, add members, audit log) |
| `sync` | 🔄 Sync encrypted vaults with a team relay server or shared directory |
| `server` | 🖥️ Start, stop, and manage the self-hosted zero-knowledge sync server |
| `backup` | 📦 Encrypted backup export and import across machines |
| `web` | 🌐 Launch or manage the local Web UI dashboard |
| `ssh` | Connect to an SSH server using saved credentials |
| `export` | Export secrets to unencrypted JSON or CSV |
| `short` | Shorten URLs via LinklyHQ |
| `cc` | Copy stdin / pipeline output to clipboard |
| `change-master-key` | Re-encrypt all secrets with a new master password |
| `version` | Show pacli version and project details |

---

## 👥 Team Vaults & Collaboration

### 1. Initialize Your Team Identity
Each team member initializes their identity once:
```sh
pacli team init
# Enter display name: Alice
# ✅ Identity set! User ID: d164fe8724cb
```

To see your identity anytime:
```sh
pacli team whoami
```

### 2. Create a Team Vault
```sh
pacli team create-vault dev-infra -d "Backend infrastructure & database credentials"
```

### 3. Add Teammates to the Vault
Add members using their unique User ID:
```sh
# Add Bob as an editor
pacli team add-member dev-infra a8f910e1234 --name "Bob" --role editor

# Add Charlie as a read-only viewer
pacli team add-member dev-infra b7c821f9876 --name "Charlie" --role viewer
```

Available roles:
- `viewer`: Read secrets in the vault
- `editor`: Read, add, update, and delete secrets
- `admin`: Full control (manage members, roles, audit log, delete vault)

### 4. Working with Secrets in Team Vaults
Simply pass `--vault <name>` or `-v <name>` to any secret command:
```sh
# Add a secret to the team vault
pacli add --vault dev-infra --password postgres_db postgres db_pass_secret
pacli add --vault dev-infra --token stripe_key sk_test_12345

# List secrets in the team vault
pacli list --vault dev-infra

# Retrieve a secret from the vault
pacli get --vault dev-infra postgres_db --clip

# View immutable audit log of actions taken in the vault
pacli team audit-log dev-infra
```

---

## 🔄 Syncing Vaults Across the Team

### Option A: Self-Hosted Zero-Knowledge Relay Server

#### 1. Start the Sync Server (DevOps / Admin)
Run on any Linux server, VPS, or cloud container:
```sh
# Start the server daemon on port 58380
pacli server start --host 0.0.0.0 --port 58380 --daemon

# Generate a team token
pacli server token create --name "DevTeam" --role admin
```

#### 2. Configure Team Members
Each team member configures their client once:
```sh
pacli sync config set --server http://secrets.mycompany.internal:58380 --token pacli_tok_...
```

#### 3. Push and Pull Updates
```sh
# Push local vault updates to the server
pacli sync push dev-infra

# Check status of remote vault
pacli sync status dev-infra

# Pull and merge latest changes from the server
pacli sync pull dev-infra
```

---

### Option B: Offline / Shared Directory Sync (No Server)

You can also sync encrypted `.pacli` bundles through **Dropbox, Google Drive, NAS, or Git**:
```sh
# Push encrypted bundle to shared directory
pacli sync push dev-infra --to ~/Dropbox/TeamSecrets/

# Pull and merge from shared directory
pacli sync pull dev-infra --from ~/Dropbox/TeamSecrets/
```

---

## 📦 Encrypted Backups

Export and import encrypted backup archives of personal or team vaults:
```sh
# Backup personal store
pacli backup export --output ~/pacli_backup.enc

# Backup a specific team vault
pacli backup export --vault dev-infra --output ~/dev_infra_backup.enc

# Restore backup
pacli backup import ~/dev_infra_backup.enc --vault dev-infra
```

---

## 🌐 Web UI

Launch the modern browser-based UI:
```sh
# Start and open in default browser
pacli web

# Start in background mode (daemon)
pacli web start

# Check status / Stop
pacli web status
pacli web stop
```

### Highlights:
- 🗂️ **Sidebar Vault Switcher**: Seamlessly switch between Personal Store and Team Vaults.
- 👥 **Team Management Modal**: Invite team members by User ID and change roles visually.
- 📋 **Audit Log Viewer**: Inspect who accessed or updated secrets with timestamps and IPs.
- 💻 **In-Browser SSH Terminal**: Direct interactive SSH terminal inside the browser.
- 🔍 **Search & Filter**: Real-time filtering by secret type (Password, Token, SSH).

---

## 💡 Pro Tips

### Session-based Master Password
Avoid typing your master password repeatedly by exporting it in your current terminal session:
```sh
export PACLI_MASTER_PASSWORD="your-master-password"
```

### Pipeline & Clipboard Tools
```sh
# Copy SSH public key to clipboard
cat ~/.ssh/id_rsa.pub | pacli cc

# Copy command output
terraform output -json | pacli cc
```

---

## 📄 License

Distributed under the [MIT License](LICENSE). Built with ❤️ by [imShakil](https://github.com/imShakil).
