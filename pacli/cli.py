import os
import json
import csv
import click
import datetime
import pyperclip
import subprocess  # nosec B404
from getpass import getpass
from .store import SecretStore
from .log import get_logger
from . import __version__
from .ssh_utils import suggest_ssh_hosts

logger = get_logger("pacli.cli")
VERSION = __version__


@click.group()
def cli():
    """🔐 pacli - Personal Access CLI for managing secrets..."""
    pass


@cli.command()
def init():
    """Initialize pacli and set a master password."""
    config_dir = os.path.expanduser("~/.config/pacli")
    os.makedirs(config_dir, exist_ok=True)
    try:
        os.chmod(config_dir, 0o700)
    except Exception as e:
        logger.warning(f"Could not set permissions on {config_dir}: {e}")
    store = SecretStore()
    if store.is_master_set():
        click.echo(
            "Master password is already set. If you want to reset, "
            + "delete ~/.config/pacli/salt.bin and run this command again."
        )
        return
    store.set_master_password()
    click.echo("✅ Master password set. You can now add secrets.")


@cli.command()
@click.option("--token", is_flag=True, help="Use this flag to store a token instead of a secret.")
@click.option(
    "--pass",
    "password_flag",
    is_flag=True,
    help="Use this flag to store a username and password instead of a token or generic secret.",
)
@click.option(
    "--ssh",
    "ssh_flag",
    is_flag=True,
    help="Use this flag to store SSH connection details (user:ip).",
)
@click.option(
    "--key",
    "key_path",
    help="Path to SSH private key file.",
)
@click.option(
    "--port",
    "-p",
    "ssh_port",
    help="SSH port (default: 22).",
)
@click.option(
    "--opts",
    "ssh_opts",
    help="Additional SSH options.",
)
@click.argument("label", required=True)
@click.argument("arg1", required=False)
@click.argument("arg2", required=False)
@click.pass_context
def add(ctx, token, password_flag, ssh_flag, key_path, ssh_port, ssh_opts, label, arg1, arg2):
    """Add a secret with LABEL. Use --token for a token, --pass for username and password, or --ssh for SSH Server."""
    store = SecretStore()
    if not store.is_master_set():
        click.echo("❌ Master password not set. Run 'pacli init' first.")
        return

    # Auto-detect type if no flags specified
    if not any([token, password_flag, ssh_flag]):
        if arg1 and ("@" in arg1 or (":" in arg1 and not arg1.count(":") > 1)):
            ssh_flag = True
        elif arg1 and arg2:  # username and password provided
            password_flag = True
        else:
            token = True  # default to token

    flags = [token, password_flag, ssh_flag]
    if sum(flags) > 1:
        logger.error("Multiple flags used together.")
        click.echo("❌ You cannot use multiple flags at the same time.")
        return

    if token:
        secret = arg1 if arg1 else getpass("🔐 Enter token: ")
        store.save_secret(label, secret, "token")
        logger.info(f"Token saved for label: {label}")
        click.echo("✅ Token saved.")
    elif password_flag:
        username = arg1 if arg1 else click.prompt("Enter username")
        password = arg2 if arg2 else getpass("🔐 Enter password: ")
        store.save_secret(label, f"{username}:{password}", "password")
        logger.info(f"Username and password saved for label: {label}")
        click.echo(f"✅ {label} credentials saved.")
    elif ssh_flag:
        if arg1:
            if "@" in arg1:
                user_ip = arg1.replace("@", ":")
            elif ":" in arg1:
                user_ip = arg1
            else:
                user = arg1
                ip = arg2 if arg2 else click.prompt("Enter SSH IP/hostname")
                user_ip = f"{user}:{ip}"
        else:
            # Suggest hosts from SSH config
            suggested_hosts = suggest_ssh_hosts()
            if suggested_hosts:
                click.echo("Available SSH hosts from config:")
                for i, host in enumerate(suggested_hosts[:5], 1):
                    click.echo(f"  {i}. {host}")
                click.echo("")

            user = click.prompt("Enter SSH username")
            ip = click.prompt("Enter SSH IP/hostname")
            user_ip = f"{user}:{ip}"

        ssh_data = user_ip
        if key_path:
            ssh_data += f"|key:{key_path}"
        if ssh_port:
            ssh_data += f"|port:{ssh_port}"
        if ssh_opts:
            ssh_data += f"|opts:{ssh_opts}"

        store.save_secret(label, ssh_data, "ssh")
        logger.info(f"SSH connection saved for label: {label}")
        click.echo(f"✅ SSH connection {label} saved.")


@cli.command()
@click.argument("label", required=True)
@click.option("--clip", is_flag=True, help="Copy the secret to clipboard instead of printing.")
def get(label, clip):
    """Retrieve secrets by LABEL. Use --clip to copy to clipboard."""
    store = SecretStore()
    if not store.is_master_set():
        click.echo("❌ Master password not set. Run 'pacli init' first.")
        return
    matches = store.get_secrets_by_label(label)
    if not matches:
        logger.warning(f"Secret not found for label: {label}")
        click.echo("❌ Secret not found.")
        return
    if len(matches) == 1:
        selected = matches[0]
    else:
        selected = choice_one(label, matches)
        if not selected:
            click.echo("❌ No valid selection made. Aborting.")
            return
    logger.info(f"Secret retrieved for label: {label}, id: {selected['id']}")
    if clip:
        if selected["type"] == "ssh":
            ssh_data = selected["secret"]
            user_ip = ssh_data.split("|")[0]
            copy_to_clipboard(user_ip)
        else:
            copy_to_clipboard(selected["secret"])
    else:
        if selected["type"] == "ssh":
            ssh_data = selected["secret"]
            parts = ssh_data.split("|")
            user_ip = parts[0]
            extras = []
            for part in parts[1:]:
                if part.startswith("key:"):
                    extras.append(f"Key: {part[4:]}")
                elif part.startswith("port:"):
                    extras.append(f"Port: {part[5:]}")
                elif part.startswith("opts:"):
                    extras.append(f"Opts: {part[5:]}")

            display = f"🔐 SSH: {user_ip}"
            if extras:
                display += f" ({', '.join(extras)})"
            click.echo(display)
        else:
            click.echo(f"🔐 Secret: {selected['secret']}")


@cli.command()
def list():
    """List all saved secrets."""
    store = SecretStore()
    if not store.is_master_set():
        click.echo("❌ Master password not set. Run 'pacli init' first.")
        return

    secrets = store.list_secrets()
    if not secrets:
        logger.info("No secrets found.")
        click.echo("(No secrets found)")
        return

    logger.info("Listing all saved secrets.")
    click.echo("📜 List of saved secrets:")

    click.echo(f"{'ID':10}  {'Label':33}  {'Type':10}  {'Created':20}  {'Updated':20}")
    click.echo("-" * 100)
    for sid, label, stype, ctime, utime in secrets:
        cstr = datetime.datetime.fromtimestamp(ctime).strftime("%Y-%m-%d %H:%M:%S") if ctime else ""
        ustr = datetime.datetime.fromtimestamp(utime).strftime("%Y-%m-%d %H:%M:%S") if utime else ""
        click.echo(f"{sid:10}  {label:33}  {stype:10}  {cstr:20}  {ustr:20}")


@cli.command()
@click.argument("label", required=True)
def update(label):
    """Update a secret by LABEL."""
    store = SecretStore()
    if not store.is_master_set():
        click.echo("❌ Master password not set. Run 'pacli init' first.")
        return
    matches = store.get_secrets_by_label(label)
    if not matches:
        logger.warning(f"Attempted to update non-existent secret: {label}")
        click.echo("❌ Secret not found or may already be deleted.")
        return
    logger.info(f"Updating secret for label: {label}")
    if len(matches) == 1:
        selected = matches[0]
    else:
        selected = choice_one(label, matches)
        if not selected:
            click.echo("❌ No valid selection made. Aborting.")
            return
    id = selected["id"]
    if selected["type"] == "ssh":
        current_ssh = selected["secret"]
        if "|" in current_ssh:
            user_ip, key_path = current_ssh.split("|", 1)
            click.echo(f"Current SSH: {user_ip} (Key: {key_path})")
        else:
            click.echo(f"Current SSH: {current_ssh}")

        new_user = click.prompt("Enter new SSH username", default="")
        new_ip = click.prompt("Enter new SSH IP/hostname", default="")
        new_key = click.prompt("Enter new SSH key path (optional)", default="")

        if new_user and new_ip:
            new_secret = f"{new_user}:{new_ip}"
            if new_key:
                new_secret += f"|{new_key}"
        else:
            click.echo("❌ Username and IP are required for SSH connections.")
            return
    else:
        new_secret = getpass(f"Enter updated secret for {label} with {id}:")
    try:
        store.update_secret(selected["id"], new_secret)
        click.echo("✅ Updated secret successfully!")
        logger.info(f"Secreted update for {label} with ID: {selected['id']}")
    except Exception as e:
        click.echo(f"❌ couldn't able to update due to {e}")


@cli.command()
@click.argument("id", required=True)
def update_by_id(id):
    """Update secret with ID"""
    store = SecretStore()
    if not store.is_master_set():
        click.echo("❌ Master password not set. Run 'pacli init' first.")
        return
    secret = store.get_secret_by_id(id)
    if not secret:
        click.echo(f"❌ No secret found with ID: {id}")
        return
    if secret["type"] == "ssh":
        current_ssh = secret["secret"]
        if "|" in current_ssh:
            user_ip, key_path = current_ssh.split("|", 1)
            click.echo(f"Current SSH: {user_ip} (Key: {key_path})")
        else:
            click.echo(f"Current SSH: {current_ssh}")

        new_user = click.prompt("Enter new SSH username", default="")
        new_ip = click.prompt("Enter new SSH IP/hostname", default="")
        new_key = click.prompt("Enter new SSH key path (optional)", default="")

        if new_user and new_ip:
            new_secret = f"{new_user}:{new_ip}"
            if new_key:
                new_secret += f"|{new_key}"
        else:
            click.echo("❌ Username and IP are required for SSH connections.")
            return
    else:
        new_secret = getpass("Enter updated secret: ")
    try:
        store.update_secret(id, new_secret)
        click.echo("✅ Updated secret successfully!")
        logger.info(f"Secreted update with ID: {id}")
    except Exception as e:
        click.echo(f"❌ couldn't able to update due to {e}")


@cli.command()
@click.argument("label", required=True)
def delete(label):
    """Delete a secret by LABEL."""
    store = SecretStore()
    if not store.is_master_set():
        click.echo("❌ Master password not set. Run 'pacli init' first.")
        return
    matches = store.get_secrets_by_label(label)
    if not matches:
        logger.warning(f"Attempted to delete non-existent secret: {label}")
        click.echo("❌ Secret not found or may already be deleted.")
        return
    logger.info(f"Deleting secret for label: {label}")
    if len(matches) == 1:
        selected = matches[0]
    else:
        selected = choice_one(label, matches)
        if not selected:
            click.echo("❌ No valid selection made. Aborting.")
            return

    if not click.confirm("Are you sure you want to delete this secret?"):
        click.echo("❌ Deletion cancelled.")
        return

    logger.info(f"Deleting secret with ID: {selected['id']} and label: {label}")
    click.echo(f"🔐 Deleting secret with ID: {selected['id']} and label: {label}")
    store.delete_secret(selected["id"])
    logger.info(f"Secret deleted for label: {label} with ID: {selected['id']}")
    click.echo("🗑️ Deleted from the list.")


@cli.command()
def change_master_key():
    """Change the master password wihtout losing secrets."""
    store = SecretStore()
    store.require_fernet()  # Ensures old key is loaded
    all_secrets = []
    for row in store.conn.execute("SELECT id, value_encrypted FROM secrets"):
        try:
            decrypted = store.fernet.decrypt(row[1].encode()).decode()
            all_secrets.append((row[0], decrypted))
        except Exception as e:
            logger.error(f"Failed to decrypt secret {row[0]}: {e}")
            click.echo("❌ Failed to decrypt a secret. Aborting master key change.")
            return

    new_password = getpass("🔐 Enter new master password: ")
    confirm_password = getpass("🔐 Confirm new master password: ")
    if new_password != confirm_password or not new_password:
        click.echo("❌ Passwords do not match or are empty. Aborting.")
        return

    store.update_master_password(new_password)
    store.require_fernet()  # Ensures new key is loaded
    for sid, plain in all_secrets:
        encrypted = store.fernet.encrypt(plain.encode()).decode()
        store.conn.execute("UPDATE secrets SET value_encrypted = ? WHERE id = ?", (encrypted, sid))
    store.conn.commit()
    logger.info("Master password changed and all secrets re-encrypted.")
    click.echo("✅ Master password changed and all secrets re-encrypted.")


@cli.command()
@click.argument("id", required=True)
@click.option("--clip", is_flag=True, help="Copy the secret to clipboard instead of printing.")
def get_by_id(id, clip):
    """Retrieve a secret by its ID."""
    store = SecretStore()
    if not store.is_master_set():
        click.echo("❌ Master password not set. Run 'pacli init' first.")
        return
    try:
        secret = store.get_secret_by_id(id)
        if not secret:
            click.echo(f"❌ No secret found with ID: {id}")
            return
        if clip:
            if secret["type"] == "ssh":
                ssh_data = secret["secret"]
                user_ip = ssh_data.split("|")[0]
                copy_to_clipboard(user_ip)
            else:
                copy_to_clipboard(secret["secret"])
        else:
            if secret["type"] == "ssh":
                ssh_data = secret["secret"]
                parts = ssh_data.split("|")
                user_ip = parts[0]
                extras = []
                for part in parts[1:]:
                    if part.startswith("key:"):
                        extras.append(f"Key: {part[4:]}")
                    elif part.startswith("port:"):
                        extras.append(f"Port: {part[5:]}")
                    elif part.startswith("opts:"):
                        extras.append(f"Opts: {part[5:]}")

                display = f"🔐 SSH for ID {id}: {user_ip}"
                if extras:
                    display += f" ({', '.join(extras)})"
                click.echo(display)
            else:
                click.echo(f"🔐 Secret for ID {id}: {secret['secret']}")
    except Exception as e:
        logger.error(f"Error retrieving secret by ID {id}: {e}")
        click.echo("❌ An error occurred while retrieving the secret.")


@cli.command()
@click.argument("id", required=True)
@click.confirmation_option(prompt="Are you sure you want to delete this secret?")
def delete_by_id(id):
    """Delete a secret by its ID."""
    store = SecretStore()
    if not store.is_master_set():
        click.echo("❌ Master password not set. Run 'pacli init' first.")
        return
    try:
        store.delete_secret(id)
        click.echo(f"🗑️ Secret with ID {id} deleted successfully.")
    except Exception as e:
        logger.error(f"Error deleting secret by ID {id}: {e}")
        click.echo("❌ An error occurred while deleting the secret.")


@cli.command()
@click.option("--format", "-f", type=click.Choice(["json", "csv"]), default="csv", help="Export format (json or csv)")
@click.option("--output", "-o", help="Output file path")
def export(format, output):
    """Export secrets to JSON or CSV format."""
    store = SecretStore()
    if not store.is_master_set():
        click.echo("❌ Master password not set. Run 'pacli init' first.")
        return

    secrets = store.list_secrets()
    if not secrets:
        click.echo("❌ No secrets to export.")
        return

    export_data = []
    for sid, label, stype, ctime, utime in secrets:
        secret_data = store.get_secret_by_id(sid)
        if secret_data:
            export_data.append(
                {
                    "id": sid,
                    "label": label,
                    "secret": secret_data["secret"],
                    "type": stype,
                    "created": datetime.datetime.fromtimestamp(ctime).isoformat() if ctime else None,
                    "updated": datetime.datetime.fromtimestamp(utime).isoformat() if utime else None,
                }
            )

    if not output:
        output = f"pacli_export_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.{format}"

    try:
        if format == "json":
            with open(output, "w") as f:
                json.dump(export_data, f, indent=2)
        else:  # csv
            with open(output, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["id", "label", "secret", "type", "created", "updated"])
                writer.writeheader()
                writer.writerows(export_data)

        click.echo(f"✅ Exported {len(export_data)} secrets to {output}")
        logger.info(f"Exported {len(export_data)} secrets to {output}")
    except Exception as e:
        click.echo(f"❌ Export failed: {e}")
        logger.error(f"Export failed: {e}")


@cli.command()
@click.argument("label", required=True)
def ssh(label):
    """Connect to SSH server using saved SSH credentials."""
    store = SecretStore()
    if not store.is_master_set():
        click.echo("❌ Master password not set. Run 'pacli init' first.")
        return

    matches = store.get_secrets_by_label(label)
    if not matches:
        logger.warning(f"SSH connection not found for label: {label}")
        click.echo("❌ SSH connection not found.")
        return

    ssh_secrets = [m for m in matches if m["type"] == "ssh"]
    if not ssh_secrets:
        click.echo("❌ No SSH connections found for this label.")
        return

    if len(ssh_secrets) == 1:
        selected = ssh_secrets[0]
    else:
        selected = choice_one(label, ssh_secrets)
        if not selected:
            click.echo("❌ No valid selection made. Aborting.")
            return

    ssh_data = selected["secret"]
    parts = ssh_data.split("|")
    user_ip = parts[0]

    if ":" not in user_ip:
        click.echo("❌ Invalid SSH format. Expected user:host")
        return

    user, ip = user_ip.split(":", 1)

    # Validate user and IP
    if not user.replace("-", "").replace("_", "").replace(".", "").isalnum():
        click.echo("❌ Invalid username format")
        return

    cmd_parts = ["ssh"]

    # Parse additional options with validation
    for part in parts[1:]:
        if part.startswith("key:"):
            key_path = part[4:]
            if not key_path or ".." in key_path:
                click.echo("❌ Invalid key path")
                return
            cmd_parts.extend(["-i", key_path])
        elif part.startswith("port:"):
            port = part[5:]
            if not port.isdigit() or not (1 <= int(port) <= 65535):
                click.echo("❌ Invalid port number")
                return
            cmd_parts.extend(["-p", port])
        elif part.startswith("opts:"):
            opts = part[5:]
            # Only allow safe SSH options
            safe_opts = ["-o", "StrictHostKeyChecking=no", "UserKnownHostsFile=/dev/null", "ConnectTimeout=10"]
            if not all(opt in safe_opts or opt.startswith("-o") for opt in opts.split()):
                click.echo("❌ Unsafe SSH options detected")
                return
            cmd_parts.extend(opts.split())

    cmd_parts.append(f"{user}@{ip}")

    logger.info(f"Connecting to SSH: {user}@{ip}")
    click.echo(f"🔗 Connecting to {user}@{ip}...")
    try:
        subprocess.run(cmd_parts, check=False)  # nosec B603
    except FileNotFoundError:
        click.echo("❌ SSH command not found. Please install OpenSSH client.")
    except Exception as e:
        click.echo(f"❌ SSH connection failed: {e}")


@cli.command()
def version():
    """Show the current version of pacli."""
    click.echo("🔐 pacli - Secrets Management CLI")
    click.echo("-" * 33)
    click.echo(f"Version: {VERSION}")
    click.echo("Author: imShakil")
    click.echo("GitHub: https://github.com/imshakil/pacli")


def choice_one(label, matches):
    click.echo(f"Multiple secrets found for label '{label}':")
    for idx, s in enumerate(matches, 1):
        cstr = (
            datetime.datetime.fromtimestamp(s["creation_time"]).strftime("%Y-%m-%d %H:%M:%S")
            if s["creation_time"]
            else ""
        )
        ustr = (
            datetime.datetime.fromtimestamp(s["update_time"]).strftime("%Y-%m-%d %H:%M:%S") if s["update_time"] else ""
        )
        click.echo(f"[{idx}] ID: {s['id']}  Type: {s['type']}  Created: {cstr}  Updated: {ustr}")
    while True:
        choice = click.prompt("Select which secret to retrieve (number)", type=int)
        if 1 <= choice <= len(matches):
            selected = matches[choice - 1]
            break
        click.echo("Invalid selection. Try again.")
    return selected


def copy_to_clipboard(secret):
    """Copy text to clipboard."""
    try:
        pyperclip.copy(secret)
        click.echo("📋 Secret copied to clipboard.")
    except ImportError:
        click.echo("❌ pyperclip is not installed. Run 'pip install pyperclip' to enable clipboard support.")
    except Exception as e:
        click.echo(f"❌ Failed to copy to clipboard: {e}")
