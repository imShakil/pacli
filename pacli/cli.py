import os
import click
import datetime
import pyperclip
from getpass import getpass
from .store import SecretStore
from .log import get_logger

logger = get_logger("pacli.cli")
VERSION = "1.0.0"


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
            "Master password is already set. If you want to reset, delete ~/.config/pacli/salt.bin and run this command again."
        )
        return
    store.set_master_password()
    click.echo("✅ Master password set. You can now add secrets.")


@cli.command()
@click.option(
    "--token", is_flag=True, help="Use this flag to store a token instead of a secret."
)
@click.option(
    "--pass",
    "password_flag",
    is_flag=True,
    help="Use this flag to store a username and password instead of a token or generic secret.",
)
@click.argument("label", required=True)
@click.argument("arg1", required=False)
@click.argument("arg2", required=False)
@click.pass_context
def add(ctx, token, password_flag, label, arg1, arg2):
    """Add a secret with LABEL. Use --token for a token or --pass for username and password."""
    store = SecretStore()
    if not store.is_master_set():
        click.echo("❌ Master password not set. Run 'pacli init' first.")
        return
    if token and password_flag:
        logger.error("Both --token and --pass flags used together.")
        click.echo("❌ You cannot use both --token and --pass flags at the same time.")
        return
    if not token and not password_flag:
        logger.error("Neither --token nor --pass flag specified.")
        click.echo("❌ You must specify either --token or --pass.")
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


@cli.command()
@click.argument("label")
@click.option(
    "--clip", is_flag=True, help="Copy the secret to clipboard instead of printing."
)
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
        copy_to_clipboard(selected["secret"])
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
        cstr = (
            datetime.datetime.fromtimestamp(ctime).strftime("%Y-%m-%d %H:%M:%S")
            if ctime
            else ""
        )
        ustr = (
            datetime.datetime.fromtimestamp(utime).strftime("%Y-%m-%d %H:%M:%S")
            if utime
            else ""
        )
        click.echo(f"{sid:10}  {label:33}  {stype:10}  {cstr:20}  {ustr:20}")


@cli.command()
@click.argument("label")
# @click.confirmation_option(prompt='Are you sure you want to delete this secret?')
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
    click.echo("/n/n 🗑️ Deleted from the list.")


@cli.command()
def change_master_key():
    """Change the master password wihtout losing existing secrets."""
    store = SecretStore()
    if not store.is_master_set():
        click.echo("❌ Master password not set. Run 'pacli init' first.")
        return
    old_password = getpass("🔐 Enter old master password: ")
    if not store.verify_master_password(old_password):
        click.echo("❌ Old master password is incorrect.")
        return
    store.require_fernet()  # Ensures old key is loaded
    all_secrets = []
    for row in store.conn.execute("SELECT id, value_encrypted FROM secrets"):
        try:
            decrypted = store.fernet.decrypt(row[1].encode()).decode()
            all_secrets.append((row[0], decrypted))
        except Exception as e:
            logger.error(f"Failed to decrypt secret {row[0]}: {e}")
            click.echo(f"❌ Failed to decrypt a secret. Aborting master key change.")
            return

    new_password = getpass("🔐 Enter new master password: ")
    confirm_password = getpass("🔐 Confirm new master password: ")
    if new_password != confirm_password or not new_password:
        click.echo("❌ Passwords do not match or are empty. Aborting.")
        return

    store.set_master_password(new_password)
    store.require_fernet()  # Ensures new key is loaded
    for sid, plain in all_secrets:
        encrypted = store.fernet.encrypt(plain.encode()).decode()
        store.conn.execute(
            "UPDATE secrets SET value_encrypted = ? WHERE id = ?", (encrypted, sid)
        )
    store.conn.commit()
    logger.info("Master password changed and all secrets re-encrypted.")
    click.echo("✅ Master password changed and all secrets re-encrypted.")


@cli.command()
@click.argument("id", required=True)
@click.option(
    "--clip", is_flag=True, help="Copy the secret to clipboard instead of printing."
)
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
            copy_to_clipboard(secret["secret"])
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
            datetime.datetime.fromtimestamp(s["creation_time"]).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            if s["creation_time"]
            else ""
        )
        ustr = (
            datetime.datetime.fromtimestamp(s["update_time"]).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            if s["update_time"]
            else ""
        )
        click.echo(
            f"[{idx}] ID: {s['id']}  Type: {s['type']}  Created: {cstr}  Updated: {ustr}"
        )
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
        click.echo(
            "❌ pyperclip is not installed. Run 'pip install pyperclip' to enable clipboard support."
        )
    except Exception as e:
        click.echo(f"❌ Failed to copy to clipboard: {e}")
