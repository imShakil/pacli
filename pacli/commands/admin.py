import os
import click
from getpass import getpass
from ..store import SecretStore
from ..log import get_logger
from .. import __version__, __metadata__

logger = get_logger("pacli.commands.admin")


@click.command()
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


@click.command()
def change_master_key():
    """Change the master password without losing secrets."""
    store = SecretStore()
    store.require_fernet()
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
    store.require_fernet()
    for sid, plain in all_secrets:
        encrypted = store.fernet.encrypt(plain.encode()).decode()
        store.conn.execute("UPDATE secrets SET value_encrypted = ? WHERE id = ?", (encrypted, sid))
    store.conn.commit()
    logger.info("Master password changed and all secrets re-encrypted.")
    click.echo("✅ Master password changed and all secrets re-encrypted.")


@click.command()
def version():
    """Show the current version of pacli."""
    AUTHOR = "Unknown"
    HOMEPAGE = "Unknown"

    if __metadata__:
        AUTHOR = __metadata__["Author-email"]
        HOMEPAGE = __metadata__["Project-URL"].split(",")[1].strip()

    click.echo("🔐 pacli - Secrets Management CLI")
    click.echo("-" * 33)
    click.echo(f"Version: {__version__}")
    click.echo(f"Author: {AUTHOR}")
    click.echo(f"GitHub: {HOMEPAGE}")
