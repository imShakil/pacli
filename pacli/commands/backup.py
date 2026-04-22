import os
import click
from getpass import getpass
from ..store import SecretStore
from ..log import get_logger
from ..decorators import master_password_required

logger = get_logger("pacli.commands.backup")

DEFAULT_BACKUP_NAME = "pacli_backup.pacli"


@click.group()
def backup():
    """Encrypted backup — export and import secrets across devices."""
    pass


@backup.command("export")
@click.option(
    "--output",
    "-o",
    default=DEFAULT_BACKUP_NAME,
    show_default=True,
    help="Output file path (e.g. ~/Dropbox/pacli_backup.pacli)",
)
@master_password_required
def backup_export(output):
    """
    Export all secrets to an encrypted backup file.

    The backup is encrypted with a *separate* backup password so it is
    safe to upload to Dropbox, Google Drive, iCloud, etc.

    To restore on another device:
        pacli backup import --input pacli_backup.pacli
    """
    store = SecretStore()
    store.require_fernet()

    click.echo("📦 Creating encrypted backup…")
    click.echo("Choose a backup password (different from your master password is fine).")
    pw1 = getpass("Backup password: ")
    if not pw1:
        click.echo("❌ Password cannot be empty.")
        return
    pw2 = getpass("Confirm backup password: ")
    if pw1 != pw2:
        click.echo("❌ Passwords do not match.")
        return

    try:
        blob = store.export_encrypted_backup(pw1)
        output = os.path.expanduser(output)
        with open(output, "wb") as f:
            f.write(blob)
        click.echo(f"✅ Backup saved to: {output}")
        click.echo("   Upload this file to your cloud storage of choice.")
        click.echo("   Use 'pacli backup import' on any device to restore.")
        logger.info(f"Encrypted backup exported to {output}")
    except Exception as e:
        click.echo(f"❌ Backup failed: {e}")
        logger.error(f"Backup export failed: {e}")


@backup.command("import")
@click.option(
    "--input",
    "-i",
    "input_path",
    required=True,
    help="Path to the .pacli backup file",
)
@click.option(
    "--overwrite",
    is_flag=True,
    default=False,
    help="Overwrite secrets that already exist (default: skip duplicates)",
)
@master_password_required
def backup_import(input_path, overwrite):
    """
    Import secrets from an encrypted backup file.

    By default, secrets that already exist on this device are skipped.
    Use --overwrite to replace them.
    """
    input_path = os.path.expanduser(input_path)
    if not os.path.exists(input_path):
        click.echo(f"❌ File not found: {input_path}")
        return

    store = SecretStore()
    store.require_fernet()

    pw = getpass("Backup password: ")
    try:
        with open(input_path, "rb") as f:
            blob = f.read()
        stats = store.import_encrypted_backup(blob, pw, merge=not overwrite)
        click.echo(
            f"✅ Import complete: {stats['imported']} imported, "
            f"{stats['skipped']} skipped, {stats['errors']} errors."
        )
        logger.info(f"Backup imported from {input_path}: {stats}")
    except ValueError as e:
        click.echo(f"❌ {e}")
    except Exception as e:
        click.echo(f"❌ Import failed: {e}")
        logger.error(f"Backup import failed: {e}")
