"""
CLI commands for vault sync — push/pull encrypted vault data to shared locations or a self-hosted pacli server.
"""

import os
import time
import click
from getpass import getpass
from ..store import SecretStore
from ..vault import VaultManager, get_user_identity
from ..sync_client import (
    get_sync_config,
    set_sync_config,
    resolve_server_params,
    push_to_server,
    pull_from_server,
    get_server_status,
)
from ..log import get_logger
from ..decorators import master_password_required

logger = get_logger("pacli.commands.sync")


@click.group()
def sync():
    """🔄 Sync vaults — push and pull encrypted vault backups to shared paths or a self-hosted server."""
    pass


# ------------------------------------------------------------------
# Config Subgroup
# ------------------------------------------------------------------


@sync.group("config")
def config_group():
    """Configure default sync server settings."""
    pass


@config_group.command("set")
@click.option("--server", "-s", "server_url", help="Sync server URL (e.g. https://pacli.example.com:58380).")
@click.option("--token", "-t", "token", help="Bearer access token from server admin.")
def config_set(server_url, token):
    """Save default sync server URL and token."""
    if not server_url and not token:
        click.echo("❌ Please provide at least --server or --token.")
        return

    cfg = set_sync_config(server_url=server_url, token=token)
    click.echo("✅ Sync configuration updated:")
    if cfg.get("server_url"):
        click.echo(f"   Server: {cfg['server_url']}")
    if cfg.get("token"):
        masked = cfg["token"][:12] + "..." if len(cfg["token"]) > 16 else "***"
        click.echo(f"   Token:  {masked}")


@config_group.command("show")
def config_show():
    """Show current saved sync configuration."""
    cfg = get_sync_config()
    if not cfg:
        click.echo("📭 No sync configuration saved. Use 'pacli sync config set --server ... --token ...'")
        return

    click.echo("📋 Saved Sync Configuration:")
    click.echo(f"   Server: {cfg.get('server_url', '—')}")
    token = cfg.get("token", "")
    masked = token[:12] + "..." if len(token) > 16 else ("(set)" if token else "—")
    click.echo(f"   Token:  {masked}")


# ------------------------------------------------------------------
# Push / Pull / Status
# ------------------------------------------------------------------


@sync.command("push")
@click.argument("vault_name")
@click.option("--to", "-t", "target_path", default=None, help="Destination directory path (e.g. ~/Dropbox/pacli/).")
@click.option("--server", "-s", "server_url", default=None, help="Sync server URL (overrides saved config).")
@click.option("--token", "token", default=None, help="Sync server token (overrides saved config).")
@click.option(
    "--password", "-p", "sync_password", default=None, help="Password for file export (not needed for server)."
)
@master_password_required
def sync_push(vault_name, target_path, server_url, token, sync_password):
    """
    Push an encrypted vault backup to a shared path or sync server.

    Examples:
        # Push to self-hosted server
        pacli sync push team-infra

        # Push to specific server with token
        pacli sync push team-infra --server http://192.168.1.50:58380 --token <tok>

        # Push to filesystem folder
        pacli sync push team-infra --to ~/Dropbox/pacli/
    """
    store = SecretStore()
    store.require_fernet()

    server_url, token = resolve_server_params(server_url, token)

    # Server mode
    if server_url and not target_path:
        if not token:
            click.echo("❌ Server URL configured but no access token provided.")
            click.echo("   Use 'pacli sync config set --token <token>' or pass --token.")
            return

        click.echo(f"☁️ Exporting and pushing vault '{vault_name}' to {server_url}...")
        try:
            vm = VaultManager()
            # For server relay, encrypt blob with vault key material
            blob = vm.export_vault_backup(vault_name, token, store.fernet)

            identity = get_user_identity()
            user_name = identity.get("user_name", "")

            res = push_to_server(vault_name, blob, server_url, token, user_name=user_name)
            status_text = "Updated" if res.get("updated") else "Unchanged"
            click.echo(f"✅ Vault '{vault_name}' pushed to server (Version: {res['version']}, Status: {status_text}).")
            logger.info(f"Vault '{vault_name}' pushed to server: {res}")
        except Exception as e:
            click.echo(f"❌ Server push failed: {e}")
            logger.error(f"Server push error: {e}")
        return

    # Filesystem mode
    if not target_path:
        click.echo("❌ Please specify --to <directory_path> or configure a sync server with 'pacli sync config set'.")
        return

    if not sync_password:
        click.echo("Choose a sync password (share this with team members).")
        pw1 = getpass("Sync password: ")
        if not pw1:
            click.echo("❌ Password cannot be empty.")
            return
        pw2 = getpass("Confirm sync password: ")
        if pw1 != pw2:
            click.echo("❌ Passwords do not match.")
            return
        sync_password = pw1

    try:
        vm = VaultManager()
        blob = vm.export_vault_backup(vault_name, sync_password, store.fernet)

        target_path = os.path.expanduser(target_path)
        os.makedirs(target_path, exist_ok=True)

        filename = f"{vault_name}.pacli"
        filepath = os.path.join(target_path, filename)

        with open(filepath, "wb") as f:
            f.write(blob)

        click.echo(f"✅ Pushed vault '{vault_name}' to: {filepath}")
        click.echo(f"   Team members can pull with: pacli sync pull {vault_name} --from {target_path}")
        logger.info(f"Vault '{vault_name}' pushed to {filepath}")
    except (ValueError, PermissionError) as e:
        click.echo(f"❌ {e}")
    except Exception as e:
        click.echo(f"❌ Push failed: {e}")
        logger.error(f"Sync push failed: {e}")


@sync.command("pull")
@click.argument("vault_name")
@click.option("--from", "-f", "source_path", default=None, help="Source directory containing .pacli files.")
@click.option("--server", "-s", "server_url", default=None, help="Sync server URL (overrides saved config).")
@click.option("--token", "token", default=None, help="Sync server token (overrides saved config).")
@click.option(
    "--password", "-p", "sync_password", default=None, help="Password for file import (not needed for server)."
)
@click.option("--overwrite", is_flag=True, default=False, help="Overwrite existing secrets (default: skip duplicates).")
@master_password_required
def sync_pull(vault_name, source_path, server_url, token, sync_password, overwrite):
    """
    Pull and import an encrypted vault backup from a shared path or sync server.

    Examples:
        # Pull from server
        pacli sync pull team-infra

        # Pull from filesystem folder
        pacli sync pull team-infra --from ~/Dropbox/pacli/
    """
    store = SecretStore()
    store.require_fernet()

    server_url, token = resolve_server_params(server_url, token)

    # Server mode
    if server_url and not source_path:
        if not token:
            click.echo("❌ Server URL configured but no access token provided.")
            return

        click.echo(f"☁️ Pulling vault '{vault_name}' from {server_url}...")
        try:
            blob, meta = pull_from_server(vault_name, server_url, token)
            if meta.get("not_modified") or blob is None:
                click.echo("✅ Vault is already up-to-date (no changes on server).")
                return

            vm = VaultManager()
            stats = vm.import_vault_backup(vault_name, blob, token, store.fernet, merge=not overwrite)

            v_str = f"v{meta['version']}" if meta.get("version") else ""
            by_str = f"by {meta['updated_by']}" if meta.get("updated_by") else ""
            click.echo(
                f"✅ Pulled vault '{vault_name}' {v_str} {by_str}: "
                f"{stats['imported']} imported, {stats['skipped']} skipped."
            )
            logger.info(f"Pulled vault '{vault_name}' from server: {stats}")
        except Exception as e:
            click.echo(f"❌ Server pull failed: {e}")
            logger.error(f"Server pull error: {e}")
        return

    # Filesystem mode
    if not source_path:
        click.echo("❌ Please specify --from <directory_path> or configure a sync server with 'pacli sync config set'.")
        return

    source_path = os.path.expanduser(source_path)
    filename = f"{vault_name}.pacli"
    filepath = os.path.join(source_path, filename)

    if not os.path.exists(filepath):
        click.echo(f"❌ File not found: {filepath}")
        click.echo(f"   Expected a file named '{filename}' in {source_path}")
        return

    if not sync_password:
        sync_password = getpass("Sync password: ")

    try:
        with open(filepath, "rb") as f:
            blob = f.read()

        vm = VaultManager()
        stats = vm.import_vault_backup(vault_name, blob, sync_password, store.fernet, merge=not overwrite)

        click.echo(
            f"✅ Pulled vault '{vault_name}': {stats['imported']} imported, "
            f"{stats['skipped']} skipped, {stats['errors']} errors."
        )
        logger.info(f"Vault '{vault_name}' pulled from {filepath}: {stats}")
    except ValueError as e:
        click.echo(f"❌ {e}")
    except Exception as e:
        click.echo(f"❌ Pull failed: {e}")
        logger.error(f"Sync pull failed: {e}")


@sync.command("status")
@click.argument("vault_name")
@click.option("--path", "-p", "sync_path", default=None, help="Sync directory path.")
@click.option("--server", "-s", "server_url", default=None, help="Sync server URL.")
@click.option("--token", "token", default=None, help="Sync server token.")
def sync_status(vault_name, sync_path, server_url, token):
    """Check if a vault has updates available at the sync path or server."""
    server_url, token = resolve_server_params(server_url, token)

    # Server mode
    if server_url and not sync_path:
        if not token:
            click.echo("❌ Server URL configured but no access token provided.")
            return

        try:
            status = get_server_status(vault_name, server_url, token)
            size_kb = (status.get("size") or 0) / 1024
            mod_time = (
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(status["updated_at"]))
                if status.get("updated_at")
                else "—"
            )
            click.echo(f"📦 Server status for vault '{vault_name}':")
            click.echo(f"   Server:     {server_url}")
            click.echo(f"   Version:    {status.get('version', 1)}")
            click.echo(f"   Size:       {size_kb:.1f} KB")
            click.echo(f"   Updated by: {status.get('updated_by', '—')}")
            click.echo(f"   Modified:   {mod_time}")
            click.echo(f"\n   To pull: pacli sync pull {vault_name}")
        except Exception as e:
            click.echo(f"❌ Server status check failed: {e}")
        return

    # Filesystem mode
    if not sync_path:
        click.echo("❌ Please specify --path <directory_path> or configure a sync server with 'pacli sync config set'.")
        return

    sync_path = os.path.expanduser(sync_path)
    filename = f"{vault_name}.pacli"
    filepath = os.path.join(sync_path, filename)

    if not os.path.exists(filepath):
        click.echo(f"📭 No sync file found for vault '{vault_name}' at {sync_path}")
        return

    stat = os.stat(filepath)
    size_kb = stat.st_size / 1024
    mod_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime))

    click.echo(f"📦 Sync file for vault '{vault_name}':")
    click.echo(f"   Path:     {filepath}")
    click.echo(f"   Size:     {size_kb:.1f} KB")
    click.echo(f"   Modified: {mod_time}")
    click.echo(f"\n   To pull: pacli sync pull {vault_name} --from {sync_path}")
