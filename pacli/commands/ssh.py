import click
import subprocess  # nosec 604
from ..store import SecretStore
from ..log import get_logger
from ..decorators import master_password_required
from ..helpers import choice_one

logger = get_logger("pacli.commands.ssh")


@click.command()
@click.argument("label", required=True)
@master_password_required
def ssh(label):
    """Connect to SSH server using saved SSH credentials."""
    store = SecretStore()
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
