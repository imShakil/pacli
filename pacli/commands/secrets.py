import click
import datetime
from getpass import getpass
from ..store import SecretStore
from ..log import get_logger
from ..decorators import master_password_required
from ..helpers import choice_one, copy_to_clipboard
from ..ssh_utils import suggest_ssh_hosts

logger = get_logger("pacli.commands.secrets")


@click.command()
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
@click.option("--key", "-k", "key_path", help="Path to SSH private key file.")
@click.option("--port", "-p", "ssh_port", help="SSH port (default: 22).")
@click.option("--opts", "-o", "ssh_opts", help="Additional SSH options.")
@click.argument("label", required=True)
@click.argument("arg1", required=False)
@click.argument("arg2", required=False)
@click.pass_context
@master_password_required
def add(ctx, token, password_flag, ssh_flag, key_path, ssh_port, ssh_opts, label, arg1, arg2):
    """Add a secret with LABEL. Use --token for a token, --pass for username and password, or --ssh for SSH Server."""
    store = SecretStore()

    # Auto-detect type if no flags specified
    if not any([token, password_flag, ssh_flag]):
        if arg1 and ("@" in arg1 or (":" in arg1 and not arg1.count(":") > 1)):
            ssh_flag = True
        elif arg1 and arg2:
            password_flag = True
        else:
            token = True

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


@click.command()
@click.argument("label", required=True)
@click.option("--clip", is_flag=True, help="Copy the secret to clipboard instead of printing.")
@master_password_required
def get(label, clip):
    """Retrieve secrets by LABEL. Use --clip to copy to clipboard."""
    store = SecretStore()
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


@click.command()
@click.argument("id", required=True)
@click.option("--clip", is_flag=True, help="Copy the secret to clipboard instead of printing.")
@master_password_required
def get_by_id(id, clip):
    """Retrieve a secret by its ID."""
    store = SecretStore()
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


@click.command()
@master_password_required
def list():
    """List all saved secrets."""
    store = SecretStore()
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


@click.command()
@click.argument("label", required=True)
@master_password_required
def update(label):
    """Update a secret by LABEL."""
    store = SecretStore()
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


@click.command()
@click.argument("id", required=True)
@master_password_required
def update_by_id(id):
    """Update secret with ID"""
    store = SecretStore()
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


@click.command()
@click.argument("label", required=True)
@master_password_required
def delete(label):
    """Delete a secret by LABEL."""
    store = SecretStore()
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


@click.command()
@click.argument("id", required=True)
@click.confirmation_option(prompt="Are you sure you want to delete this secret?")
@master_password_required
def delete_by_id(id):
    """Delete a secret by its ID."""
    store = SecretStore()
    try:
        store.delete_secret(id)
        click.echo(f"🗑️ Secret with ID {id} deleted successfully.")
    except Exception as e:
        logger.error(f"Error deleting secret by ID {id}: {e}")
        click.echo("❌ An error occurred while deleting the secret.")
