import click
from .commands.admin import init, change_master_key, version
from .commands.secrets import add, get, get_by_id, list, update, update_by_id, delete, delete_by_id
from .commands.ssh import ssh
from .commands.utils import export, short, cc


@click.group()
def cli():
    """🔐 pacli - Personal Access CLI for managing secrets..."""
    pass


# Register all commands
cli.add_command(init)
cli.add_command(add)
cli.add_command(get)
cli.add_command(get_by_id)
cli.add_command(list)
cli.add_command(update)
cli.add_command(update_by_id)
cli.add_command(delete)
cli.add_command(delete_by_id)
cli.add_command(change_master_key)
cli.add_command(ssh)
cli.add_command(export)
cli.add_command(short)
cli.add_command(cc)
cli.add_command(version)
