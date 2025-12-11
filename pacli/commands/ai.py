import click

# import os
from ..log import get_logger

__name__ = "pacli.commands.ai"

logger = get_logger(__name__)


@click.command()
def ai():
    """AI command."""
    click.echo("AI command is not implemented yet.")
    logger.info("AI command is not implemented yet.")
