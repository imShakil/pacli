import click
from functools import wraps
from .store import SecretStore


def master_password_required(f):
    """Decorator to check if master password is set before executing command."""

    @wraps(f)
    def wrapper(*args, **kwargs):
        store = SecretStore()
        if not store.is_master_set():
            click.echo("❌ Master password not set. Run 'pacli init' first.")
            return
        return f(*args, **kwargs)

    return wrapper
