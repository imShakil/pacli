import click
import webbrowser
import os
from ..web.app import create_app
from ..log import get_logger

logger = get_logger("pacli.web")


@click.command()
@click.option(
    "--host",
    default="127.0.0.1",
    help="Host to bind to (default: 127.0.0.1)",
)
@click.option(
    "--port",
    default=5000,
    type=int,
    help="Port to bind to (default: 5000)",
)
@click.option(
    "--no-browser",
    is_flag=True,
    help="Don't open browser automatically",
)
def web(host, port, no_browser):
    """Launch the Web UI for pacli."""
    try:
        app = create_app()

        # Set Flask environment
        os.environ["FLASK_ENV"] = "production"

        url = f"http://{host}:{port}"

        if not no_browser:
            # Open browser after a short delay to allow server to start
            import threading
            import time

            def open_browser():
                time.sleep(1)
                try:
                    webbrowser.open(url)
                except Exception as e:
                    logger.warning(f"Could not open browser: {e}")

            thread = threading.Thread(target=open_browser, daemon=True)
            thread.start()

        click.echo(f"🔐 pacli Web UI starting at {url}")
        click.echo("Press Ctrl+C to stop the server")

        app.run(host=host, port=port, debug=False)
    except Exception as e:
        logger.error(f"Failed to start web UI: {e}")
        click.echo(f"Error: {e}", err=True)
        raise click.Abort()
