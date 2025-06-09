"""
Command line interface for the Launchpad service.
"""

import click
import structlog
from gunicorn.app.wsgiapp import WSGIApplication

from launchpad.app import create_app
from launchpad.settings import get_settings

logger = structlog.get_logger(__name__)


class GunicornApp(WSGIApplication):
    """Custom Gunicorn application class."""

    def __init__(self, app, options=None):
        self.options = options or {}
        self.application = app
        super().__init__()

    def load_config(self):
        """Load Gunicorn configuration."""
        config = {key: value for key, value in self.options.items() if key in self.cfg.settings and value is not None}
        for key, value in config.items():
            self.cfg.set(key.lower(), value)

    def load(self):
        """Load the WSGI application."""
        return self.application


@click.group()
@click.version_option()
def main():
    """Launchpad service CLI."""
    pass


@main.command()
@click.option("--host", default=None, help="Host to bind to")
@click.option("--port", default=None, type=int, help="Port to bind to")
@click.option("--workers", default=None, type=int, help="Number of worker processes")
@click.option("--no-workers", is_flag=True, help="Run without worker processes (single threaded)")
@click.option("--reload", is_flag=True, help="Auto-reload on code changes")
def devserver(host, port, workers, no_workers, reload):
    """Run the development server."""
    settings = get_settings()

    # Override settings with CLI options
    if host:
        settings.host = host
    if port:
        settings.port = port

    app = create_app()

    if settings.debug or reload:
        # Development mode - use Flask's built-in server
        logger.info("Starting development server", host=settings.host, port=settings.port)
        app.run(host=settings.host, port=settings.port, debug=settings.debug, use_reloader=reload)
    else:
        # Production mode - use Gunicorn
        worker_count = 1 if no_workers else (workers or 4)

        options = {
            "bind": f"{settings.host}:{settings.port}",
            "workers": worker_count,
            "worker_class": "sync",
            "timeout": 30,
            "keepalive": 2,
            "max_requests": 1000,
            "max_requests_jitter": 100,
            "preload_app": True,
            "access_log_format": '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s',
        }

        logger.info("Starting Gunicorn server", host=settings.host, port=settings.port, workers=worker_count)
        GunicornApp(app, options).run()


@main.command()
def health():
    """Check service health."""
    import requests

    settings = get_settings()

    try:
        response = requests.get(f"http://{settings.host}:{settings.port}/health", timeout=5)
        if response.status_code == 200:
            click.echo("✅ Service is healthy")
            click.echo(response.json())
        else:
            click.echo(f"❌ Service returned status {response.status_code}")
            click.echo(response.text)
    except requests.RequestException as e:
        click.echo(f"❌ Failed to connect to service: {e}")


@main.command()
def config():
    """Show current configuration."""
    settings = get_settings()
    click.echo("Current configuration:")
    click.echo(f"  Host: {settings.host}")
    click.echo(f"  Port: {settings.port}")
    click.echo(f"  Debug: {settings.debug}")
    click.echo(f"  Redis: {settings.redis_host}:{settings.redis_port}")
    click.echo(f"  Kafka: {settings.kafka_brokers}")
    click.echo(f"  Log Level: {settings.log_level}")


if __name__ == "__main__":
    main()
