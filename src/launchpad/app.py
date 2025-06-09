"""
Main Flask application for the Launchpad service.
"""

import ipaddress
import logging
from typing import Any, Dict

import sentry_sdk
import structlog
from flask import Flask, abort, jsonify, request
from sentry_sdk.integrations.flask import FlaskIntegration
from sentry_sdk.integrations.logging import LoggingIntegration

from launchpad.settings import get_settings


def create_app() -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)
    settings = get_settings()

    # Configure logging
    configure_logging(settings.log_level)

    # Configure Sentry
    if settings.sentry_dsn:
        configure_sentry(settings.sentry_dsn, settings.sentry_environment)

    # Add security middleware
    add_security_middleware(app, settings)

    # Register blueprints/routes
    register_routes(app)

    return app


def configure_logging(log_level: str) -> None:
    """Configure structured logging."""
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    logging.basicConfig(
        format="%(message)s",
        level=getattr(logging, log_level.upper()),
    )


def configure_sentry(dsn: str, environment: str) -> None:
    """Configure Sentry error tracking."""
    sentry_logging = LoggingIntegration(level=logging.INFO, event_level=logging.ERROR)

    sentry_sdk.init(
        dsn=dsn,
        integrations=[
            FlaskIntegration(transaction_style="url"),
            sentry_logging,
        ],
        environment=environment,
        traces_sample_rate=0.1,
    )


def add_security_middleware(app: Flask, settings) -> None:
    """Add security middleware for internal service protection."""
    logger = structlog.get_logger(__name__)

    @app.before_request
    def check_internal_access():
        """Ensure requests come from allowed internal sources."""
        # Skip security checks in debug mode for development
        if settings.debug:
            return

        # Health checks are always allowed (for load balancers)
        if request.path in ["/health", "/health_envoy"]:
            return

        # Check if request is from allowed host
        host = request.headers.get("Host", "").split(":")[0]
        if host not in settings.allowed_hosts:
            logger.warning("Request from disallowed host", host=host, path=request.path)
            abort(403, "Access denied: Invalid host")

        # Check if request is from internal network
        client_ip = request.environ.get("HTTP_X_FORWARDED_FOR", request.environ.get("REMOTE_ADDR", ""))
        if client_ip:
            try:
                client_addr = ipaddress.ip_address(client_ip.split(",")[0].strip())
                is_internal = any(
                    client_addr in ipaddress.ip_network(network, strict=False) for network in settings.internal_networks
                )
                if not is_internal:
                    logger.warning("Request from external IP", client_ip=str(client_addr), path=request.path)
                    abort(403, "Access denied: External access not allowed")
            except ValueError:
                logger.warning("Invalid client IP format", client_ip=client_ip)
                abort(400, "Invalid request")

        # Check for internal auth token on non-health endpoints
        if settings.require_internal_auth and settings.internal_auth_token:
            auth_header = request.headers.get("Authorization", "")
            expected_token = f"Bearer {settings.internal_auth_token}"
            if auth_header != expected_token:
                logger.warning("Missing or invalid auth token", path=request.path)
                abort(401, "Authentication required")


def register_routes(app: Flask) -> None:
    """Register all routes with the Flask app."""

    @app.route("/health", methods=["GET"])
    def health() -> Dict[str, Any]:
        """Basic health check endpoint."""
        return jsonify({"status": "healthy", "service": "launchpad", "version": "0.1.0"})

    @app.route("/health_envoy", methods=["GET"])
    def health_envoy() -> Dict[str, Any]:
        """Health check endpoint for Envoy/load balancer."""
        # This is what the devservices config expects
        return jsonify({"status": "healthy", "service": "launchpad"})

    @app.route("/", methods=["GET"])
    def index() -> Dict[str, Any]:
        """Root endpoint."""
        return jsonify(
            {
                "service": "launchpad",
                "description": "Sentry service for preprod artifact analysis",
                "version": "0.1.0",
                "note": "This is an internal Sentry service",
            }
        )

    @app.route("/analyze", methods=["POST"])
    def analyze() -> Dict[str, Any]:
        """Analyze an artifact."""
        from pathlib import Path

        from launchpad.services.analysis import AnalysisService

        # Check if file was uploaded
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "No file selected"}), 400

        try:
            # Save uploaded file temporarily
            settings = get_settings()
            temp_dir = Path(settings.temp_dir)
            temp_dir.mkdir(parents=True, exist_ok=True)

            file_path = temp_dir / file.filename
            file.save(str(file_path))

            # Analyze the file
            analysis_service = AnalysisService()
            result = analysis_service.analyze_artifact(file_path)

            # Clean up temp file
            file_path.unlink(missing_ok=True)

            return jsonify({"status": "success", "result": result.dict()})

        except Exception as e:
            # Clean up temp file on error
            if "file_path" in locals():
                file_path.unlink(missing_ok=True)

            return jsonify({"status": "error", "message": str(e)}), 500
