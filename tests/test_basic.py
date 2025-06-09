"""
Basic tests for the Launchpad service.
"""

import pytest
from flask import Flask

from launchpad.app import create_app
from launchpad.settings import get_settings


def test_create_app():
    """Test that the Flask app can be created."""
    app = create_app()
    assert isinstance(app, Flask)
    assert app.name == "launchpad.app"


def test_settings():
    """Test that settings can be loaded."""
    settings = get_settings()
    assert settings.host == "127.0.0.1"  # Updated for internal service security
    assert settings.port == 1218


def test_health_endpoint(client):
    """Test the health endpoint."""
    response = client.get("/health")
    assert response.status_code == 200

    data = response.get_json()
    assert data["status"] == "healthy"
    assert data["service"] == "launchpad"


def test_health_envoy_endpoint(client):
    """Test the health_envoy endpoint."""
    response = client.get("/health_envoy")
    assert response.status_code == 200

    data = response.get_json()
    assert data["status"] == "healthy"
    assert data["service"] == "launchpad"


def test_index_endpoint(client):
    """Test the index endpoint."""
    response = client.get("/")
    assert response.status_code == 200

    data = response.get_json()
    assert data["service"] == "launchpad"


@pytest.fixture
def client():
    """Create a test client."""
    app = create_app()
    app.config["TESTING"] = True

    with app.test_client() as client:
        yield client
