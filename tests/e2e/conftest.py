"""Conftest for E2E tests - overrides main conftest to avoid importing launchpad."""

import os

import pytest


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Set up test environment variables for E2E tests."""
    os.environ.setdefault("LAUNCHPAD_ENV", "e2e-test")
