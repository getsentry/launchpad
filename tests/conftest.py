import os

import pytest


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Set up test environment variables for all tests."""
    os.environ.setdefault("LAUNCHPAD_ENV", "TEST")
