import os

import pytest


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    os.environ.setdefault("LAUNCHPAD_ENV", "e2e-test")
