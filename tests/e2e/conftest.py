import os

import pytest


def pytest_configure(config):
    config.addinivalue_line("markers", "slow: marks tests as slow (iOS/AAB analysis takes several minutes)")


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    os.environ.setdefault("LAUNCHPAD_ENV", "e2e-test")
