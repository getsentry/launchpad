import os

from unittest.mock import patch

import pytest

from launchpad.worker.config import DEFAULT_HEALTH_CHECK_FILE_PATH, WorkerConfig, get_worker_config


class TestGetWorkerConfig:
    def test_valid_config(self):
        with patch.dict(
            os.environ,
            {
                "LAUNCHPAD_WORKER_RPC_HOST": "localhost:50051",
                "LAUNCHPAD_WORKER_CONCURRENCY": "8",
            },
        ):
            config = get_worker_config()
            assert config == WorkerConfig(
                rpc_hosts=["localhost:50051"],
                concurrency=8,
                health_check_file_path=DEFAULT_HEALTH_CHECK_FILE_PATH,
            )

    def test_custom_health_check_file_path(self):
        with patch.dict(
            os.environ,
            {
                "LAUNCHPAD_WORKER_RPC_HOST": "localhost:50051",
                "LAUNCHPAD_WORKER_CONCURRENCY": "8",
                "LAUNCHPAD_WORKER_HEALTH_CHECK_FILE_PATH": "/custom/health",
            },
        ):
            config = get_worker_config()
            assert config.health_check_file_path == "/custom/health"

    def test_comma_separated_hosts(self):
        with patch.dict(
            os.environ,
            {
                "LAUNCHPAD_WORKER_RPC_HOST": "host1:50051, host2:50051, host3:50051",
                "LAUNCHPAD_WORKER_CONCURRENCY": "4",
            },
        ):
            config = get_worker_config()
            assert config.rpc_hosts == ["host1:50051", "host2:50051", "host3:50051"]

    def test_missing_rpc_host(self):
        with patch.dict(os.environ, {"LAUNCHPAD_WORKER_CONCURRENCY": "8"}, clear=True):
            with pytest.raises(ValueError, match="LAUNCHPAD_WORKER_RPC_HOST"):
                get_worker_config()

    def test_missing_concurrency(self):
        with patch.dict(os.environ, {"LAUNCHPAD_WORKER_RPC_HOST": "localhost:50051"}, clear=True):
            with pytest.raises(ValueError, match="LAUNCHPAD_WORKER_CONCURRENCY"):
                get_worker_config()

    def test_invalid_concurrency(self):
        with patch.dict(
            os.environ,
            {
                "LAUNCHPAD_WORKER_RPC_HOST": "localhost:50051",
                "LAUNCHPAD_WORKER_CONCURRENCY": "not-a-number",
            },
        ):
            with pytest.raises(ValueError, match="must be a valid integer"):
                get_worker_config()
