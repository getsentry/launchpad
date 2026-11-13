import os

from unittest.mock import patch

import pytest

from launchpad.worker.config import (
    DEFAULT_HEALTH_CHECK_FILE_PATH,
    DEFAULT_MAX_CHILD_TASK_COUNT,
    WorkerConfig,
    get_worker_config,
    run_worker,
)


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
                rpc_host_service="",
                concurrency=8,
                health_check_file_path=DEFAULT_HEALTH_CHECK_FILE_PATH,
                max_child_task_count=DEFAULT_MAX_CHILD_TASK_COUNT,
                pod_name="",
                push_mode=False,
                push_timeout_sec=5,
                wait_for_child_exit=False,
                prometheus_port=None,
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

    def test_custom_max_child_task_count(self):
        with patch.dict(
            os.environ,
            {
                "LAUNCHPAD_WORKER_RPC_HOST": "localhost:50051",
                "LAUNCHPAD_WORKER_CONCURRENCY": "8",
                "LAUNCHPAD_WORKER_MAX_CHILD_TASK_COUNT": "500",
            },
        ):
            config = get_worker_config()
            assert config.max_child_task_count == 500

    def test_invalid_max_child_task_count(self):
        with patch.dict(
            os.environ,
            {
                "LAUNCHPAD_WORKER_RPC_HOST": "localhost:50051",
                "LAUNCHPAD_WORKER_CONCURRENCY": "8",
                "LAUNCHPAD_WORKER_MAX_CHILD_TASK_COUNT": "not-a-number",
            },
        ):
            with pytest.raises(ValueError, match="LAUNCHPAD_WORKER_MAX_CHILD_TASK_COUNT must be a valid integer"):
                get_worker_config()

    def test_rpc_host_service(self):
        with patch.dict(
            os.environ,
            {
                "LAUNCHPAD_WORKER_RPC_HOST_SERVICE": "localhost:50051",
                "LAUNCHPAD_WORKER_CONCURRENCY": "8",
            },
        ):
            config = get_worker_config()
            assert config.rpc_host_service == "localhost:50051"

    def test_wait_for_child_exit_enabled(self):
        with patch.dict(
            os.environ,
            {
                "LAUNCHPAD_WORKER_RPC_HOST": "localhost:50051",
                "LAUNCHPAD_WORKER_CONCURRENCY": "2",
                "LAUNCHPAD_WORKER_WAIT_FOR_CHILD_EXIT": "true",
            },
            clear=True,
        ):
            config = get_worker_config()
            assert config.wait_for_child_exit is True

    def test_prometheus_port(self):
        with patch.dict(
            os.environ,
            {
                "LAUNCHPAD_WORKER_RPC_HOST_SERVICE": "localhost:50051",
                "LAUNCHPAD_WORKER_CONCURRENCY": "2",
                "LAUNCHPAD_WORKER_PROMETHEUS_PORT": "9100",
            },
            clear=True,
        ):
            config = get_worker_config()
            assert config.prometheus_port == 9100

    def test_invalid_prometheus_port(self):
        with patch.dict(
            os.environ,
            {
                "LAUNCHPAD_WORKER_RPC_HOST_SERVICE": "localhost:50051",
                "LAUNCHPAD_WORKER_CONCURRENCY": "2",
                "LAUNCHPAD_WORKER_PROMETHEUS_PORT": "not-a-port",
            },
            clear=True,
        ):
            with pytest.raises(ValueError, match="LAUNCHPAD_WORKER_PROMETHEUS_PORT must be a valid integer"):
                get_worker_config()


class TestRunWorker:
    @pytest.fixture(autouse=True)
    def _skip_bootup(self):
        with (
            patch("launchpad.worker.config.initialize_sentry_sdk"),
            patch("launchpad.worker.config.init_options"),
        ):
            yield

    def test_push_mode_passes_prometheus_port(self):
        env = {
            "LAUNCHPAD_WORKER_RPC_HOST_SERVICE": "task-launchpad-push-broker-grpc:50051",
            "LAUNCHPAD_WORKER_CONCURRENCY": "2",
            "LAUNCHPAD_WORKER_PUSH_MODE": "true",
            "LAUNCHPAD_WORKER_PROMETHEUS_PORT": "9100",
        }
        with (
            patch.dict(os.environ, env, clear=True),
            patch("launchpad.worker.config.PushTaskWorker") as push_worker,
        ):
            push_worker.return_value.start.return_value = 0
            with pytest.raises(SystemExit):
                run_worker(processing_pool_name="launchpad-push")

        kwargs = push_worker.call_args.kwargs
        assert kwargs["prometheus_port"] == 9100
        assert kwargs["processing_pool_name"] == "launchpad-push"

    def test_push_mode_prometheus_disabled_by_default(self):
        env = {
            "LAUNCHPAD_WORKER_RPC_HOST_SERVICE": "task-launchpad-push-broker-grpc:50051",
            "LAUNCHPAD_WORKER_CONCURRENCY": "2",
            "LAUNCHPAD_WORKER_PUSH_MODE": "true",
        }
        with (
            patch.dict(os.environ, env, clear=True),
            patch("launchpad.worker.config.PushTaskWorker") as push_worker,
        ):
            push_worker.return_value.start.return_value = 0
            with pytest.raises(SystemExit):
                run_worker()

        assert push_worker.call_args.kwargs["prometheus_port"] is None

    def test_pull_mode_ignores_prometheus_port(self):
        env = {
            "LAUNCHPAD_WORKER_RPC_HOST": "task-launchpad-broker-grpc-0:50051",
            "LAUNCHPAD_WORKER_CONCURRENCY": "2",
            "LAUNCHPAD_WORKER_PROMETHEUS_PORT": "9100",
        }
        with (
            patch.dict(os.environ, env, clear=True),
            patch("launchpad.worker.config.TaskWorker") as pull_worker,
        ):
            pull_worker.return_value.start.return_value = 0
            with pytest.raises(SystemExit):
                run_worker()

        assert "prometheus_port" not in pull_worker.call_args.kwargs
