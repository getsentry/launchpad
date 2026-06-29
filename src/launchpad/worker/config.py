from __future__ import annotations

import os

from dataclasses import dataclass

from taskbroker_client.worker import BatchPushTaskWorker, PushTaskWorker, TaskWorker

from launchpad.sentry_sdk_init import initialize_sentry_sdk
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


DEFAULT_HEALTH_CHECK_FILE_PATH = "/tmp/health"


DEFAULT_MAX_CHILD_TASK_COUNT = 1


@dataclass
class WorkerConfig:
    rpc_hosts: list[str]
    rpc_host_service: str
    concurrency: int
    health_check_file_path: str
    max_child_task_count: int
    pod_name: str
    worker_rpc_port: int
    push_mode: bool
    push_timeout_sec: int


def get_worker_config() -> WorkerConfig:
    rpc_host = os.getenv("LAUNCHPAD_WORKER_RPC_HOST")
    rpc_host_service = os.getenv("LAUNCHPAD_WORKER_RPC_HOST_SERVICE", "")
    if not rpc_host and not rpc_host_service:
        raise ValueError(
            "LAUNCHPAD_WORKER_RPC_HOST or LAUNCHPAD_WORKER_RPC_HOST_SERVICE environment variable is required"
        )

    rpc_hosts = [h.strip() for h in rpc_host.split(",")] if rpc_host else []

    concurrency_str = os.getenv("LAUNCHPAD_WORKER_CONCURRENCY")
    if not concurrency_str:
        raise ValueError("LAUNCHPAD_WORKER_CONCURRENCY environment variable is required")

    try:
        concurrency = int(concurrency_str)
    except ValueError:
        raise ValueError(f"LAUNCHPAD_WORKER_CONCURRENCY must be a valid integer, got: {concurrency_str}")

    health_check_file_path = os.getenv("LAUNCHPAD_WORKER_HEALTH_CHECK_FILE_PATH", DEFAULT_HEALTH_CHECK_FILE_PATH)

    max_child_task_count_str = os.getenv("LAUNCHPAD_WORKER_MAX_CHILD_TASK_COUNT", str(DEFAULT_MAX_CHILD_TASK_COUNT))
    try:
        max_child_task_count = int(max_child_task_count_str)
    except ValueError:
        raise ValueError(
            f"LAUNCHPAD_WORKER_MAX_CHILD_TASK_COUNT must be a valid integer, got: {max_child_task_count_str}"
        )

    pod_name = os.getenv("LAUNCHPAD_WORKER_POD_NAME", "")
    try:
        worker_rpc_port = int(os.getenv("LAUNCHPAD_WORKER_RPC_PORT", "50052"))
    except ValueError:
        raise ValueError(
            f"LAUNCHPAD_WORKER_RPC_PORT must be a valid integer, got: {os.getenv('LAUNCHPAD_WORKER_RPC_PORT', '50052')}"
        )
    push_mode = os.getenv("LAUNCHPAD_WORKER_PUSH_MODE", "false") == "true"
    try:
        push_timeout_sec = int(os.getenv("LAUNCHPAD_WORKER_PUSH_TIMEOUT_SEC", "5"))
    except ValueError:
        raise ValueError(
            f"LAUNCHPAD_WORKER_PUSH_TIMEOUT_SEC must be a valid integer, got: {os.getenv('LAUNCHPAD_WORKER_PUSH_TIMEOUT_SEC', '5')}"
        )

    return WorkerConfig(
        rpc_hosts=rpc_hosts,
        rpc_host_service=rpc_host_service,
        concurrency=concurrency,
        health_check_file_path=health_check_file_path,
        max_child_task_count=max_child_task_count,
        pod_name=pod_name,
        worker_rpc_port=worker_rpc_port,
        push_mode=push_mode,
        push_timeout_sec=push_timeout_sec,
    )


def run_worker(
    processing_pool_name: str = "launchpad",
) -> None:
    initialize_sentry_sdk()
    config = get_worker_config()

    logger.info(
        f"Starting TaskWorker (rpc_hosts={config.rpc_hosts}, concurrency={config.concurrency}, "
        f"max_child_task_count={config.max_child_task_count}, health_check_file_path={config.health_check_file_path})"
    )
    if config.push_mode:
        assert config.rpc_host_service, (
            "LAUNCHPAD_WORKER_RPC_HOST_SERVICE environment variable is required when push mode is enabled"
        )
        worker: PushTaskWorker | TaskWorker = BatchPushTaskWorker(
            app_module="launchpad.worker.app:app",
            broker_service=config.rpc_host_service,
            max_child_task_count=config.max_child_task_count,
            concurrency=config.concurrency,
            child_tasks_queue_maxsize=1,
            result_queue_maxsize=1,
            rebalance_after=16,
            processing_pool_name=processing_pool_name,
            process_type="forkserver",
            health_check_file_path=config.health_check_file_path,
            pod_name=config.pod_name,
            worker_rpc_port=config.worker_rpc_port,
            update_in_batches=True,
            push_task_timeout=config.push_timeout_sec,
        )
    else:
        assert config.rpc_hosts, "LAUNCHPAD_WORKER_RPC_HOST environment variable is required when push mode is disabled"
        worker = TaskWorker(
            app_module="launchpad.worker.app:app",
            broker_hosts=config.rpc_hosts,
            max_child_task_count=config.max_child_task_count,
            concurrency=config.concurrency,
            child_tasks_queue_maxsize=1,
            result_queue_maxsize=1,
            rebalance_after=16,
            processing_pool_name=processing_pool_name,
            process_type="forkserver",
            health_check_file_path=config.health_check_file_path,
        )

    exitcode = worker.start()
    raise SystemExit(exitcode)
