from __future__ import annotations

import os

from dataclasses import dataclass

from taskbroker_client.worker import TaskWorker

from launchpad.sentry_sdk_init import initialize_sentry_sdk
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


DEFAULT_HEALTH_CHECK_FILE_PATH = "/tmp/health"


DEFAULT_MAX_CHILD_TASK_COUNT = 1


@dataclass
class WorkerConfig:
    rpc_hosts: list[str]
    concurrency: int
    health_check_file_path: str
    max_child_task_count: int


def get_worker_config() -> WorkerConfig:
    rpc_host = os.getenv("LAUNCHPAD_WORKER_RPC_HOST")
    if not rpc_host:
        raise ValueError("LAUNCHPAD_WORKER_RPC_HOST environment variable is required")

    rpc_hosts = [h.strip() for h in rpc_host.split(",")]

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

    return WorkerConfig(
        rpc_hosts=rpc_hosts,
        concurrency=concurrency,
        health_check_file_path=health_check_file_path,
        max_child_task_count=max_child_task_count,
    )


def run_worker(processing_pool_name: str = "launchpad") -> None:
    initialize_sentry_sdk()
    config = get_worker_config()

    logger.info(
        f"Starting TaskWorker (rpc_hosts={config.rpc_hosts}, concurrency={config.concurrency}, "
        f"max_child_task_count={config.max_child_task_count}, health_check_file_path={config.health_check_file_path})"
    )

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
