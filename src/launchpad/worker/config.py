from __future__ import annotations

import os

from dataclasses import dataclass

from taskbroker_client.worker import TaskWorker

from launchpad.sentry_sdk_init import initialize_sentry_sdk
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class WorkerConfig:
    rpc_host: str
    concurrency: int


def get_worker_config() -> WorkerConfig:
    rpc_host = os.getenv("LAUNCHPAD_WORKER_RPC_HOST")
    if not rpc_host:
        raise ValueError("LAUNCHPAD_WORKER_RPC_HOST environment variable is required")

    concurrency_str = os.getenv("LAUNCHPAD_WORKER_CONCURRENCY")
    if not concurrency_str:
        raise ValueError("LAUNCHPAD_WORKER_CONCURRENCY environment variable is required")

    try:
        concurrency = int(concurrency_str)
    except ValueError:
        raise ValueError(f"LAUNCHPAD_WORKER_CONCURRENCY must be a valid integer, got: {concurrency_str}")

    return WorkerConfig(rpc_host=rpc_host, concurrency=concurrency)


def run_worker() -> None:
    initialize_sentry_sdk()
    config = get_worker_config()

    logger.info(f"Starting TaskWorker (rpc_host={config.rpc_host}, concurrency={config.concurrency})")

    worker = TaskWorker(
        app_module="launchpad.worker.app:app",
        broker_hosts=[config.rpc_host],
        max_child_task_count=100,
        concurrency=config.concurrency,
        child_tasks_queue_maxsize=config.concurrency * 2,
        result_queue_maxsize=config.concurrency * 2,
        rebalance_after=32,
        processing_pool_name="launchpad",
        process_type="forkserver",
    )

    exitcode = worker.start()
    raise SystemExit(exitcode)
