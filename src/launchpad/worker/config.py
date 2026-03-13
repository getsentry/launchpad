from __future__ import annotations

import os

from dataclasses import dataclass

from taskbroker_client.worker import TaskWorker

from launchpad.sentry_sdk_init import initialize_sentry_sdk
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class WorkerConfig:
    rpc_hosts: list[str]
    concurrency: int


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

    return WorkerConfig(rpc_hosts=rpc_hosts, concurrency=concurrency)


def run_worker() -> None:
    initialize_sentry_sdk()
    config = get_worker_config()

    logger.info(f"Starting TaskWorker (rpc_hosts={config.rpc_hosts}, concurrency={config.concurrency})")

    # TODO: Should we explore setting health_check_file_path for K8s file-based liveness probes (TaskWorker has no HTTP server)
    worker = TaskWorker(
        app_module="launchpad.worker.app:app",
        broker_hosts=config.rpc_hosts,
        max_child_task_count=1000,
        concurrency=config.concurrency,
        child_tasks_queue_maxsize=config.concurrency * 2,
        result_queue_maxsize=config.concurrency * 2,
        rebalance_after=16,
        processing_pool_name="launchpad",
        process_type="forkserver",
    )

    exitcode = worker.start()
    raise SystemExit(exitcode)
