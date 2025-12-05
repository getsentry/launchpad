"""Kafka consumer implementation for Launchpad using Arroyo."""

from __future__ import annotations

import logging
import multiprocessing
import os
import sys
import threading

from dataclasses import dataclass
from functools import partial
from logging.handlers import QueueHandler, QueueListener
from typing import Any, Mapping

from arroyo import Message, Topic, configure_metrics
from arroyo.backends.kafka import KafkaConsumer as ArroyoKafkaConsumer
from arroyo.backends.kafka import KafkaPayload
from arroyo.processing.processor import StreamProcessor
from arroyo.processing.strategies import ProcessingStrategy, ProcessingStrategyFactory
from arroyo.processing.strategies.commit import CommitOffsets
from arroyo.processing.strategies.run_task_in_threads import RunTaskInThreads
from arroyo.types import Commit, Partition
from sentry_kafka_schemas import get_codec

from launchpad.artifact_processor import ArtifactProcessor
from launchpad.constants import PREPROD_ARTIFACT_EVENTS_TOPIC
from launchpad.tracing import RequestLogFilter
from launchpad.utils.arroyo_metrics import DatadogMetricsBackend
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)

# Schema codec for preprod artifact events
PREPROD_ARTIFACT_SCHEMA = get_codec(PREPROD_ARTIFACT_EVENTS_TOPIC)


def _process_in_subprocess(decoded_message: Any, log_queue: multiprocessing.Queue[Any]) -> None:
    """Worker function that runs in subprocess."""
    root_logger = logging.getLogger()
    root_logger.handlers.clear()

    queue_handler = QueueHandler(log_queue)
    queue_handler.addFilter(RequestLogFilter())

    root_logger.addHandler(queue_handler)
    root_logger.setLevel(logging.DEBUG)

    try:
        ArtifactProcessor.process_message(decoded_message)
    except Exception:
        logger.exception("Error processing message in subprocess")
        sys.exit(1)


def _kill_process(process: multiprocessing.Process, artifact_id: str) -> None:
    """Gracefully terminate, then force kill a subprocess."""
    process.terminate()
    process.join(timeout=5)
    if process.is_alive():
        logger.warning(
            "Process did not terminate gracefully, force killing",
            extra={"artifact_id": artifact_id, "pid": process.pid},
        )
        process.kill()
        process.join(timeout=1)  # Brief timeout to reap zombie, avoid infinite block
        if process.is_alive():
            logger.error(
                "Process could not be killed, may become zombie",
                extra={"artifact_id": artifact_id, "pid": process.pid},
            )


def process_kafka_message_with_service(
    msg: Message[KafkaPayload],
    log_queue: multiprocessing.Queue[Any],
    process_registry: dict[int, tuple[multiprocessing.Process, str]],
    registry_lock: threading.Lock,
    factory: LaunchpadStrategyFactory,
) -> Any:
    """Process a Kafka message by spawning a fresh subprocess with timeout protection."""
    timeout = int(os.getenv("KAFKA_TASK_TIMEOUT_SECONDS", "720"))  # 12 minutes default

    try:
        decoded = PREPROD_ARTIFACT_SCHEMA.decode(msg.payload.value)
    except Exception:
        logger.exception("Failed to decode message")
        raise

    artifact_id = decoded.get("artifact_id", "unknown")

    # Spawn actual processing in a subprocess
    process = multiprocessing.Process(target=_process_in_subprocess, args=(decoded, log_queue))
    process.start()

    # Register the process for tracking (PID is always set after start())
    with registry_lock:
        process_registry[process.pid] = (process, artifact_id)  # type: ignore[index]

    try:
        process.join(timeout=timeout)

        # Check if killed during rebalance
        pid = process.pid
        if pid is not None:
            with registry_lock:
                was_killed_by_rebalance = pid in factory._killed_during_rebalance
                if was_killed_by_rebalance:
                    factory._killed_during_rebalance.discard(pid)

            if was_killed_by_rebalance:
                # Wait for kill to complete, then don't commit offset
                process.join(timeout=10)  # Give kill_active_processes time to finish
                logger.warning(
                    "Process killed during rebalance, message will be reprocessed",
                    extra={"artifact_id": artifact_id},
                )
                raise TimeoutError("Subprocess killed during rebalance")

        # Handle timeout (process still alive after full timeout)
        if process.is_alive():
            logger.error(
                "Launchpad task killed after exceeding timeout",
                extra={"timeout_seconds": timeout, "artifact_id": artifact_id},
            )
            _kill_process(process, artifact_id)
            return None  # type: ignore[return-value]

        if process.exitcode != 0:
            logger.error(
                "Process exited with non-zero code",
                extra={"exit_code": process.exitcode, "artifact_id": artifact_id},
            )
            return None  # type: ignore[return-value]

        return decoded  # type: ignore[no-any-return]
    finally:
        with registry_lock:
            process_registry.pop(process.pid, None)


def create_kafka_consumer() -> LaunchpadKafkaConsumer:
    """Create and configure a Kafka consumer using environment variables."""
    config = get_kafka_config()
    configure_metrics(DatadogMetricsBackend(config.group_id))

    environment = os.getenv("LAUNCHPAD_ENV")
    if not environment:
        raise ValueError("LAUNCHPAD_ENV environment variable is required")

    consumer_config = {
        "bootstrap.servers": config.bootstrap_servers,
        "group.id": config.group_id,
        "auto.offset.reset": config.auto_offset_reset,
        "arroyo.strict.offset.reset": config.arroyo_strict_offset_reset,
        "enable.auto.commit": False,
        "enable.auto.offset.store": False,
        "security.protocol": config.security_protocol,
    }

    # SASL is used in some prod environments.
    if config.sasl_mechanism:
        consumer_config.update(
            {
                "sasl.mechanism": config.sasl_mechanism,
                "sasl.username": config.sasl_username,
                "sasl.password": config.sasl_password,
            }
        )

    arroyo_consumer = ArroyoKafkaConsumer(consumer_config)

    strategy_factory = LaunchpadStrategyFactory(
        concurrency=config.concurrency,
        max_pending_futures=config.max_pending_futures,
    )

    topics = [Topic(topic) for topic in config.topics]
    topic = topics[0] if topics else Topic("default")
    processor = StreamProcessor(
        consumer=arroyo_consumer,
        topic=topic,
        processor_factory=strategy_factory,
        join_timeout=config.join_timeout_seconds,  # Drop in-flight work during rebalance before Kafka times out
    )
    return LaunchpadKafkaConsumer(processor, strategy_factory)


# This wrapper is required to ensure that the active subprocesses are killed during rebalances due to the nature of run_task_in_threads.
class ShutdownAwareStrategy(ProcessingStrategy[KafkaPayload]):
    """Wrapper that kills active subprocesses during rebalance."""

    def __init__(self, inner: ProcessingStrategy[KafkaPayload], factory: LaunchpadStrategyFactory):
        self._inner = inner
        self._factory = factory

    def submit(self, message: Message[KafkaPayload]) -> None:
        self._inner.submit(message)

    def poll(self) -> None:
        self._inner.poll()

    def close(self) -> None:
        # Kill all active subprocesses BEFORE closing inner strategy
        self._factory.kill_active_processes()
        self._inner.close()

    def terminate(self) -> None:
        self._factory.kill_active_processes()
        self._inner.terminate()

    def join(self, timeout: float | None = None) -> None:
        self._inner.join(timeout)


class LaunchpadKafkaConsumer:
    processor: StreamProcessor[KafkaPayload]
    strategy_factory: LaunchpadStrategyFactory
    _running: bool

    def __init__(
        self,
        processor: StreamProcessor[KafkaPayload],
        strategy_factory: LaunchpadStrategyFactory,
    ):
        self.processor = processor
        self.strategy_factory = strategy_factory
        self._running = False

    def run(self):
        assert not self._running, "Already running"
        logger.info(f"{self} running")
        self._running = True

        try:
            self.processor.run()
        finally:
            self._running = False
            try:
                self.strategy_factory.close()
            except Exception:
                logger.exception("Error closing strategy factory")

    def stop(self):
        """Signal shutdown to the processor."""
        logger.info(f"{self} stop commanded")
        self.processor.signal_shutdown()

    def is_healthy(self) -> bool:
        return True


class LaunchpadStrategyFactory(ProcessingStrategyFactory[KafkaPayload]):
    """Factory for creating the processing strategy chain."""

    def __init__(
        self,
        concurrency: int,
        max_pending_futures: int,
    ) -> None:
        self._log_queue: multiprocessing.Queue[Any] = multiprocessing.Queue()
        self._queue_listener = self._setup_queue_listener()
        self._queue_listener.start()

        self._active_processes: dict[int, tuple[multiprocessing.Process, str]] = {}
        self._processes_lock = threading.Lock()
        self._killed_during_rebalance: set[int] = set()

        self.concurrency = concurrency
        self.max_pending_futures = max_pending_futures

    def _setup_queue_listener(self) -> QueueListener:
        """Set up listener in main process to handle logs from workers."""
        root_logger = logging.getLogger()
        handlers = list(root_logger.handlers) if root_logger.handlers else []

        return QueueListener(self._log_queue, *handlers, respect_handler_level=True)

    def kill_active_processes(self) -> None:
        """Kill all active subprocesses. Called during rebalancing."""
        with self._processes_lock:
            if self._active_processes:
                logger.info(
                    "Killing %d active subprocess(es) during rebalance",
                    len(self._active_processes),
                )
                for pid, (process, artifact_id) in list(self._active_processes.items()):
                    if process.is_alive():
                        self._killed_during_rebalance.add(pid)
                        logger.info("Terminating subprocess with PID %d", pid)
                        _kill_process(process, artifact_id)
                self._active_processes.clear()

    def create_with_partitions(
        self,
        commit: Commit,
        partitions: Mapping[Partition, int],
    ) -> ProcessingStrategy[KafkaPayload]:
        """Create the processing strategy chain."""
        next_step: ProcessingStrategy[Any] = CommitOffsets(commit)

        processing_function = partial(
            process_kafka_message_with_service,
            log_queue=self._log_queue,
            process_registry=self._active_processes,
            registry_lock=self._processes_lock,
            factory=self,
        )
        inner_strategy = RunTaskInThreads(
            processing_function=processing_function,
            concurrency=self.concurrency,
            max_pending_futures=self.max_pending_futures,
            next_step=next_step,
        )

        return ShutdownAwareStrategy(inner_strategy, self)

    def close(self) -> None:
        """Clean up the logging queue and listener."""
        try:
            self._queue_listener.stop()
            logger.debug("Closed queue listener")
        except Exception:
            logger.exception("Error stopping queue listener")


@dataclass
class KafkaConfig:
    """Kafka configuration data."""

    bootstrap_servers: str
    group_id: str
    topics: list[str]
    concurrency: int
    max_pending_futures: int
    auto_offset_reset: str
    arroyo_strict_offset_reset: bool | None
    security_protocol: str
    sasl_mechanism: str | None
    sasl_username: str | None
    sasl_password: str | None
    join_timeout_seconds: float


def get_kafka_config() -> KafkaConfig:
    """Get Kafka configuration from environment variables."""
    # Required configuration
    bootstrap_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS")
    if not bootstrap_servers:
        raise ValueError("KAFKA_BOOTSTRAP_SERVERS env var is required")

    group_id = os.getenv("KAFKA_GROUP_ID")
    if not group_id:
        raise ValueError("KAFKA_GROUP_ID env var is required")

    topics_env = os.getenv("KAFKA_TOPICS")
    if not topics_env:
        raise ValueError("KAFKA_TOPICS env var is required")

    # Parse arroyo_strict_offset_reset as boolean, default to None if invalid
    arroyo_strict_offset_reset = {"true": True, "false": False}.get(os.getenv("ARROYO_STRICT_OFFSET_RESET", "").lower())

    # Optional configuration with defaults
    return KafkaConfig(
        bootstrap_servers=bootstrap_servers,
        group_id=group_id,
        topics=topics_env.split(","),
        concurrency=int(os.getenv("KAFKA_CONCURRENCY", "1")),
        max_pending_futures=int(os.getenv("KAFKA_MAX_PENDING_FUTURES", "0")),
        auto_offset_reset=os.getenv("KAFKA_AUTO_OFFSET_RESET", "latest"),  # latest = skip old messages
        arroyo_strict_offset_reset=arroyo_strict_offset_reset,
        security_protocol=os.environ.get("KAFKA_SECURITY_PROTOCOL", "plaintext"),
        sasl_mechanism=os.environ.get("KAFKA_SASL_MECHANISM", None),
        sasl_username=os.environ.get("KAFKA_SASL_USERNAME", None),
        sasl_password=os.environ.get("KAFKA_SASL_PASSWORD", None),
        join_timeout_seconds=float(os.getenv("KAFKA_JOIN_TIMEOUT_SECONDS", "10")),
    )
