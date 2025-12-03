"""Kafka consumer implementation for Launchpad using Arroyo."""

from __future__ import annotations

import logging
import multiprocessing
import os
import sys

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
from arroyo.processing.strategies.healthcheck import Healthcheck
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


def process_kafka_message_with_service(
    msg: Message[KafkaPayload],
    log_queue: multiprocessing.Queue[Any],
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
    process.join(timeout=timeout)

    if process.is_alive():
        logger.error(
            "Launchpad task killed after exceeding timeout",
            extra={"timeout_seconds": timeout, "artifact_id": artifact_id},
        )
        process.terminate()
        process.join(timeout=5)  # Give it 5s to terminate gracefully
        if process.is_alive():
            logger.warning(
                "Process did not terminate gracefully, force killing",
                extra={"artifact_id": artifact_id},
            )
            process.kill()
            process.join()
        return None  # type: ignore[return-value]

    if process.exitcode != 0:
        logger.error(
            "Process exited with non-zero code",
            extra={"exit_code": process.exitcode, "artifact_id": artifact_id},
        )
        return None  # type: ignore[return-value]

    return decoded  # type: ignore[no-any-return]


def create_kafka_consumer() -> LaunchpadKafkaConsumer:
    """Create and configure a Kafka consumer using environment variables."""

    healthcheck_path = os.getenv("KAFKA_HEALTHCHECK_FILE")
    if not healthcheck_path:
        healthcheck_path = f"/tmp/launchpad-kafka-health-{os.getpid()}"
        os.environ["KAFKA_HEALTHCHECK_FILE"] = healthcheck_path
        logger.info(f"Using healthcheck file: {healthcheck_path}")

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
    healthcheck_path = config.healthcheck_file

    strategy_factory = LaunchpadStrategyFactory(
        concurrency=config.concurrency,
        max_pending_futures=config.max_pending_futures,
        healthcheck_file=healthcheck_path,
    )

    topics = [Topic(topic) for topic in config.topics]
    topic = topics[0] if topics else Topic("default")
    processor = StreamProcessor(
        consumer=arroyo_consumer,
        topic=topic,
        processor_factory=strategy_factory,
        join_timeout=config.join_timeout_seconds,  # Drop in-flight work during rebalance before Kafka times out
    )
    return LaunchpadKafkaConsumer(processor, strategy_factory, healthcheck_path)


class LaunchpadKafkaConsumer:
    processor: StreamProcessor[KafkaPayload]
    strategy_factory: LaunchpadStrategyFactory
    healthcheck_path: str | None
    _running: bool

    def __init__(
        self,
        processor: StreamProcessor[KafkaPayload],
        strategy_factory: LaunchpadStrategyFactory,
        healthcheck_path: str | None,
    ):
        self.processor = processor
        self.strategy_factory = strategy_factory
        self.healthcheck_path = healthcheck_path
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
                os.remove(self.healthcheck_path)
                logger.info(f"Removed healthcheck file: {self.healthcheck_path}")
            except FileNotFoundError:
                pass

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
        healthcheck_file: str | None = None,
    ) -> None:
        self._log_queue: multiprocessing.Queue[Any] = multiprocessing.Queue()
        self._queue_listener = self._setup_queue_listener()
        self._queue_listener.start()

        self.concurrency = concurrency
        self.max_pending_futures = max_pending_futures
        self.healthcheck_file = healthcheck_file

    def _setup_queue_listener(self) -> QueueListener:
        """Set up listener in main process to handle logs from workers."""
        root_logger = logging.getLogger()
        handlers = list(root_logger.handlers) if root_logger.handlers else []

        return QueueListener(self._log_queue, *handlers, respect_handler_level=True)

    def create_with_partitions(
        self,
        commit: Commit,
        partitions: Mapping[Partition, int],
    ) -> ProcessingStrategy[KafkaPayload]:
        """Create the processing strategy chain."""
        next_step: ProcessingStrategy[Any] = CommitOffsets(commit)
        assert self.healthcheck_file
        next_step = Healthcheck(self.healthcheck_file, next_step)

        processing_function = partial(process_kafka_message_with_service, log_queue=self._log_queue)
        strategy = RunTaskInThreads(
            processing_function=processing_function,
            concurrency=self.concurrency,
            max_pending_futures=self.max_pending_futures,
            next_step=next_step,
        )

        return strategy

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
    healthcheck_file: str | None
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
        max_pending_futures=int(os.getenv("KAFKA_MAX_PENDING_FUTURES", "100")),
        healthcheck_file=os.getenv("KAFKA_HEALTHCHECK_FILE"),
        auto_offset_reset=os.getenv("KAFKA_AUTO_OFFSET_RESET", "latest"),  # latest = skip old messages
        arroyo_strict_offset_reset=arroyo_strict_offset_reset,
        security_protocol=os.environ.get("KAFKA_SECURITY_PROTOCOL", "plaintext"),
        sasl_mechanism=os.environ.get("KAFKA_SASL_MECHANISM", None),
        sasl_username=os.environ.get("KAFKA_SASL_USERNAME", None),
        sasl_password=os.environ.get("KAFKA_SASL_PASSWORD", None),
        join_timeout_seconds=float(os.getenv("KAFKA_JOIN_TIMEOUT_SECONDS", "10")),
    )
