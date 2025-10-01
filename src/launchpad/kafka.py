"""Kafka consumer implementation for Launchpad using Arroyo."""

from __future__ import annotations

import multiprocessing
import os
import signal
import time

from dataclasses import dataclass
from functools import partial
from multiprocessing.pool import Pool
from typing import Any, Callable, Mapping

from arroyo import Message, Topic, configure_metrics
from arroyo.backends.kafka import KafkaConsumer as ArroyoKafkaConsumer
from arroyo.backends.kafka import KafkaPayload
from arroyo.processing.processor import StreamProcessor
from arroyo.processing.strategies import ProcessingStrategy, ProcessingStrategyFactory
from arroyo.processing.strategies.commit import CommitOffsets
from arroyo.processing.strategies.healthcheck import Healthcheck
from arroyo.processing.strategies.run_task_with_multiprocessing import (
    MultiprocessingPool,
    RunTaskWithMultiprocessing,
    parallel_worker_initializer,
)
from arroyo.types import Commit, FilteredPayload, Partition, TStrategyPayload
from sentry_kafka_schemas import get_codec

from launchpad.artifact_processor import ArtifactProcessor
from launchpad.constants import HEALTHCHECK_MAX_AGE_SECONDS, PREPROD_ARTIFACT_EVENTS_TOPIC
from launchpad.server import get_server_config
from launchpad.utils.arroyo_metrics import DatadogMetricsBackend
from launchpad.utils.logging import get_logger, setup_logging

logger = get_logger(__name__)

# Schema codec for preprod artifact events
PREPROD_ARTIFACT_SCHEMA = get_codec(PREPROD_ARTIFACT_EVENTS_TOPIC)


class LaunchpadMultiProcessingPool(MultiprocessingPool):
    """Extended MultiprocessingPool with maxtasksperchild=1 to ensure clean worker state."""

    def maybe_create_pool(self) -> None:
        if self._MultiprocessingPool__pool is None:
            self._MultiprocessingPool__metrics.increment("arroyo.strategies.run_task_with_multiprocessing.pool.create")
            self._MultiprocessingPool__pool = Pool(
                self._MultiprocessingPool__num_processes,
                initializer=partial(parallel_worker_initializer, self._MultiprocessingPool__initializer),
                context=multiprocessing.get_context("spawn"),
                maxtasksperchild=1,  # why we have this subclass
            )


class LaunchpadRunTaskWithMultiprocessing(RunTaskWithMultiprocessing[TStrategyPayload, Any]):
    """Tolerates child process exits from maxtasksperchild=1 by ignoring SIGCHLD."""

    def __init__(
        self,
        function: Callable[[Message[TStrategyPayload]], Any],
        next_step: ProcessingStrategy[FilteredPayload | Any],
        max_batch_size: int,
        max_batch_time: float,
        pool: MultiprocessingPool,
        input_block_size: int | None = None,
        output_block_size: int | None = None,
    ) -> None:
        super().__init__(function, next_step, max_batch_size, max_batch_time, pool, input_block_size, output_block_size)
        # Override SIGCHLD handler - child exits are expected with maxtasksperchild=1
        signal.signal(
            signal.SIGCHLD,
            lambda signum, frame: logger.debug(f"Worker process exited normally (SIGCHLD {signum})"),
        )


def process_kafka_message_with_service(msg: Message[KafkaPayload]) -> Any:
    """Process a Kafka message using the actual service logic in a worker process."""
    try:
        decoded = PREPROD_ARTIFACT_SCHEMA.decode(msg.payload.value)
        ArtifactProcessor.process_message(decoded)
        return decoded  # type: ignore[no-any-return]
    except Exception as e:
        logger.error(f"Failed to process message in worker: {e}", exc_info=True)
        raise


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
    )
    return LaunchpadKafkaConsumer(processor, healthcheck_path, strategy_factory)


class LaunchpadKafkaConsumer:
    processor: StreamProcessor[KafkaPayload]
    healthcheck_path: str | None
    strategy_factory: LaunchpadStrategyFactory
    _running: bool

    def __init__(
        self,
        processor: StreamProcessor[KafkaPayload],
        healthcheck_path: str | None,
        strategy_factory: LaunchpadStrategyFactory,
    ):
        self.processor = processor
        self.healthcheck_path = healthcheck_path
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
                os.remove(self.healthcheck_path)
                logger.info(f"Removed healthcheck file: {self.healthcheck_path}")
            except FileNotFoundError:
                pass

            # Clean up multiprocessing pool
            try:
                self.strategy_factory.close()
                logger.debug("Closed multiprocessing pool")
            except Exception:
                logger.exception("Error closing multiprocessing pool")

    def stop(self):
        """Signal shutdown to the processor."""
        logger.info(f"{self} stop commanded")
        self.processor.signal_shutdown()

        # Kill all multiprocessing worker children (development only)
        environment = os.getenv("LAUNCHPAD_ENV", "development").lower()
        if environment == "development":
            for child in multiprocessing.active_children():
                child.terminate()

    def is_healthy(self) -> bool:
        try:
            mtime = os.path.getmtime(self.healthcheck_path)
            age = time.time() - mtime
        except OSError:
            return False
        else:
            return age <= HEALTHCHECK_MAX_AGE_SECONDS


class LaunchpadStrategyFactory(ProcessingStrategyFactory[KafkaPayload]):
    """Factory for creating the processing strategy chain."""

    @staticmethod
    def _initialize_worker_logging() -> None:
        """Initialize logging in worker process."""
        server_config = get_server_config()
        setup_logging(verbose=server_config.debug, quiet=not server_config.debug)

    def __init__(
        self,
        concurrency: int,
        max_pending_futures: int,
        healthcheck_file: str | None = None,
    ) -> None:
        self._pool = LaunchpadMultiProcessingPool(
            num_processes=concurrency,
            initializer=self._initialize_worker_logging,
        )
        self.concurrency = concurrency
        self.max_pending_futures = max_pending_futures
        self.healthcheck_file = healthcheck_file

    def create_with_partitions(
        self,
        commit: Commit,
        partitions: Mapping[Partition, int],
    ) -> ProcessingStrategy[KafkaPayload]:
        """Create the processing strategy chain."""
        next_step: ProcessingStrategy[Any] = CommitOffsets(commit)
        assert self.healthcheck_file
        next_step = Healthcheck(self.healthcheck_file, next_step)

        strategy = LaunchpadRunTaskWithMultiprocessing(
            process_kafka_message_with_service,
            next_step=next_step,
            max_batch_size=1,  # Process immediately, subject to be re-tuned
            max_batch_time=1,  # Process after 1 second max, subject to be re-tuned
            pool=self._pool,
            input_block_size=None,
            output_block_size=None,
        )

        return strategy

    def close(self) -> None:
        """Clean up the multiprocessing pool."""
        self._pool.close()


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
        concurrency=int(os.getenv("KAFKA_CONCURRENCY", "2")),
        max_pending_futures=int(os.getenv("KAFKA_MAX_PENDING_FUTURES", "100")),
        healthcheck_file=os.getenv("KAFKA_HEALTHCHECK_FILE"),
        auto_offset_reset=os.getenv("KAFKA_AUTO_OFFSET_RESET", "latest"),  # latest = skip old messages
        arroyo_strict_offset_reset=arroyo_strict_offset_reset,
        security_protocol=os.environ.get("KAFKA_SECURITY_PROTOCOL", "plaintext"),
        sasl_mechanism=os.environ.get("KAFKA_SASL_MECHANISM", None),
        sasl_username=os.environ.get("KAFKA_SASL_USERNAME", None),
        sasl_password=os.environ.get("KAFKA_SASL_PASSWORD", None),
    )
