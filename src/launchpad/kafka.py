"""Kafka consumer implementation for Launchpad using Arroyo."""

from __future__ import annotations

import asyncio
import os
import time

from typing import Any, Callable, Dict, Mapping

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
from sentry_kafka_schemas.schema_types.preprod_artifact_events_v1 import (
    PreprodArtifactEvents,
)

from launchpad.constants import (
    HEALTHCHECK_MAX_AGE_SECONDS,
    PREPROD_ARTIFACT_EVENTS_TOPIC,
)
from launchpad.utils.arroyo_metrics import DatadogMetricsBackend
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)

# Schema codec for preprod artifact events
PREPROD_ARTIFACT_SCHEMA = get_codec(PREPROD_ARTIFACT_EVENTS_TOPIC)


def create_kafka_consumer(
    message_handler: Callable[[PreprodArtifactEvents], Any],
) -> LaunchpadKafkaConsumer:
    """Create and configure a Kafka consumer using environment variables."""

    healthcheck_path = os.getenv("KAFKA_HEALTHCHECK_FILE")
    if not healthcheck_path:
        healthcheck_path = f"/tmp/launchpad-kafka-health-{os.getpid()}"
        os.environ["KAFKA_HEALTHCHECK_FILE"] = healthcheck_path
        logger.info(f"Using healthcheck file: {healthcheck_path}")

    configure_metrics(DatadogMetricsBackend())
    config = get_kafka_config()

    environment = os.getenv("LAUNCHPAD_ENV")
    if not environment:
        raise ValueError("LAUNCHPAD_ENV environment variable is required")

    # Create Arroyo consumer
    # TODO: When we're closer to production, we'll need a way to disable this logic as
    # topics, partitions and kafka clusters are configured through getsentry/ops.
    # We will work with the streaming teams to get this set up.
    consumer_config = {
        "bootstrap.servers": config["bootstrap_servers"],
        "group.id": config["group_id"],
        "auto.offset.reset": config["auto_offset_reset"],
        "arroyo.strict.offset.reset": config["arroyo_strict_offset_reset"],
        "enable.auto.commit": False,
        "enable.auto.offset.store": False,
        "security.protocol": config["security.protocol"],
    }

    # SASL is used in some prod environments.
    if config["sasl.mechanism"]:
        consumer_config.update(
            {
                "sasl.mechanism": config["sasl.mechanism"],
                "sasl.username": config["sasl.username"],
                "sasl.password": config["sasl.password"],
            }
        )

    arroyo_consumer = ArroyoKafkaConsumer(consumer_config)
    healthcheck_path = config.get("healthcheck_file")

    strategy_factory = LaunchpadStrategyFactory(
        message_handler=message_handler,
        concurrency=config["concurrency"],
        max_pending_futures=config["max_pending_futures"],
        healthcheck_file=healthcheck_path,
    )

    topics = [Topic(topic) for topic in config["topics"]]
    topic = topics[0] if topics else Topic("default")
    processor = StreamProcessor(
        consumer=arroyo_consumer,
        topic=topic,
        processor_factory=strategy_factory,
    )
    return LaunchpadKafkaConsumer(processor, healthcheck_path)


class LaunchpadKafkaConsumer:
    processor: StreamProcessor[KafkaPayload]
    healthcheck_path: str
    _future: asyncio.Future
    _running: bool

    def __init__(self, processor, healthcheck_path):
        self.processor = processor
        self.healthcheck_path = healthcheck_path
        loop = asyncio.get_event_loop()
        self._future = loop.create_future()
        self._future.set_result(None)
        self._running = False

    async def start(self):
        logger.info(f"{self} start commanded")
        loop = asyncio.get_event_loop()
        # run() is blocking so we need to run in another thread:
        self._future = loop.run_in_executor(None, self.run)

    def run(self):
        assert not self._running, "Already running"
        logger.info(f"{self} running")
        try:
            self._running = True
            self.processor.run()
            try:
                os.remove(self.healthcheck_path)
                logger.info(f"Removed healthcheck file: {self.healthcheck_path}")
            except FileNotFoundError:
                pass
        finally:
            self._running = False

    async def stop(self, timeout_s=10):
        logger.info(f"{self} stop commanded")
        self.processor.signal_shutdown()
        try:
            logger.info(f"Waiting for Kafka processor shutdown ({timeout_s}s)...")
            await asyncio.wait_for(self._future, timeout=timeout_s)
            logger.info("...Kafka processor shutdown complete")
        except asyncio.TimeoutError:
            logger.warning(f"{self} did not stop within timeout {timeout_s}s")
            self._future.cancel()

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

    def __init__(
        self,
        message_handler: Callable[[PreprodArtifactEvents], Any],
        concurrency: int = 4,
        max_pending_futures: int = 100,
        healthcheck_file: str | None = None,
    ) -> None:
        self.message_handler = message_handler
        self.concurrency = concurrency
        self.max_pending_futures = max_pending_futures
        self.healthcheck_file = healthcheck_file

    def create_with_partitions(
        self,
        commit: Commit,
        partitions: Mapping[Partition, int],
    ) -> ProcessingStrategy[KafkaPayload]:
        """Create the processing strategy chain."""
        logger.info("KAFKASETUP: Creating processing strategy chain")
        logger.info(f"KAFKASETUP: Partitions: {dict(partitions)}")
        logger.info(f"KAFKASETUP: Commit strategy: {type(commit)}")

        # Start with the commit strategy (always last in chain)
        next_step: ProcessingStrategy[Any] = CommitOffsets(commit)
        logger.info("KAFKASETUP: Base strategy: CommitOffsets")

        logger.info("KAFKASETUP: Checking healthcheck configuration...")
        logger.info(f"KAFKASETUP: Healthcheck file configured: {self.healthcheck_file}")
        logger.info("KAFKASETUP: Adding Healthcheck strategy to processing chain")
        assert self.healthcheck_file
        next_step = Healthcheck(self.healthcheck_file, next_step)
        logger.info("KAFKASETUP: Healthcheck strategy added successfully")

        # Use RunTaskInThreads for concurrent processing
        logger.info("KAFKASETUP: Setting up concurrent message processing")
        logger.info(f"KAFKASETUP: Concurrency level: {self.concurrency}")
        logger.info(f"KAFKASETUP: Max pending futures: {self.max_pending_futures}")

        def process_message(msg: Message[KafkaPayload]) -> Any:
            try:
                decoded = PREPROD_ARTIFACT_SCHEMA.decode(msg.payload.value)
                return self.message_handler(decoded)  # type: ignore[no-any-return]
            except Exception as e:
                logger.error(f"Failed to decode message: {e}")
                raise  # Re-raise the exception to prevent processing invalid messages

        strategy = RunTaskInThreads(
            processing_function=process_message,
            concurrency=self.concurrency,
            max_pending_futures=self.max_pending_futures,
            next_step=next_step,
        )

        logger.info("KAFKASETUP: Processing strategy chain creation complete")
        logger.info(f"KAFKASETUP: Final strategy type: {type(strategy)}")
        return strategy


def get_kafka_config() -> Dict[str, Any]:
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
    return {
        "bootstrap_servers": bootstrap_servers,
        "group_id": group_id,
        "topics": topics_env.split(","),
        "concurrency": int(os.getenv("KAFKA_CONCURRENCY", "4")),
        "max_pending_futures": int(os.getenv("KAFKA_MAX_PENDING_FUTURES", "100")),
        "healthcheck_file": os.getenv("KAFKA_HEALTHCHECK_FILE"),
        "auto_offset_reset": os.getenv("KAFKA_AUTO_OFFSET_RESET", "latest"),  # latest = skip old messages
        "arroyo_strict_offset_reset": arroyo_strict_offset_reset,
        "security.protocol": os.environ.get("KAFKA_SECURITY_PROTOCOL", "plaintext"),
        "sasl.mechanism": os.environ.get("KAFKA_SASL_MECHANISM", None),
        "sasl.username": os.environ.get("KAFKA_SASL_USERNAME", None),
        "sasl.password": os.environ.get("KAFKA_SASL_PASSWORD", None),
    }
