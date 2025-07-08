"""Kafka consumer implementation for Launchpad using Arroyo."""

from __future__ import annotations

import os

from typing import Any, Callable, Dict, Mapping

from arroyo import Message, Topic
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

from launchpad.constants import PREPROD_ARTIFACT_EVENTS_TOPIC
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)

# Schema codec for preprod artifact events
PREPROD_ARTIFACT_SCHEMA = get_codec(PREPROD_ARTIFACT_EVENTS_TOPIC)


def create_kafka_consumer(
    message_handler: Callable[[PreprodArtifactEvents], Any],
) -> StreamProcessor[KafkaPayload]:
    """Create and configure a Kafka consumer using environment variables."""
    # Get configuration from environment
    config = get_kafka_config()

    # Create Arroyo consumer
    # TODO: When we're closer to production, we'll need a way to disable this logic as
    # topics, partitions and kafka clusters are configured through getsentry/ops.
    # We will work with the streaming teams to get this set up.
    consumer_config = {
        "bootstrap.servers": config["bootstrap_servers"],
        "group.id": config["group_id"],
        "auto.offset.reset": config["auto_offset_reset"],
        "enable.auto.commit": False,
        "enable.auto.offset.store": False,
    }

    arroyo_consumer = ArroyoKafkaConsumer(consumer_config)

    # Create strategy factory
    strategy_factory = LaunchpadStrategyFactory(
        message_handler=message_handler,
        concurrency=config["concurrency"],
        max_pending_futures=config["max_pending_futures"],
        healthcheck_file=config.get("healthcheck_file"),
    )

    # Create and return stream processor
    topics = [Topic(topic) for topic in config["topics"]]
    topic = topics[0] if topics else Topic("default")
    return StreamProcessor(
        consumer=arroyo_consumer,
        topic=topic,
        processor_factory=strategy_factory,
    )


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
        # Start with the commit strategy (always last in chain)
        next_step: ProcessingStrategy[Any] = CommitOffsets(commit)

        # Add healthcheck if configured
        if self.healthcheck_file:
            next_step = Healthcheck(self.healthcheck_file, next_step)

        # Use RunTaskInThreads for concurrent processing
        def process_message(msg: Message[KafkaPayload]) -> Any:
            try:
                decoded = PREPROD_ARTIFACT_SCHEMA.decode(msg.payload.value)
                return self.message_handler(decoded)  # type: ignore[no-any-return]
            except Exception as e:
                logger.error(f"Failed to decode message: {e}")
                raise  # Re-raise the exception to prevent processing invalid messages

        return RunTaskInThreads(
            processing_function=process_message,
            concurrency=self.concurrency,
            max_pending_futures=self.max_pending_futures,
            next_step=next_step,
        )


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

    # Optional configuration with defaults
    return {
        "bootstrap_servers": bootstrap_servers,
        "group_id": group_id,
        "topics": topics_env.split(","),
        "concurrency": int(os.getenv("KAFKA_CONCURRENCY", "4")),
        "max_pending_futures": int(os.getenv("KAFKA_MAX_PENDING_FUTURES", "100")),
        "healthcheck_file": os.getenv("KAFKA_HEALTHCHECK_FILE"),
        "auto_offset_reset": os.getenv(
            "KAFKA_AUTO_OFFSET_RESET", "latest"
        ),  # latest = skip old messages
    }
