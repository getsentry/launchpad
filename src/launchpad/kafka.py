"""Kafka consumer implementation for Launchpad using Arroyo."""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any, Callable, Dict, List, Mapping, Optional

from arroyo import Message, Topic
from arroyo.backends.kafka import KafkaConsumer as ArroyoKafkaConsumer
from arroyo.backends.kafka import KafkaPayload
from arroyo.processing.processor import StreamProcessor
from arroyo.processing.strategies import ProcessingStrategy, ProcessingStrategyFactory
from arroyo.types import BrokerValue, Commit, Partition
from sentry_kafka_schemas import get_codec
from sentry_kafka_schemas.codecs import ValidationError
from sentry_kafka_schemas.schema_types.preprod_artifact_events_v1 import PreprodArtifactEvents

from launchpad.constants import PREPROD_ARTIFACT_EVENTS_TOPIC
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)

# Schema codec for preprod artifact events
PREPROD_ARTIFACT_SCHEMA = get_codec(PREPROD_ARTIFACT_EVENTS_TOPIC)


def get_topic_name() -> str:
    """
    Get the canonical topic name for preprod artifact events.

    Returns:
        The topic name as defined in sentry_kafka_schemas
    """
    # Use the topic name from the schema registry (following Snuba's pattern)
    return PREPROD_ARTIFACT_EVENTS_TOPIC


class LaunchpadMessage:
    """Represents a processed Kafka message for Launchpad."""

    def __init__(
        self,
        topic: str,
        partition: int,
        offset: int,
        key: bytes | None,
        value: bytes,
        timestamp: float | None = None,
    ) -> None:
        self.topic = topic
        self.partition = partition
        self.offset = offset
        self.key = key
        self.value = value
        self.timestamp = timestamp

    def get_validated_payload(self) -> PreprodArtifactEvents | None:
        """Parse and validate the message using the schema."""
        try:
            decoded = PREPROD_ARTIFACT_SCHEMA.decode(self.value)
            return decoded
        except ValidationError as e:
            logger.error(f"Schema validation failed for message: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to decode message: {e}")
            return None

    def is_valid_preprod_artifact_event(self) -> bool:
        """Check if this message is a valid preprod artifact event."""
        return self.get_validated_payload() is not None

    def __str__(self) -> str:
        return f"LaunchpadMessage(topic={self.topic}, partition={self.partition}, offset={self.offset})"


class MessageProcessingStrategy(ProcessingStrategy[KafkaPayload]):
    """Strategy to process Kafka messages."""

    def __init__(self, message_handler: Callable[[LaunchpadMessage], Any] | None = None) -> None:
        self.message_handler = message_handler

    def poll(self) -> None:
        pass

    def submit(self, message: Message[KafkaPayload]) -> None:
        """Process a single message."""
        try:
            # Convert Arroyo message to Launchpad message
            kafka_payload = message.payload

            # Assume we're getting BrokerValue from Kafka consumer
            broker_value = message.value
            if isinstance(broker_value, BrokerValue):
                launchpad_msg = LaunchpadMessage(
                    topic=broker_value.partition.topic.name,
                    partition=broker_value.partition.index,
                    offset=broker_value.offset,
                    key=kafka_payload.key,
                    value=kafka_payload.value,
                    timestamp=broker_value.timestamp.timestamp() if broker_value.timestamp else None,
                )
            else:
                logger.error(f"Expected BrokerValue but got {type(broker_value)}")
                return

            logger.debug(f"Processing message: {launchpad_msg}")

            if self.message_handler:
                try:
                    result = self.message_handler(launchpad_msg)
                    # Note: In synchronous context, we can't handle async handlers
                    # The handler should be synchronous or handle its own async scheduling
                    if asyncio.iscoroutine(result):
                        logger.warning("Message handler returned a coroutine but we're in sync context - ignoring")
                except Exception as e:
                    logger.error(f"Error in message handler: {e}", exc_info=True)
            else:
                logger.info(f"No handler set, received message: {launchpad_msg}")
                if launchpad_msg.is_valid_preprod_artifact_event():
                    payload = launchpad_msg.get_validated_payload()
                    logger.info(f"Valid preprod artifact event: {payload}")
                else:
                    logger.warning(f"Invalid or malformed message received on topic {launchpad_msg.topic}")

        except Exception as e:
            logger.error(f"Error processing message: {e}", exc_info=True)

    def close(self) -> None:
        pass

    def terminate(self) -> None:
        pass

    def join(self, timeout: float | None = None) -> None:
        pass


class MessageProcessingStrategyFactory(ProcessingStrategyFactory[KafkaPayload]):
    """Factory for creating message processing strategies."""

    def __init__(self, message_handler: Optional[Callable[[LaunchpadMessage], Any]] = None) -> None:
        self.message_handler = message_handler

    def create_with_partitions(
        self,
        commit: Commit,
        partitions: Mapping[Partition, int],
    ) -> ProcessingStrategy[KafkaPayload]:
        """Create a processing strategy with partition information."""
        # Use the message processing strategy directly
        return MessageProcessingStrategy(self.message_handler)


class KafkaConsumer:
    """Arroyo-based Kafka consumer for Launchpad."""

    def __init__(
        self,
        topics: List[str],
        group_id: str,
        bootstrap_servers: str | None = None,
        message_handler: Optional[Callable[[LaunchpadMessage], Any]] = None,
    ) -> None:
        self.topics = topics
        self.group_id = group_id
        # Ensure bootstrap_servers is always a string
        self.bootstrap_servers: str = bootstrap_servers or os.getenv(
            "KAFKA_BOOTSTRAP_SERVERS"
        )  # type: ignore[assignment]
        if not self.bootstrap_servers:
            raise ValueError("KAFKA_BOOTSTRAP_SERVERS environment variable must be set")
        self.message_handler = message_handler
        self._processor: StreamProcessor[KafkaPayload] | None = None
        self._shutdown_requested = False

        logger.info(f"Initialized Arroyo Kafka consumer for topics: {topics}")
        logger.info(f"Group ID: {group_id}")
        logger.info(f"Bootstrap servers: {self.bootstrap_servers}")

    def run(self) -> None:
        """Run the Kafka consumer (blocking, like Snuba)."""
        while not self._shutdown_requested:
            try:
                # Create Arroyo consumer - minimal config for Arroyo
                # TODO: When we're closer to production, we'll need a way to disable this logic as
                # topics, partitions and kafka clusters are configured through getsentry/ops.
                # We will work with the streaming teams to get this set up.
                consumer_config = {
                    "bootstrap.servers": self.bootstrap_servers,
                    "group.id": self.group_id,
                    "auto.offset.reset": "latest",
                    "enable.auto.commit": False,  # Arroyo manages commits via strategies
                    "enable.auto.offset.store": False,  # Arroyo manages offset storage
                }

                # Create topics list for Arroyo
                arroyo_topics = [Topic(topic) for topic in self.topics]

                arroyo_consumer = ArroyoKafkaConsumer(consumer_config)

                # Create processing strategy factory
                strategy_factory = MessageProcessingStrategyFactory(self.message_handler)

                # Create stream processor
                self._processor = StreamProcessor(
                    consumer=arroyo_consumer,
                    topic=arroyo_topics[0] if arroyo_topics else Topic("default"),
                    processor_factory=strategy_factory,
                )

                logger.info("Arroyo Kafka consumer started, calling processor.run()...")

                # This blocks until shutdown is signaled (exactly like Snuba)
                self._processor.run()

                logger.info("Processor.run() completed")
                break

            except Exception as e:
                if not self._shutdown_requested:
                    logger.error(f"Error in Kafka consumer: {e}", exc_info=True)
                    # Sleep a bit before retrying (like Snuba)
                    time.sleep(1.0)
                else:
                    # This else branch is theoretically unreachable due to loop condition
                    logger.info(  # type: ignore[unreachable]
                        "Kafka consumer shutting down due to error during shutdown"
                    )
                    break

        logger.info("Kafka consumer run loop completed")

    def shutdown(self) -> None:
        """Signal shutdown to the Kafka consumer."""
        logger.info("Shutdown requested for Kafka consumer")
        self._shutdown_requested = True

        if self._processor:
            try:
                logger.info("Calling signal_shutdown on processor")
                self._processor.signal_shutdown()
            except Exception as e:
                logger.warning(f"Error signaling processor shutdown: {e}")

    def set_message_handler(self, handler: Callable[[LaunchpadMessage], Any]) -> None:
        """Set the message handler function."""
        self.message_handler = handler
        # If processor is already created, we'd need to recreate it
        # For now, this should be called before start()
        if self._shutdown_requested:
            logger.warning("Cannot change message handler while consumer is running")

    async def health_check(self) -> Dict[str, Any]:
        """Check the health of the Kafka connection."""
        return {
            "status": "running" if not self._shutdown_requested else "stopped",
            "topics": self.topics,
            "group_id": self.group_id,
            "bootstrap_servers": self.bootstrap_servers,
            "processor_active": self._processor is not None,
        }


def get_kafka_config() -> Dict[str, Any]:
    """Get Kafka configuration from environment."""

    # Use the canonical topic name from schema by default
    default_topic = get_topic_name()

    return {
        "bootstrap_servers": os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
        "group_id": os.getenv("KAFKA_GROUP_ID", "launchpad-consumer"),
        "topics": os.getenv("KAFKA_TOPICS", default_topic).split(","),
    }
