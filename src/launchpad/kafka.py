"""Kafka consumer implementation for Launchpad using Arroyo."""

from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

import sentry_kafka_schemas
from arroyo import Message, Topic
from arroyo.backends.kafka import KafkaConsumer as ArroyoKafkaConsumer
from arroyo.backends.kafka import KafkaPayload
from arroyo.processing.processor import StreamProcessor
from arroyo.processing.strategies import ProcessingStrategy, ProcessingStrategyFactory
from arroyo.types import BrokerValue, Commit, Partition
from confluent_kafka import KafkaError, KafkaException
from confluent_kafka.admin import AdminClient, NewTopic

from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


def ensure_topics_exist_dev_only(
    bootstrap_servers: str,
    topic_names: Sequence[str],
    num_partitions: int = 1,
    replication_factor: int = 1,
    timeout_s: float = 10.0,
) -> None:
    """
    Ensure that the specified Kafka topics exist, creating them if they don't.

    Args:
        bootstrap_servers: Kafka bootstrap servers
        topic_names: List of topic names to ensure exist
        num_partitions: Number of partitions for new topics
        replication_factor: Replication factor for new topics
        timeout_s: Timeout for topic creation operations
    """
    if not _is_local_development_environment():
        logger.info("Skipping topic creation - not in development environment")
        return

    if not topic_names:
        return

    logger.info(f"[DEV ONLY] Ensuring Kafka topics exist: {list(topic_names)}")

    admin_client = AdminClient({"bootstrap.servers": bootstrap_servers})

    # Check which topics already exist
    metadata = admin_client.list_topics(timeout=timeout_s)
    existing_topics = set(metadata.topics.keys())

    topics_to_create = []
    for topic_name in topic_names:
        if topic_name not in existing_topics:
            logger.info(f"[DEV ONLY] Topic '{topic_name}' does not exist, will create it")

            # Use schema-defined config if available, otherwise use defaults
            topic_config = get_topic_creation_config() if topic_name == get_topic_name() else {}
            default_config = {
                "cleanup.policy": "delete",
                "retention.ms": str(7 * 24 * 60 * 60 * 1000),  # 7 days
            }
            # Schema config takes precedence over defaults
            final_config = {**default_config, **topic_config}

            topics_to_create.append(
                NewTopic(
                    topic_name,
                    num_partitions=num_partitions,
                    replication_factor=replication_factor,
                    config=final_config,
                )
            )
        else:
            logger.debug(f"[DEV ONLY] Topic '{topic_name}' already exists")

    if not topics_to_create:
        logger.info("[DEV ONLY] All required topics already exist")
        return

    # Create the topics
    logger.info(f"[DEV ONLY] Creating {len(topics_to_create)} topic(s)...")
    future_map = admin_client.create_topics(topics_to_create, operation_timeout=timeout_s)

    for topic_name, future in future_map.items():
        try:
            future.result()  # Block until topic is created
            logger.info(f"[DEV ONLY] Successfully created topic '{topic_name}'")
        except KafkaException as e:
            if e.args[0].code() == KafkaError.TOPIC_ALREADY_EXISTS:
                logger.info(f"[DEV ONLY] Topic '{topic_name}' already exists (created by another process)")
            else:
                logger.error(f"[DEV ONLY] Failed to create topic '{topic_name}': {e}")
                raise


def _is_local_development_environment() -> bool:
    """
    Check if we're running in the local development environment where topic creation is allowed.

    Returns:
        True if in development environment, False otherwise
    """
    # Check for explicit development flag
    if os.getenv("LAUNCHPAD_DEV_ENVIRONMENT", "false").lower() == "true":
        return True

    return False


def get_topic_name() -> str:
    """
    Get the canonical topic name for preprod artifact events.

    Returns:
        The topic name as defined in sentry_kafka_schemas
    """
    # Use the topic name from the schema registry (following Snuba's pattern)
    return "preprod-artifact-events"


def get_topic_creation_config() -> Dict[str, str]:
    """
    Get topic creation configuration from schema registry.

    Returns:
        Topic creation config dict, or empty dict if not found
    """
    topic_name = get_topic_name()
    try:
        topic_info = sentry_kafka_schemas.get_topic(topic_name)
        return topic_info.get("topic_creation_config", {})
    except sentry_kafka_schemas.SchemaNotFound:
        logger.warning(f"Topic '{topic_name}' not found in schema registry")
        return {}


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

    def get_json_payload(self) -> Dict[str, Any]:
        """Parse the message value as JSON."""
        try:
            result: Dict[str, Any] = json.loads(self.value.decode("utf-8"))
            return result
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.error(f"Failed to parse message as JSON: {e}")
            return {}

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
                payload = launchpad_msg.get_json_payload()
                logger.info(f"Message payload: {payload}")

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
        # Ensure required topics exist before starting consumer (development only)
        try:
            ensure_topics_exist_dev_only(
                bootstrap_servers=self.bootstrap_servers,
                topic_names=self.topics,
                num_partitions=1,
                replication_factor=1,
            )
        except Exception as e:
            logger.error(f"Failed to ensure topics exist: {e}")
            raise

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
