#!/usr/bin/env python3
"""Standalone utility to ensure Kafka topics exist for development."""

import os
import sys

from confluent_kafka import KafkaException
from confluent_kafka.admin import AdminClient, NewTopic
from sentry_kafka_schemas import get_topic


def create_kafka_topic(bootstrap_servers: str = "localhost:9092") -> bool:
    """Create the launchpad Kafka topic. Returns True if successful."""
    # Import launchpad constants (needs sys.path modification)
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
    from launchpad.constants import PREPROD_ARTIFACT_EVENTS_TOPIC

    admin_client = AdminClient({"bootstrap.servers": bootstrap_servers})
    topic_name = PREPROD_ARTIFACT_EVENTS_TOPIC

    try:
        # Check if topic already exists
        try:
            existing_topics = admin_client.list_topics(timeout=10).topics
            if topic_name in existing_topics:
                print(f"✓ Topic exists: {topic_name}")
                return True
        except Exception:
            pass  # Continue to create, handle TopicExistsException later

        # Get topic configuration and create
        topic_data = get_topic(topic_name)
        config = topic_data.get("topic_creation_config", {})
        partitions = topic_data.get("enforced_partition_count") or 1
        replication = int(config.get("replication.factor", "1"))

        # Create topic without config to avoid conflicts - config can be set later
        new_topic = NewTopic(topic_name, partitions, replication)
        futures = admin_client.create_topics([new_topic])
        futures[topic_name].result()  # Wait for completion

        print(f"✓ Created topic: {topic_name}")
        return True

    except KafkaException as e:
        if e.args[0].code() == 36:  # TopicExistsException
            print(f"✓ Topic exists: {topic_name}")
            return True
        print(f"✗ Failed to create topic: {e}")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


if __name__ == "__main__":
    if os.getenv("LAUNCHPAD_CREATE_KAFKA_TOPIC") != "1":
        env_val = os.getenv("LAUNCHPAD_CREATE_KAFKA_TOPIC")
        print(f"LAUNCHPAD_CREATE_KAFKA_TOPIC={env_val}")
        print("Topic creation disabled")
        sys.exit(0)

    bootstrap_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS")
    if not bootstrap_servers:
        raise ValueError("KAFKA_BOOTSTRAP_SERVERS env var is required")
    success = create_kafka_topic(bootstrap_servers)
    sys.exit(0 if success else 1)
