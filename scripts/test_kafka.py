#!/usr/bin/env python3
"""Script to send test messages to Kafka for testing Launchpad consumer."""

import json
import sys
import time
from typing import Any, Dict

import click
from kafka import KafkaProducer

sys.path.insert(0, "src")
from launchpad.constants import PREPROD_ARTIFACT_EVENTS_TOPIC  # noqa: E402


def create_producer(bootstrap_servers: str = "localhost:9092") -> KafkaProducer:
    """Create a Kafka producer."""
    return KafkaProducer(
        bootstrap_servers=[bootstrap_servers],
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        key_serializer=lambda k: k.encode("utf-8") if k else None,
    )


def create_preprod_artifact_event(
    artifact_id: str | None = None, project_id: str | None = None, organization_id: str | None = None
) -> Dict[str, Any]:
    """Create a preprod artifact event message matching the schema."""
    return {
        "artifact_id": artifact_id or f"test-artifact-{int(time.time())}",
        "project_id": project_id or f"test-project-{int(time.time())}",
        "organization_id": organization_id or f"test-org-{int(time.time())}",
    }


@click.command()
@click.option("--topic", default=PREPROD_ARTIFACT_EVENTS_TOPIC, help="Kafka topic to send messages to")
@click.option("--bootstrap-servers", default="localhost:9092", help="Kafka bootstrap servers")
@click.option("--artifact-id", help="Custom artifact ID (auto-generated if not provided)")
@click.option("--project-id", help="Custom project ID (auto-generated if not provided)")
@click.option("--organization-id", help="Custom organization ID (auto-generated if not provided)")
@click.option("--custom-json", help="Custom JSON message to send (overrides other options)")
@click.option("--count", default=1, help="Number of messages to send")
@click.option("--interval", default=1.0, help="Interval between messages in seconds")
def main(
    topic: str,
    bootstrap_servers: str,
    artifact_id: str,
    project_id: str,
    organization_id: str,
    custom_json: str,
    count: int,
    interval: float,
) -> None:
    """Send preprod artifact event messages to Kafka for Launchpad testing."""

    try:
        producer = create_producer(bootstrap_servers)
        click.echo(f"Connected to Kafka at {bootstrap_servers}")

        for i in range(count):
            if custom_json:
                try:
                    message = json.loads(custom_json)
                except json.JSONDecodeError as e:
                    click.echo(f"Error parsing custom JSON: {e}", err=True)
                    sys.exit(1)
            else:
                # Use provided IDs or generate them with counter
                current_artifact_id = artifact_id or f"test-artifact-{int(time.time())}-{i+1}"
                current_project_id = project_id or f"test-project-{int(time.time())}-{i+1}"
                current_organization_id = organization_id or f"test-org-{int(time.time())}-{i+1}"

                message = create_preprod_artifact_event(
                    artifact_id=current_artifact_id,
                    project_id=current_project_id,
                    organization_id=current_organization_id,
                )

            # Send message
            key = f"test-{i+1}"
            future = producer.send(topic, value=message, key=key)

            # Wait for the message to be sent
            record_metadata = future.get(timeout=10)

            click.echo(
                f"Message {i+1}/{count} sent to {record_metadata.topic}:"
                f"{record_metadata.partition}:{record_metadata.offset}"
            )
            click.echo(f"  Key: {key}")
            click.echo(f"  Message: {json.dumps(message, indent=2)}")

            if i < count - 1:
                time.sleep(interval)

        producer.close()
        click.echo(f"Successfully sent {count} message(s) to topic '{topic}'")

    except Exception as e:
        click.echo(f"Error sending messages: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
