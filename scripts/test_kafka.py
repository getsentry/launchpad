#!/usr/bin/env python3
"""Script to send test messages to Kafka for testing Launchpad consumer."""

import json
import sys
import time
from typing import Any, Dict

import click
from kafka import KafkaProducer


def create_producer(bootstrap_servers: str = "localhost:9092") -> KafkaProducer:
    """Create a Kafka producer."""
    return KafkaProducer(
        bootstrap_servers=[bootstrap_servers],
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        key_serializer=lambda k: k.encode("utf-8") if k else None,
    )


def create_apple_analysis_message(artifact_path: str) -> Dict[str, Any]:
    """Create an Apple analysis message."""
    return {
        "type": "analyze_apple",
        "artifact_path": artifact_path,
        "timestamp": time.time(),
        "request_id": f"ios-{int(time.time())}",
    }


def create_android_analysis_message(artifact_path: str) -> Dict[str, Any]:
    """Create an Android analysis message."""
    return {
        "type": "analyze_android",
        "artifact_path": artifact_path,
        "timestamp": time.time(),
        "request_id": f"android-{int(time.time())}",
    }


@click.command()
@click.option("--topic", default="launchpad-events", help="Kafka topic to send messages to")
@click.option("--bootstrap-servers", default="localhost:9092", help="Kafka bootstrap servers")
@click.option(
    "--message-type", type=click.Choice(["ios", "android", "custom"]), default="ios", help="Type of message to send"
)
@click.option("--artifact-path", default="/path/to/test.xcarchive.zip", help="Path to artifact for analysis")
@click.option("--custom-json", help="Custom JSON message to send (overrides other options)")
@click.option("--count", default=1, help="Number of messages to send")
@click.option("--interval", default=1.0, help="Interval between messages in seconds")
def main(
    topic: str,
    bootstrap_servers: str,
    message_type: str,
    artifact_path: str,
    custom_json: str,
    count: int,
    interval: float,
) -> None:
    """Send test messages to Kafka for Launchpad testing."""

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
            elif message_type == "ios":
                message = create_apple_analysis_message(artifact_path)
            elif message_type == "android":
                message = create_android_analysis_message(artifact_path)
            else:
                click.echo(f"Unknown message type: {message_type}", err=True)
                sys.exit(1)

            # Send message
            key = f"{message_type}-{i+1}"
            future = producer.send(topic, value=message, key=key)

            # Wait for the message to be sent
            record_metadata = future.get(timeout=10)

            click.echo(
                f"Message {i+1}/{count} sent to {record_metadata.topic}:{record_metadata.partition}:{record_metadata.offset}"
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
