"""Tests for Kafka message processing timeout functionality."""

import logging
import multiprocessing
import os
import time

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from launchpad.kafka import process_kafka_message_with_service


def slow_processor(decoded_message: Any) -> None:
    """Mock processor that takes a long time."""
    time.sleep(10)


@pytest.fixture
def log_queue():
    """Create a log queue for testing."""
    manager = multiprocessing.Manager()
    return manager.Queue(-1)


@pytest.fixture
def mock_kafka_message():
    """Create a mock Kafka message."""
    message = MagicMock()
    message.payload.value = (
        b'{"artifact_id":"test-timeout","project_id":"test-proj","organization_id":"test-org","requested_features":[]}'
    )
    return message


def test_process_timeout_kills_subprocess(mock_kafka_message, log_queue, caplog):
    """Test that subprocess is killed when it exceeds the timeout."""
    # Set a timeout shorter than the sleep time
    with patch.dict(os.environ, {"KAFKA_TASK_TIMEOUT_SECONDS": "1"}):
        with patch("launchpad.kafka.ArtifactProcessor.process_message", side_effect=slow_processor):
            with caplog.at_level(logging.ERROR):
                result = process_kafka_message_with_service(mock_kafka_message, log_queue)

    assert result is None

    timeout_logs = [record for record in caplog.records if "Task exceeded timeout" in record.message]
    assert len(timeout_logs) == 1
    assert "killing process" in timeout_logs[0].message
