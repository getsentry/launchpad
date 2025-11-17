"""Integration tests for the Launchpad Kafka service.

These tests verify actual integration between components with minimal mocking.
They test real message processing, service lifecycle, and error handling.

## Test Organization

- **TestKafkaConfigIntegration**: Configuration loading (no Kafka needed)
- **TestKafkaConsumerIntegration**: Real Kafka integration (requires Kafka broker)
- **TestServiceIntegration**: Service setup and health checks (no Kafka needed)
- **TestMessageProcessingFlow**: Message processing logic (mocked processor)

## Running Tests

In CI, Kafka is started via `devservices up` and all tests run.
Locally, you can skip Kafka tests with `SKIP_KAFKA_INTEGRATION_TESTS=1`.

See KAFKA_TEST_IMPROVEMENTS.md for detailed documentation.
"""

from __future__ import annotations

import os
import tempfile
import time

from pathlib import Path
from threading import Thread
from unittest.mock import patch

import pytest

from confluent_kafka import Producer
from sentry_kafka_schemas import get_codec

from launchpad.artifact_processor import ArtifactProcessor
from launchpad.constants import PREPROD_ARTIFACT_EVENTS_TOPIC
from launchpad.kafka import LaunchpadKafkaConsumer, create_kafka_consumer, get_kafka_config
from launchpad.service import LaunchpadService
from launchpad.utils.statsd import FakeStatsd


@pytest.fixture
def kafka_env_vars():
    """Set up Kafka environment variables for testing."""
    env_vars = {
        "KAFKA_BOOTSTRAP_SERVERS": os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
        "KAFKA_GROUP_ID": f"launchpad-test-{int(time.time())}",
        "KAFKA_TOPICS": PREPROD_ARTIFACT_EVENTS_TOPIC,
        "KAFKA_CONCURRENCY": "1",
        "KAFKA_AUTO_OFFSET_RESET": "earliest",
        "LAUNCHPAD_ENV": "development",
        "SENTRY_BASE_URL": "http://test.sentry.io",
    }
    with patch.dict(os.environ, env_vars, clear=False):
        yield env_vars


@pytest.fixture
def kafka_producer(kafka_env_vars):
    """Create a Kafka producer for sending test messages."""
    config = {"bootstrap.servers": kafka_env_vars["KAFKA_BOOTSTRAP_SERVERS"]}
    producer = Producer(config)
    yield producer
    producer.flush()


@pytest.fixture
def temp_healthcheck_file():
    """Create a temporary healthcheck file."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        yield f.name
    try:
        os.unlink(f.name)
    except FileNotFoundError:
        pass


class TestKafkaConfigIntegration:
    """Integration tests for Kafka configuration loading."""

    def test_kafka_config_from_environment(self, kafka_env_vars):
        """Test that Kafka configuration is correctly loaded from environment variables."""
        config = get_kafka_config()

        assert config.bootstrap_servers == kafka_env_vars["KAFKA_BOOTSTRAP_SERVERS"]
        assert config.group_id == kafka_env_vars["KAFKA_GROUP_ID"]
        assert config.topics == [PREPROD_ARTIFACT_EVENTS_TOPIC]
        assert config.concurrency == 1
        assert config.auto_offset_reset == "earliest"

    def test_kafka_config_missing_required_vars(self):
        """Test that missing required environment variables raise errors."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError, match="KAFKA_BOOTSTRAP_SERVERS"):
                create_kafka_consumer()

    def test_kafka_config_with_security_settings(self):
        """Test that security configuration is properly loaded."""
        with patch.dict(
            os.environ,
            {
                "KAFKA_BOOTSTRAP_SERVERS": "localhost:9092",
                "KAFKA_GROUP_ID": "test-group",
                "KAFKA_TOPICS": "test-topic",
                "KAFKA_SECURITY_PROTOCOL": "SASL_SSL",
                "KAFKA_SASL_MECHANISM": "PLAIN",
                "KAFKA_SASL_USERNAME": "test-user",
                "KAFKA_SASL_PASSWORD": "test-pass",
                "LAUNCHPAD_ENV": "development",
            },
        ):
            config = get_kafka_config()
            assert config.security_protocol == "SASL_SSL"
            assert config.sasl_mechanism == "PLAIN"
            assert config.sasl_username == "test-user"
            assert config.sasl_password == "test-pass"


@pytest.mark.integration
@pytest.mark.skipif(
    os.getenv("SKIP_KAFKA_INTEGRATION_TESTS") == "1",
    reason="Kafka integration tests require running Kafka broker (devservices up)",
)
class TestKafkaConsumerIntegration:
    """Integration tests that require a real Kafka broker.

    These tests run by default in CI (which starts Kafka via devservices) and locally
    with devservices running. Set SKIP_KAFKA_INTEGRATION_TESTS=1 to skip them.

    Run with Kafka:
        devservices up
        pytest tests/integration/test_kafka_service.py::TestKafkaConsumerIntegration -v

    Skip (fast mode):
        SKIP_KAFKA_INTEGRATION_TESTS=1 pytest tests/integration/test_kafka_service.py -v
    """

    def test_kafka_consumer_creation(self, kafka_env_vars):
        """Test that Kafka consumer can be created with real configuration."""
        consumer = create_kafka_consumer()

        assert isinstance(consumer, LaunchpadKafkaConsumer)
        assert consumer.processor is not None
        assert consumer.healthcheck_path is not None
        assert consumer.strategy_factory is not None

    def test_kafka_consumer_healthcheck_file_creation(self, kafka_env_vars, temp_healthcheck_file):
        """Test that consumer health check file is managed correctly."""
        with (
            patch.dict(os.environ, {"KAFKA_HEALTHCHECK_FILE": temp_healthcheck_file}),
            patch("launchpad.kafka.configure_metrics"),
        ):
            consumer = create_kafka_consumer()

            old_time = time.time() - 120
            os.utime(temp_healthcheck_file, (old_time, old_time))
            assert not consumer.is_healthy()

            Path(temp_healthcheck_file).touch()
            assert consumer.is_healthy()

    def test_message_processing_with_mock_artifact(self, kafka_env_vars, kafka_producer):
        """Test that messages can be sent to Kafka and processed."""
        schema = get_codec(PREPROD_ARTIFACT_EVENTS_TOPIC)
        test_message = {
            "artifact_id": "test-artifact-123",
            "project_id": "test-project",
            "organization_id": "test-org",
            "requested_features": ["size_analysis"],
        }

        processed_messages = []

        def mock_process_artifact(self, org_id, project_id, artifact_id, features):
            processed_messages.append(
                {"org_id": org_id, "project_id": project_id, "artifact_id": artifact_id, "features": features}
            )

        with (
            patch.object(ArtifactProcessor, "process_artifact", mock_process_artifact),
            patch("launchpad.kafka.configure_metrics"),
        ):
            encoded_message = schema.encode(test_message)
            kafka_producer.produce(
                PREPROD_ARTIFACT_EVENTS_TOPIC,
                value=encoded_message,
                key=test_message["artifact_id"].encode(),
            )
            kafka_producer.flush()

            consumer = create_kafka_consumer()

            def run_consumer():
                try:
                    consumer.run()
                except Exception:
                    pass

            consumer_thread = Thread(target=run_consumer, daemon=True)
            consumer_thread.start()

            max_wait = 10
            start_time = time.time()
            while len(processed_messages) == 0 and (time.time() - start_time) < max_wait:
                time.sleep(0.1)

            consumer.stop()
            consumer_thread.join(timeout=5)

            assert len(processed_messages) == 1
            processed = processed_messages[0]
            assert processed["artifact_id"] == "test-artifact-123"
            assert processed["project_id"] == "test-project"
            assert processed["org_id"] == "test-org"

    def test_kafka_consumer_handles_malformed_message(self, kafka_env_vars, kafka_producer):
        """Test that consumer handles malformed messages gracefully."""
        with patch("launchpad.kafka.configure_metrics"):
            kafka_producer.produce(
                PREPROD_ARTIFACT_EVENTS_TOPIC,
                value=b"this is not valid json",
                key=b"test-key",
            )
            kafka_producer.flush()

            consumer = create_kafka_consumer()

            def run_consumer():
                try:
                    consumer.run()
                except Exception:
                    pass

            consumer_thread = Thread(target=run_consumer, daemon=True)
            consumer_thread.start()

            time.sleep(2)

            consumer.stop()
            consumer_thread.join(timeout=5)

            assert not consumer_thread.is_alive()


@pytest.mark.integration
class TestServiceIntegration:
    """Integration tests for the full service orchestration with minimal mocking."""

    def test_service_setup_with_real_components(self, kafka_env_vars):
        """Test that service setup initializes real components correctly."""
        fake_statsd = FakeStatsd()
        service = LaunchpadService(fake_statsd)

        with (
            patch("launchpad.service.initialize_sentry_sdk"),
            patch("launchpad.kafka.configure_metrics"),
        ):
            service.setup()

            assert service._service_config is not None
            assert service._sentry_client is not None
            assert service.server is not None
            assert service.kafka is not None

            assert hasattr(service.server, "create_app")
            assert hasattr(service.kafka, "run")
            assert hasattr(service.kafka, "is_healthy")

    def test_service_health_check_with_real_components(self, kafka_env_vars, temp_healthcheck_file):
        """Test service health check with real Kafka consumer."""
        fake_statsd = FakeStatsd()
        service = LaunchpadService(fake_statsd)

        with (
            patch("launchpad.service.initialize_sentry_sdk"),
            patch("launchpad.kafka.configure_metrics"),
            patch.dict(os.environ, {"KAFKA_HEALTHCHECK_FILE": temp_healthcheck_file}),
        ):
            service.setup()

            old_time = time.time() - 120
            os.utime(temp_healthcheck_file, (old_time, old_time))
            assert not service.kafka.is_healthy()

            Path(temp_healthcheck_file).touch()
            assert service.kafka.is_healthy()
            assert service.is_healthy()

    def test_service_config_loading(self):
        """Test service configuration loading from environment."""
        from launchpad.service import get_service_config

        with patch.dict("os.environ", {}, clear=True):
            config = get_service_config()
            assert config.sentry_base_url == "http://getsentry.default"
            assert config.projects_to_skip == []

        with patch.dict(
            "os.environ",
            {
                "SENTRY_BASE_URL": "https://custom.sentry.io",
                "PROJECT_IDS_TO_SKIP": "project1,project2,project3",
            },
        ):
            config = get_service_config()
            assert config.sentry_base_url == "https://custom.sentry.io"
            assert config.projects_to_skip == ["project1", "project2", "project3"]

    @pytest.mark.asyncio
    async def test_http_server_endpoints_integration(self, kafka_env_vars, temp_healthcheck_file):
        """Test HTTP server endpoints with real service components."""
        from aiohttp.test_utils import TestClient, TestServer

        fake_statsd = FakeStatsd()
        service = LaunchpadService(fake_statsd)

        with (
            patch("launchpad.service.initialize_sentry_sdk"),
            patch("launchpad.kafka.configure_metrics"),
            patch.dict(os.environ, {"KAFKA_HEALTHCHECK_FILE": temp_healthcheck_file}),
        ):
            service.setup()

            Path(temp_healthcheck_file).touch()

            app = service.server.create_app()
            server = TestServer(app)
            client = TestClient(server)

            await client.start_server()
            try:
                resp = await client.get("/health")
                assert resp.status == 200
                data = await resp.json()
                assert data["service"] == "launchpad"

                resp = await client.get("/ready")
                assert resp.status == 200
                data = await resp.json()
                assert data["service"] == "launchpad"
            finally:
                await client.close()


class TestMessageProcessingFlow:
    """Test the message processing flow with real processing logic."""

    def test_process_message_with_skipped_project(self):
        """Test that projects in skip list are not processed."""
        from launchpad.service import ServiceConfig

        fake_statsd = FakeStatsd()
        service_config = ServiceConfig(
            sentry_base_url="http://test.sentry.io",
            projects_to_skip=["skip-project"],
        )

        test_message = {
            "artifact_id": "test-123",
            "project_id": "skip-project",
            "organization_id": "test-org",
            "requested_features": ["size_analysis"],
        }

        with patch.object(ArtifactProcessor, "process_artifact") as mock_process:
            ArtifactProcessor.process_message(test_message, service_config=service_config, statsd=fake_statsd)
            mock_process.assert_not_called()

    def test_process_message_with_allowed_project(self):
        """Test that non-skipped projects are processed."""
        from launchpad.constants import PreprodFeature
        from launchpad.service import ServiceConfig

        fake_statsd = FakeStatsd()
        service_config = ServiceConfig(
            sentry_base_url="http://test.sentry.io",
            projects_to_skip=["other-project"],
        )

        test_message = {
            "artifact_id": "test-123",
            "project_id": "normal-project",
            "organization_id": "test-org",
            "requested_features": ["size_analysis"],
        }

        with patch.object(ArtifactProcessor, "process_artifact") as mock_process:
            ArtifactProcessor.process_message(test_message, service_config=service_config, statsd=fake_statsd)

            mock_process.assert_called_once_with(
                "test-org",
                "normal-project",
                "test-123",
                [PreprodFeature.SIZE_ANALYSIS],
            )

            calls = fake_statsd.calls
            assert ("increment", {"metric": "artifact.processing.started", "value": 1, "tags": None}) in calls
            assert ("increment", {"metric": "artifact.processing.completed", "value": 1, "tags": None}) in calls

    def test_process_message_error_handling(self):
        """Test that processing errors are handled gracefully."""
        from launchpad.service import ServiceConfig

        fake_statsd = FakeStatsd()
        service_config = ServiceConfig(
            sentry_base_url="http://test.sentry.io",
            projects_to_skip=[],
        )

        test_message = {
            "artifact_id": "test-123",
            "project_id": "test-project",
            "organization_id": "test-org",
            "requested_features": ["size_analysis"],
        }

        with patch.object(ArtifactProcessor, "process_artifact", side_effect=RuntimeError("Test error")):
            ArtifactProcessor.process_message(test_message, service_config=service_config, statsd=fake_statsd)

            calls = fake_statsd.calls
            increment_calls = [call for call in calls if call[0] == "increment"]
            assert any(call[1]["metric"] == "artifact.processing.failed" for call in increment_calls)
