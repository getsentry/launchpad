from __future__ import annotations

import os
import time

from unittest.mock import patch

import pytest

from aiohttp.test_utils import TestClient, TestServer

from launchpad.artifact_processor import ArtifactProcessor
from launchpad.constants import PREPROD_ARTIFACT_EVENTS_TOPIC
from launchpad.kafka import LaunchpadKafkaConsumer, create_kafka_consumer, get_kafka_config
from launchpad.service import LaunchpadService, ServiceConfig, get_service_config
from launchpad.utils.statsd import FakeStatsd


@pytest.fixture
def kafka_env_vars():
    env_vars = {
        "KAFKA_BOOTSTRAP_SERVERS": os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
        "KAFKA_GROUP_ID": f"launchpad-test-{int(time.time())}",
        "KAFKA_TOPICS": PREPROD_ARTIFACT_EVENTS_TOPIC,
        "KAFKA_AUTO_OFFSET_RESET": "earliest",
        "LAUNCHPAD_ENV": "development",
        "SENTRY_BASE_URL": "http://test.sentry.io",
    }
    with patch.dict(os.environ, env_vars, clear=False):
        yield env_vars


class TestKafkaConfigIntegration:
    """Integration tests for Kafka configuration loading."""

    def test_kafka_config_from_environment(self, kafka_env_vars):
        """Test that Kafka configuration is correctly loaded from environment variables."""
        config = get_kafka_config()

        assert config.bootstrap_servers == kafka_env_vars["KAFKA_BOOTSTRAP_SERVERS"]
        assert config.group_id == kafka_env_vars["KAFKA_GROUP_ID"]
        assert config.topics == [PREPROD_ARTIFACT_EVENTS_TOPIC]
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


@pytest.mark.integration
class TestServiceIntegration:
    def test_service_setup(self, kafka_env_vars):
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

    def test_service_config_loading(self):
        """Test service configuration loading from environment."""

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
    async def test_http_server_endpoints_integration(self, kafka_env_vars):
        """Test HTTP server endpoints with real service components."""

        fake_statsd = FakeStatsd()
        service = LaunchpadService(fake_statsd)

        with (
            patch("launchpad.service.initialize_sentry_sdk"),
            patch("launchpad.kafka.configure_metrics"),
        ):
            service.setup()

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

        fake_statsd = FakeStatsd()
        service_config = ServiceConfig(
            sentry_base_url="http://test.sentry.io",
            projects_to_skip=["skip-project"],
            objectstore_url="http://test.objectstore.io",
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

        fake_statsd = FakeStatsd()
        service_config = ServiceConfig(
            sentry_base_url="http://test.sentry.io",
            projects_to_skip=["other-project"],
            objectstore_url="http://test.objectstore.io",
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
            )

            calls = fake_statsd.calls
            assert ("increment", {"metric": "artifact.processing.started", "value": 1, "tags": None}) in calls
            assert ("increment", {"metric": "artifact.processing.completed", "value": 1, "tags": None}) in calls

    def test_process_message_error_handling(self):
        """Test that processing errors are handled gracefully."""

        fake_statsd = FakeStatsd()
        service_config = ServiceConfig(
            sentry_base_url="http://test.sentry.io",
            projects_to_skip=[],
            objectstore_url="http://test.objectstore.io",
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
