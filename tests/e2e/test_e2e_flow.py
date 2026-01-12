"""End-to-end tests for Launchpad service.

Tests the full flow:
1. Upload test artifact to mock API
2. Send Kafka message to trigger processing
3. Wait for Launchpad to process
4. Verify results via mock API
"""

import json
import os
import time

from datetime import datetime
from pathlib import Path
from typing import Any, Dict

import pytest
import requests

from confluent_kafka import Producer

# Configuration from environment
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9093")
MOCK_API_URL = os.getenv("MOCK_API_URL", "http://mock-sentry-api:8000")
LAUNCHPAD_URL = os.getenv("LAUNCHPAD_URL", "http://launchpad:2218")
KAFKA_TOPIC = "preprod-artifact-events"

# Test fixtures
FIXTURES_DIR = Path("/app/fixtures")
IOS_FIXTURE = FIXTURES_DIR / "ios" / "HackerNews.xcarchive.zip"
ANDROID_APK_FIXTURE = FIXTURES_DIR / "android" / "hn.apk"
ANDROID_AAB_FIXTURE = FIXTURES_DIR / "android" / "hn.aab"


def wait_for_service(url: str, timeout: int = 60, service_name: str = "service") -> None:
    """Wait for a service to be healthy."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            response = requests.get(f"{url}/health", timeout=5)
            if response.status_code == 200:
                print(f"✓ {service_name} is healthy")
                return
        except requests.exceptions.RequestException:
            pass
        time.sleep(2)
    raise TimeoutError(f"{service_name} did not become healthy within {timeout}s")


def upload_artifact_to_mock_api(artifact_id: str, file_path: Path) -> None:
    """Upload an artifact file to the mock API."""
    with open(file_path, "rb") as f:
        files = {"file": (file_path.name, f, "application/zip")}
        response = requests.post(f"{MOCK_API_URL}/test/upload-artifact/{artifact_id}", files=files, timeout=30)
        response.raise_for_status()
        print(f"✓ Uploaded artifact {artifact_id} ({file_path.name})")


def send_kafka_message(artifact_id: str, org: str, project: str, features: list[str]) -> None:
    """Send a Kafka message to trigger artifact processing."""
    producer = Producer({"bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS, "client.id": "e2e-test-producer"})

    message = {
        "artifact_id": artifact_id,
        "organization_id": org,
        "project_id": project,
        "requested_features": features,
    }

    producer.produce(KAFKA_TOPIC, key=artifact_id.encode("utf-8"), value=json.dumps(message).encode("utf-8"))
    producer.flush(timeout=10)
    print(f"✓ Sent Kafka message for artifact {artifact_id}")


def wait_for_processing(artifact_id: str, timeout: int = 120, check_interval: int = 3) -> Dict[str, Any]:
    """Wait for artifact processing to complete and return results."""
    start_time = time.time()
    last_status = None

    while time.time() - start_time < timeout:
        try:
            response = requests.get(f"{MOCK_API_URL}/test/results/{artifact_id}", timeout=10)
            response.raise_for_status()
            results = response.json()

            # Check if processing is complete
            # Processing is complete when both metadata is updated AND size analysis file exists
            if results.get("artifact_metadata") and results.get("has_size_analysis_file"):
                print(f"✓ Processing completed for {artifact_id}")
                return results

            # Show progress
            current_status = json.dumps(results, sort_keys=True)
            if current_status != last_status:
                print(f"  Waiting for processing... (results so far: {results})")
                last_status = current_status

        except requests.exceptions.RequestException as e:
            print(f"  Error checking results: {e}")

        time.sleep(check_interval)

    raise TimeoutError(f"Artifact {artifact_id} was not processed within {timeout}s")


def get_size_analysis_raw(artifact_id: str) -> Dict[str, Any]:
    """Get the raw size analysis JSON for an artifact."""
    response = requests.get(f"{MOCK_API_URL}/test/results/{artifact_id}/size-analysis-raw", timeout=10)
    response.raise_for_status()
    return response.json()


class TestE2EFlow:
    """End-to-end tests for full Launchpad service flow."""

    @classmethod
    def setup_class(cls):
        """Wait for all services to be ready before running tests."""
        print("\n=== Waiting for services to be ready ===")
        wait_for_service(MOCK_API_URL, service_name="Mock Sentry API")
        wait_for_service(LAUNCHPAD_URL, service_name="Launchpad")
        print("=== All services ready ===\n")

    def test_ios_xcarchive_full_flow(self):
        """Test full flow with iOS .xcarchive.zip file."""
        if not IOS_FIXTURE.exists():
            pytest.skip(f"iOS fixture not found: {IOS_FIXTURE}")

        artifact_id = "test-ios-001"
        org = "test-org"
        project = "test-ios-project"

        print("\n=== Testing iOS .xcarchive.zip E2E flow ===")

        # Step 1: Upload artifact to mock API
        upload_artifact_to_mock_api(artifact_id, IOS_FIXTURE)

        # Step 2: Send Kafka message
        send_kafka_message(artifact_id, org, project, ["size_analysis"])

        # Step 3: Wait for processing
        results = wait_for_processing(artifact_id, timeout=180)

        # Step 4: Verify results
        print("\n=== Verifying results ===")

        # Check artifact metadata was updated
        assert results["artifact_metadata"], "Artifact metadata should be updated"
        metadata = results["artifact_metadata"]

        # Verify iOS-specific metadata fields (API contract)
        # These are the fields Sentry expects from Launchpad for iOS apps
        ios_required_fields = [
            "app_name",
            "app_id",
            "build_version",
            "short_version",
        ]
        for field in ios_required_fields:
            assert field in metadata, f"iOS metadata missing required field: {field}"
            assert metadata[field] is not None, f"iOS metadata field {field} should not be None"

        # Verify iOS-specific optional fields are present (may be None but key should exist)
        ios_optional_fields = [
            "minimum_os_version",
            "sdk_version",
            "is_simulator",
            "codesigning_type",
            "build_date",
        ]
        for field in ios_optional_fields:
            assert field in metadata, f"iOS metadata missing optional field: {field}"

        # Verify build_date format if present (should be ISO format)
        if metadata.get("build_date"):
            try:
                datetime.fromisoformat(metadata["build_date"])
            except ValueError:
                raise AssertionError(f"build_date should be ISO format, got: {metadata['build_date']}")

        # Check size analysis was uploaded
        assert results["has_size_analysis_file"], "Size analysis file should be uploaded"

        # Verify size analysis contents
        size_analysis = get_size_analysis_raw(artifact_id)
        assert "download_size" in size_analysis, "Size analysis should contain download_size"
        assert isinstance(size_analysis["download_size"], int), "download_size should be an integer"
        assert "insights" in size_analysis, "Size analysis should contain insights"
        assert "treemap" in size_analysis, "Size analysis should contain treemap"

        # Verify insights were generated
        insights = size_analysis["insights"]
        assert isinstance(insights, list), "insights should be a list"
        assert len(insights) > 0, "Should generate at least one insight"

        print("✓ iOS E2E test passed!")
        print(f"  - Download size: {size_analysis.get('download_size', 'N/A')} bytes")
        print(f"  - Insights generated: {len(insights)}")
        print(f"  - App name: {metadata.get('app_name')}")
        print(f"  - Build date: {metadata.get('build_date')}")

    def test_android_apk_full_flow(self):
        """Test full flow with Android .apk file."""
        if not ANDROID_APK_FIXTURE.exists():
            pytest.skip(f"Android APK fixture not found: {ANDROID_APK_FIXTURE}")

        artifact_id = "test-android-apk-001"
        org = "test-org"
        project = "test-android-project"

        print("\n=== Testing Android .apk E2E flow ===")

        # Step 1: Upload artifact to mock API
        upload_artifact_to_mock_api(artifact_id, ANDROID_APK_FIXTURE)

        # Step 2: Send Kafka message
        send_kafka_message(artifact_id, org, project, ["size_analysis"])

        # Step 3: Wait for processing
        results = wait_for_processing(artifact_id, timeout=180)

        # Step 4: Verify results
        print("\n=== Verifying results ===")

        # Check artifact metadata was updated
        assert results["artifact_metadata"], "Artifact metadata should be updated"
        metadata = results["artifact_metadata"]

        # Verify Android-specific metadata fields (API contract)
        android_required_fields = [
            "app_name",
            "app_id",
            "version_code",
            "version_name",
        ]
        for field in android_required_fields:
            assert field in metadata, f"Android metadata missing required field: {field}"
            assert metadata[field] is not None, f"Android metadata field {field} should not be None"

        # Check size analysis was uploaded
        assert results["has_size_analysis_file"], "Size analysis file should be uploaded"

        # Verify size analysis contents
        size_analysis = get_size_analysis_raw(artifact_id)
        assert "download_size" in size_analysis, "Size analysis should contain download_size"
        assert isinstance(size_analysis["download_size"], int), "download_size should be an integer"
        assert "insights" in size_analysis, "Size analysis should contain insights"
        assert isinstance(size_analysis["insights"], list), "insights should be a list"

        print("✓ Android APK E2E test passed!")
        print(f"  - Download size: {size_analysis.get('download_size', 'N/A')} bytes")
        print(f"  - Insights generated: {len(size_analysis['insights'])}")
        print(f"  - App name: {metadata.get('app_name')}")

    def test_android_aab_full_flow(self):
        """Test full flow with Android .aab file."""
        if not ANDROID_AAB_FIXTURE.exists():
            pytest.skip(f"Android AAB fixture not found: {ANDROID_AAB_FIXTURE}")

        artifact_id = "test-android-aab-001"
        org = "test-org"
        project = "test-android-project"

        print("\n=== Testing Android .aab E2E flow ===")

        # Step 1: Upload artifact to mock API
        upload_artifact_to_mock_api(artifact_id, ANDROID_AAB_FIXTURE)

        # Step 2: Send Kafka message
        send_kafka_message(artifact_id, org, project, ["size_analysis"])

        # Step 3: Wait for processing
        results = wait_for_processing(artifact_id, timeout=180)

        # Step 4: Verify results
        print("\n=== Verifying results ===")

        # Check artifact metadata was updated
        assert results["artifact_metadata"], "Artifact metadata should be updated"
        metadata = results["artifact_metadata"]

        # Verify Android-specific metadata fields (API contract)
        android_required_fields = [
            "app_name",
            "app_id",
            "version_code",
            "version_name",
        ]
        for field in android_required_fields:
            assert field in metadata, f"Android metadata missing required field: {field}"
            assert metadata[field] is not None, f"Android metadata field {field} should not be None"

        # Check size analysis was uploaded
        assert results["has_size_analysis_file"], "Size analysis file should be uploaded"

        # Verify size analysis contents
        size_analysis = get_size_analysis_raw(artifact_id)
        assert "download_size" in size_analysis, "Size analysis should contain download_size"
        assert isinstance(size_analysis["download_size"], int), "download_size should be an integer"
        assert "insights" in size_analysis, "Size analysis should contain insights"
        assert isinstance(size_analysis["insights"], list), "insights should be a list"

        print("✓ Android AAB E2E test passed!")
        print(f"  - Download size: {size_analysis.get('download_size', 'N/A')} bytes")
        print(f"  - Insights generated: {len(size_analysis['insights'])}")
        print(f"  - App name: {metadata.get('app_name')}")

    def test_launchpad_health_check(self):
        """Verify Launchpad service is healthy."""
        response = requests.get(f"{LAUNCHPAD_URL}/health", timeout=10)
        assert response.status_code == 200
        data = response.json()
        assert data["service"] == "launchpad"
        assert data["status"] == "ok"
        print("✓ Launchpad health check passed")
