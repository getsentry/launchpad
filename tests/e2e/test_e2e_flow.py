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
                print(f"[OK] {service_name} is healthy")
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
        print(f"[OK] Uploaded artifact {artifact_id} ({file_path.name})")


def send_kafka_message(artifact_id: str, org: str, project: str, features: list[str]) -> None:
    """Send a Kafka message to trigger artifact processing."""
    delivery_error = None

    def delivery_callback(err, msg):
        nonlocal delivery_error
        if err:
            delivery_error = err

    producer = Producer({"bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS, "client.id": "e2e-test-producer"})

    message = {
        "artifact_id": artifact_id,
        "organization_id": org,
        "project_id": project,
        "requested_features": features,
    }

    producer.produce(
        KAFKA_TOPIC,
        key=artifact_id.encode("utf-8"),
        value=json.dumps(message).encode("utf-8"),
        callback=delivery_callback,
    )
    remaining = producer.flush(timeout=10)

    if delivery_error:
        raise RuntimeError(f"Kafka message delivery failed: {delivery_error}")
    if remaining > 0:
        raise RuntimeError(f"Failed to flush {remaining} Kafka messages")

    print(f"[OK] Sent Kafka message for artifact {artifact_id}")


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
                print(f"[OK] Processing completed for {artifact_id}")
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

        # Verify exact metadata values for HackerNews.xcarchive.zip
        assert metadata["app_name"] == "HackerNews"
        assert metadata["app_id"] == "com.emergetools.hackernews"
        assert metadata["build_version"] == "3.8"
        assert metadata["build_number"] == 1
        assert metadata["artifact_type"] == 0  # iOS xcarchive

        # Verify iOS-specific nested info
        assert "apple_app_info" in metadata
        apple_info = metadata["apple_app_info"]
        assert apple_info["is_simulator"] is False
        assert apple_info["codesigning_type"] == "development"
        assert apple_info["build_date"] == "2025-05-19T16:15:12"
        assert apple_info["is_code_signature_valid"] is True
        assert apple_info["main_binary_uuid"] == "BEB3C0D6-2518-343D-BB6F-FF5581C544E8"

        # Check size analysis was uploaded
        assert results["has_size_analysis_file"], "Size analysis file should be uploaded"

        # Verify size analysis contents with exact values
        size_analysis = get_size_analysis_raw(artifact_id)
        assert size_analysis["download_size"] == 6502319

        # Verify treemap structure (root size is install size, different from download_size)
        treemap = size_analysis["treemap"]
        assert treemap["platform"] == "ios"
        assert treemap["root"]["name"] == "HackerNews"
        assert treemap["root"]["size"] == 9728000  # Install size, larger than download_size
        assert treemap["root"]["is_dir"] is True
        assert len(treemap["root"]["children"]) > 0

        # Verify expected insight categories and their structure
        insights = size_analysis["insights"]
        assert "duplicate_files" in insights
        assert insights["duplicate_files"]["total_savings"] > 0
        assert len(insights["duplicate_files"]["groups"]) > 0

        assert "image_optimization" in insights
        assert insights["image_optimization"]["total_savings"] > 0
        assert len(insights["image_optimization"]["optimizable_files"]) > 0

        assert "main_binary_exported_symbols" in insights
        assert insights["main_binary_exported_symbols"]["total_savings"] > 0

        print("[OK] iOS E2E test passed!")
        print(f"  - Download size: {size_analysis['download_size']} bytes")
        print(f"  - Treemap root size: {treemap['root']['size']} bytes")
        print(f"  - Insight categories: {list(insights.keys())}")

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

        # Verify exact metadata values for hn.apk
        assert metadata["app_name"] == "Hacker News"
        assert metadata["app_id"] == "com.emergetools.hackernews"
        assert metadata["artifact_type"] == 2  # Android APK

        # Verify Android-specific nested info
        assert "android_app_info" in metadata
        android_info = metadata["android_app_info"]
        assert android_info["has_proguard_mapping"] is False

        # Check size analysis was uploaded
        assert results["has_size_analysis_file"], "Size analysis file should be uploaded"

        # Verify size analysis contents with exact values
        size_analysis = get_size_analysis_raw(artifact_id)
        assert size_analysis["download_size"] == 3670839

        # Verify treemap structure and root size
        treemap = size_analysis["treemap"]
        assert treemap["platform"] == "android"
        assert treemap["root"]["name"] == "Hacker News"
        assert treemap["root"]["size"] == 7886041
        assert treemap["root"]["is_dir"] is True
        assert len(treemap["root"]["children"]) == 14

        # Verify expected insight categories and their structure
        insights = size_analysis["insights"]
        assert "duplicate_files" in insights
        assert insights["duplicate_files"]["total_savings"] == 51709
        assert len(insights["duplicate_files"]["groups"]) > 0

        assert "multiple_native_library_archs" in insights
        assert insights["multiple_native_library_archs"]["total_savings"] == 1891208

        print("[OK] Android APK E2E test passed!")
        print(f"  - Download size: {size_analysis['download_size']} bytes")
        print(f"  - Treemap root size: {treemap['root']['size']} bytes")
        print(f"  - Insight categories: {list(insights.keys())}")

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

        # Verify exact metadata values for hn.aab
        assert metadata["app_name"] == "Hacker News"
        assert metadata["app_id"] == "com.emergetools.hackernews"
        assert metadata["build_version"] == "1.0.2"
        assert metadata["build_number"] == 13
        assert metadata["artifact_type"] == 1  # Android AAB

        # Verify Android-specific nested info
        assert "android_app_info" in metadata
        android_info = metadata["android_app_info"]
        assert android_info["has_proguard_mapping"] is True

        # Check size analysis was uploaded
        assert results["has_size_analysis_file"], "Size analysis file should be uploaded"

        # Verify size analysis contents
        size_analysis = get_size_analysis_raw(artifact_id)
        # AAB download size varies based on extracted APKs - verify it's positive
        assert size_analysis["download_size"] > 0

        # Verify treemap structure and root size
        treemap = size_analysis["treemap"]
        assert treemap["platform"] == "android"
        assert treemap["root"]["name"] == "Hacker News"
        assert treemap["root"]["size"] == 5932249
        assert treemap["root"]["is_dir"] is True
        assert len(treemap["root"]["children"]) == 14

        # Verify expected insight categories for Android AAB
        insights = size_analysis["insights"]
        assert "duplicate_files" in insights
        assert insights["duplicate_files"]["total_savings"] >= 0
        assert "groups" in insights["duplicate_files"]

        print("[OK] Android AAB E2E test passed!")
        print(f"  - Download size: {size_analysis['download_size']} bytes")
        print(f"  - Treemap root size: {treemap['root']['size']} bytes")
        print(f"  - Insight categories: {list(insights.keys())}")

    def test_launchpad_health_check(self):
        """Verify Launchpad service is healthy."""
        response = requests.get(f"{LAUNCHPAD_URL}/health", timeout=10)
        assert response.status_code == 200
        data = response.json()
        assert data["service"] == "launchpad"
        assert data["status"] == "ok"
        print("[OK] Launchpad health check passed")

    def test_nonexistent_artifact_error_handling(self):
        """Test that processing a non-existent artifact is handled gracefully."""
        artifact_id = "test-nonexistent-artifact"
        org = "test-org"
        project = "test-project"

        print("\n=== Testing non-existent artifact error handling ===")

        # Don't upload any artifact - just send Kafka message for non-existent one
        send_kafka_message(artifact_id, org, project, ["size_analysis"])

        # Wait a bit for processing attempt
        time.sleep(10)

        # Check results - should have error metadata, no size analysis
        response = requests.get(f"{MOCK_API_URL}/test/results/{artifact_id}", timeout=10)
        response.raise_for_status()
        results = response.json()

        # Verify no size analysis was uploaded (artifact download should have failed)
        assert not results["has_size_analysis_file"], "Should not have size analysis for non-existent artifact"

        # The artifact metadata may have error information
        metadata = results.get("artifact_metadata", {})
        # If error was recorded, it should indicate a download/processing failure
        if metadata:
            # Check if error fields are present (depends on implementation)
            print(f"  Metadata received: {metadata}")

        print("[OK] Non-existent artifact handled correctly (no size analysis produced)")
