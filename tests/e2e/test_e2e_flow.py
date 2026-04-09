"""End-to-end tests for Launchpad service via TaskWorker.

Tests the full flow:
1. Upload test artifact to mock API
2. Dispatch task via taskbroker-client (process_artifact.delay())
3. Wait for Launchpad worker to process
4. Verify results via mock API
"""

import json
import os
import time

from pathlib import Path
from typing import Any, Dict

import pytest
import requests

MOCK_API_URL = os.getenv("MOCK_API_URL", "http://mock-sentry-api:8000")

FIXTURES_DIR = Path("/app/fixtures")
IOS_FIXTURE = FIXTURES_DIR / "ios" / "HackerNews.xcarchive.zip"
ANDROID_APK_FIXTURE = FIXTURES_DIR / "android" / "hn.apk"
ANDROID_AAB_FIXTURE = FIXTURES_DIR / "android" / "hn.aab"


def dispatch_task(artifact_id: str, org: str, project: str) -> None:
    from launchpad.worker.tasks import process_artifact

    process_artifact.delay(
        artifact_id=artifact_id,
        project_id=project,
        organization_id=org,
    )
    print(f"[OK] Dispatched task for artifact {artifact_id}")


def upload_artifact_to_mock_api(artifact_id: str, file_path: Path) -> None:
    with open(file_path, "rb") as f:
        files = {"file": (file_path.name, f, "application/zip")}
        response = requests.post(f"{MOCK_API_URL}/test/upload-artifact/{artifact_id}", files=files, timeout=30)
        response.raise_for_status()
        print(f"[OK] Uploaded artifact {artifact_id} ({file_path.name})")


def wait_for_processing(artifact_id: str, timeout: int = 120, check_interval: int = 3) -> Dict[str, Any]:
    start_time = time.time()
    last_status = None

    while time.time() - start_time < timeout:
        try:
            response = requests.get(f"{MOCK_API_URL}/test/results/{artifact_id}", timeout=10)
            response.raise_for_status()
            results = response.json()

            if results.get("artifact_metadata") and results.get("has_size_analysis_file"):
                print(f"[OK] Processing completed for {artifact_id}")
                return results

            current_status = json.dumps(results, sort_keys=True)
            if current_status != last_status:
                print(f"  Waiting for processing... (results so far: {results})")
                last_status = current_status

        except requests.exceptions.RequestException as e:
            print(f"  Error checking results: {e}")

        time.sleep(check_interval)

    raise TimeoutError(f"Artifact {artifact_id} was not processed within {timeout}s")


def get_size_analysis_raw(artifact_id: str) -> Dict[str, Any]:
    response = requests.get(f"{MOCK_API_URL}/test/results/{artifact_id}/size-analysis-raw", timeout=10)
    response.raise_for_status()
    return response.json()


class TestE2EFlow:
    @classmethod
    def setup_class(cls):
        print("\n=== Waiting for services to be ready ===")

        start_time = time.time()
        while time.time() - start_time < 60:
            try:
                response = requests.get(f"{MOCK_API_URL}/health", timeout=5)
                if response.status_code == 200:
                    print("[OK] Mock Sentry API is healthy")
                    break
            except requests.exceptions.RequestException:
                pass
            time.sleep(2)
        else:
            raise TimeoutError("Mock Sentry API did not become healthy within 60s")

        print("=== All services ready ===\n")

    def test_ios_xcarchive_full_flow(self):
        if not IOS_FIXTURE.exists():
            pytest.skip(f"iOS fixture not found: {IOS_FIXTURE}")

        artifact_id = "test-ios-001"
        org = "test-org"
        project = "test-ios-project"

        print("\n=== Testing iOS .xcarchive.zip E2E flow ===")

        upload_artifact_to_mock_api(artifact_id, IOS_FIXTURE)
        dispatch_task(artifact_id, org, project)
        results = wait_for_processing(artifact_id, timeout=360)

        print("\n=== Verifying results ===")

        assert results["artifact_metadata"], "Artifact metadata should be updated"
        metadata = results["artifact_metadata"]

        assert metadata["app_name"] == "HackerNews"
        assert metadata["app_id"] == "com.emergetools.hackernews"
        assert metadata["build_version"] == "3.8"
        assert metadata["build_number"] == 1
        assert metadata["artifact_type"] == 0

        assert "apple_app_info" in metadata
        apple_info = metadata["apple_app_info"]
        assert apple_info["is_simulator"] is False
        assert apple_info["codesigning_type"] == "development"
        assert apple_info["build_date"] == "2025-05-19T16:15:12"
        assert apple_info["is_code_signature_valid"] is True
        assert apple_info["main_binary_uuid"] == "BEB3C0D6-2518-343D-BB6F-FF5581C544E8"

        assert results["has_size_analysis_file"], "Size analysis file should be uploaded"

        size_analysis = get_size_analysis_raw(artifact_id)
        assert size_analysis["download_size"] == 6502319

        treemap = size_analysis["treemap"]
        assert treemap["platform"] == "ios"
        assert treemap["root"]["name"] == "HackerNews"
        assert treemap["root"]["size"] == 9728000
        assert treemap["root"]["is_dir"] is True
        assert len(treemap["root"]["children"]) > 0

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

    def test_android_apk_full_flow(self):
        if not ANDROID_APK_FIXTURE.exists():
            pytest.skip(f"Android APK fixture not found: {ANDROID_APK_FIXTURE}")

        artifact_id = "test-android-apk-001"
        org = "test-org"
        project = "test-android-project"

        print("\n=== Testing Android .apk E2E flow ===")

        upload_artifact_to_mock_api(artifact_id, ANDROID_APK_FIXTURE)
        dispatch_task(artifact_id, org, project)
        results = wait_for_processing(artifact_id, timeout=360)

        print("\n=== Verifying results ===")

        assert results["artifact_metadata"], "Artifact metadata should be updated"
        metadata = results["artifact_metadata"]

        assert metadata["app_name"] == "Hacker News"
        assert metadata["app_id"] == "com.emergetools.hackernews"
        assert metadata["artifact_type"] == 2

        assert "android_app_info" in metadata
        android_info = metadata["android_app_info"]
        assert android_info["has_proguard_mapping"] is False

        assert results["has_size_analysis_file"], "Size analysis file should be uploaded"

        size_analysis = get_size_analysis_raw(artifact_id)
        assert size_analysis["download_size"] == 3670839

        treemap = size_analysis["treemap"]
        assert treemap["platform"] == "android"
        assert treemap["root"]["name"] == "Hacker News"
        assert treemap["root"]["size"] == 7886041
        assert treemap["root"]["is_dir"] is True
        assert len(treemap["root"]["children"]) == 14

        insights = size_analysis["insights"]
        assert "duplicate_files" in insights
        assert insights["duplicate_files"]["total_savings"] == 51709
        assert len(insights["duplicate_files"]["groups"]) > 0

        assert "multiple_native_library_archs" in insights
        assert insights["multiple_native_library_archs"]["total_savings"] == 1891208

        print("[OK] Android APK E2E test passed!")

    def test_android_aab_full_flow(self):
        if not ANDROID_AAB_FIXTURE.exists():
            pytest.skip(f"Android AAB fixture not found: {ANDROID_AAB_FIXTURE}")

        artifact_id = "test-android-aab-001"
        org = "test-org"
        project = "test-android-project"

        print("\n=== Testing Android .aab E2E flow ===")

        upload_artifact_to_mock_api(artifact_id, ANDROID_AAB_FIXTURE)
        dispatch_task(artifact_id, org, project)
        results = wait_for_processing(artifact_id, timeout=360)

        print("\n=== Verifying results ===")

        assert results["artifact_metadata"], "Artifact metadata should be updated"
        metadata = results["artifact_metadata"]

        assert metadata["app_name"] == "Hacker News"
        assert metadata["app_id"] == "com.emergetools.hackernews"
        assert metadata["build_version"] == "1.0.2"
        assert metadata["build_number"] == 13
        assert metadata["artifact_type"] == 1

        assert "android_app_info" in metadata
        android_info = metadata["android_app_info"]
        assert android_info["has_proguard_mapping"] is True

        assert results["has_size_analysis_file"], "Size analysis file should be uploaded"

        size_analysis = get_size_analysis_raw(artifact_id)
        assert size_analysis["download_size"] > 0

        treemap = size_analysis["treemap"]
        assert treemap["platform"] == "android"
        assert treemap["root"]["name"] == "Hacker News"
        assert treemap["root"]["size"] == 5932249
        assert treemap["root"]["is_dir"] is True
        assert len(treemap["root"]["children"]) == 14

        insights = size_analysis["insights"]
        assert "duplicate_files" in insights
        assert insights["duplicate_files"]["total_savings"] >= 0
        assert "groups" in insights["duplicate_files"]

        print("[OK] Android AAB E2E test passed!")

    def test_nonexistent_artifact_error_handling(self):
        artifact_id = "test-nonexistent-artifact"
        org = "test-org"
        project = "test-project"

        print("\n=== Testing non-existent artifact error handling ===")

        dispatch_task(artifact_id, org, project)

        time.sleep(15)

        response = requests.get(f"{MOCK_API_URL}/test/results/{artifact_id}", timeout=10)
        response.raise_for_status()
        results = response.json()

        assert not results["has_size_analysis_file"], "Should not have size analysis for non-existent artifact"

        print("[OK] Non-existent artifact handled correctly")
