"""End-to-end tests for Launchpad service via TaskWorker.

Tests the full flow:
1. Upload all test artifacts to mock API
2. Dispatch all tasks via taskbroker-client (process_artifact.delay())
3. Wait for Launchpad worker to process all artifacts in parallel
4. Verify results via mock API

All artifact tasks are dispatched upfront and processed concurrently
by the worker (LAUNCHPAD_WORKER_CONCURRENCY=3), so total time is
bounded by the slowest artifact rather than the sum of all.
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
                print(f"  [{artifact_id}] Waiting... (results so far: {results})")
                last_status = current_status

        except requests.exceptions.RequestException as e:
            print(f"  [{artifact_id}] Error checking results: {e}")

        time.sleep(check_interval)

    raise TimeoutError(f"Artifact {artifact_id} was not processed within {timeout}s")


def get_size_analysis_raw(artifact_id: str) -> Dict[str, Any]:
    response = requests.get(f"{MOCK_API_URL}/test/results/{artifact_id}/size-analysis-raw", timeout=10)
    response.raise_for_status()
    return response.json()


def wait_for_mock_api(timeout: int = 60) -> None:
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            response = requests.get(f"{MOCK_API_URL}/health", timeout=5)
            if response.status_code == 200:
                print("[OK] Mock Sentry API is healthy")
                return
        except requests.exceptions.RequestException:
            pass
        time.sleep(2)
    raise TimeoutError("Mock Sentry API did not become healthy within 60s")


class TestE2EFlow:
    """Fast e2e tests — APK processing + error handling.

    These run locally on any architecture since APK analysis is lightweight.
    """

    @classmethod
    def setup_class(cls):
        wait_for_mock_api()

    def test_android_apk_full_flow(self):
        if not ANDROID_APK_FIXTURE.exists():
            pytest.skip(f"Android APK fixture not found: {ANDROID_APK_FIXTURE}")

        artifact_id = "test-android-apk-001"

        upload_artifact_to_mock_api(artifact_id, ANDROID_APK_FIXTURE)
        dispatch_task(artifact_id, "test-org", "test-android-project")
        results = wait_for_processing(artifact_id, timeout=120)

        metadata = results["artifact_metadata"]
        assert metadata["app_name"] == "Hacker News"
        assert metadata["app_id"] == "com.emergetools.hackernews"
        assert metadata["artifact_type"] == 2
        assert metadata["android_app_info"]["has_proguard_mapping"] is False

        assert results["has_size_analysis_file"]

        size_analysis = get_size_analysis_raw(artifact_id)
        assert size_analysis["download_size"] == 3670839

        treemap = size_analysis["treemap"]
        assert treemap["platform"] == "android"
        assert treemap["root"]["name"] == "Hacker News"
        assert treemap["root"]["size"] == 7886041
        assert len(treemap["root"]["children"]) == 14

        insights = size_analysis["insights"]
        assert insights["duplicate_files"]["total_savings"] == 51709
        assert insights["multiple_native_library_archs"]["total_savings"] == 1891208

    def test_nonexistent_artifact_error_handling(self):
        dispatch_task("test-nonexistent-artifact", "test-org", "test-project")
        time.sleep(15)

        response = requests.get(f"{MOCK_API_URL}/test/results/test-nonexistent-artifact", timeout=10)
        results = response.json()
        assert not results["has_size_analysis_file"]


@pytest.mark.slow
class TestE2EFlowAllPlatforms:
    """Full platform e2e tests — dispatches iOS, APK, and AAB in parallel.

    Requires LAUNCHPAD_WORKER_CONCURRENCY>=3 to process concurrently.
    Total time is bounded by the slowest artifact (~6 min for iOS)
    rather than the sum of all.
    """

    @classmethod
    def setup_class(cls):
        wait_for_mock_api()

        cls.artifacts = {}

        if ANDROID_APK_FIXTURE.exists():
            upload_artifact_to_mock_api("test-apk-parallel", ANDROID_APK_FIXTURE)
            dispatch_task("test-apk-parallel", "test-org", "test-android-project")
            cls.artifacts["apk"] = "test-apk-parallel"

        if IOS_FIXTURE.exists():
            upload_artifact_to_mock_api("test-ios-parallel", IOS_FIXTURE)
            dispatch_task("test-ios-parallel", "test-org", "test-ios-project")
            cls.artifacts["ios"] = "test-ios-parallel"

        if ANDROID_AAB_FIXTURE.exists():
            upload_artifact_to_mock_api("test-aab-parallel", ANDROID_AAB_FIXTURE)
            dispatch_task("test-aab-parallel", "test-org", "test-android-project")
            cls.artifacts["aab"] = "test-aab-parallel"

        dispatch_task("test-nonexistent-parallel", "test-org", "test-project")
        cls.artifacts["nonexistent"] = "test-nonexistent-parallel"

        print(f"[OK] Dispatched {len(cls.artifacts)} tasks for parallel processing")

    def test_android_apk(self):
        artifact_id = self.artifacts.get("apk")
        if not artifact_id:
            pytest.skip("APK fixture not found")

        results = wait_for_processing(artifact_id, timeout=600)

        metadata = results["artifact_metadata"]
        assert metadata["app_name"] == "Hacker News"
        assert metadata["app_id"] == "com.emergetools.hackernews"
        assert metadata["artifact_type"] == 2

        assert results["has_size_analysis_file"]
        size_analysis = get_size_analysis_raw(artifact_id)
        assert size_analysis["download_size"] == 3670839

    def test_ios_xcarchive(self):
        artifact_id = self.artifacts.get("ios")
        if not artifact_id:
            pytest.skip("iOS fixture not found")

        results = wait_for_processing(artifact_id, timeout=600)

        metadata = results["artifact_metadata"]
        assert metadata["app_name"] == "HackerNews"
        assert metadata["app_id"] == "com.emergetools.hackernews"
        assert metadata["artifact_type"] == 0
        assert metadata["apple_app_info"]["is_simulator"] is False

        assert results["has_size_analysis_file"]
        size_analysis = get_size_analysis_raw(artifact_id)
        assert size_analysis["download_size"] == 6502319
        assert size_analysis["treemap"]["root"]["size"] == 9728000

    def test_android_aab(self):
        artifact_id = self.artifacts.get("aab")
        if not artifact_id:
            pytest.skip("AAB fixture not found")

        results = wait_for_processing(artifact_id, timeout=600)

        metadata = results["artifact_metadata"]
        assert metadata["app_name"] == "Hacker News"
        assert metadata["app_id"] == "com.emergetools.hackernews"
        assert metadata["artifact_type"] == 1

        assert results["has_size_analysis_file"]
        size_analysis = get_size_analysis_raw(artifact_id)
        assert size_analysis["download_size"] > 0
        assert size_analysis["treemap"]["root"]["size"] == 5932249

    def test_nonexistent_artifact(self):
        time.sleep(15)
        response = requests.get(f"{MOCK_API_URL}/test/results/test-nonexistent-parallel", timeout=10)
        results = response.json()
        assert not results["has_size_analysis_file"]
