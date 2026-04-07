"""End-to-end tests for Launchpad service.

These tests require the E2E Docker Compose environment to be running.
The full artifact processing flow tests need to be updated to use
TaskWorker-based triggering instead of Kafka.
"""

import os
import time

from pathlib import Path
from typing import Any, Dict

import requests

MOCK_API_URL = os.getenv("MOCK_API_URL", "http://mock-sentry-api:8000")
LAUNCHPAD_URL = os.getenv("LAUNCHPAD_URL", "http://launchpad:2218")

FIXTURES_DIR = Path("/app/fixtures")
IOS_FIXTURE = FIXTURES_DIR / "ios" / "HackerNews.xcarchive.zip"
ANDROID_APK_FIXTURE = FIXTURES_DIR / "android" / "hn.apk"
ANDROID_AAB_FIXTURE = FIXTURES_DIR / "android" / "hn.aab"


def wait_for_service(url: str, timeout: int = 60, service_name: str = "service") -> None:
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

            import json

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
