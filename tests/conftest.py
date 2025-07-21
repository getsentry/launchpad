import os
import sys

from io import StringIO
from typing import Generator

import pytest


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Set up test environment variables for all tests."""
    os.environ.setdefault("LAUNCHPAD_ENV", "TEST")


class NanobindLeakDetector:
    """Captures stderr and detects nanobind leak messages."""

    def __init__(self):
        self.original_stderr = sys.stderr
        self.captured_stderr = StringIO()
        self.leak_detected = False
        self.leak_messages: list[str] = []

    def start_capture(self):
        """Start capturing stderr."""
        sys.stderr = self.captured_stderr

    def stop_capture_and_check(self):
        """Stop capturing stderr and check for nanobind leaks."""
        # Restore original stderr
        sys.stderr = self.original_stderr

        # Get captured content
        captured_content = self.captured_stderr.getvalue()

        # Check for nanobind leak messages
        lines = captured_content.split("\n")
        leak_lines = [line for line in lines if "nanobind: leaked" in line.lower()]

        if leak_lines:
            self.leak_detected = True
            self.leak_messages.extend(leak_lines)

        # Write captured content to original stderr so it's still visible
        if captured_content:
            self.original_stderr.write(captured_content)

        # Reset for next capture
        self.captured_stderr = StringIO()


@pytest.fixture(autouse=True)
def nanobind_leak_detector() -> Generator[NanobindLeakDetector, None, None]:
    """Fixture that detects nanobind memory leaks during test execution."""
    detector = NanobindLeakDetector()

    # Start capturing before the test
    detector.start_capture()

    try:
        yield detector
    finally:
        detector.stop_capture_and_check()

        if detector.leak_detected:
            leak_summary = "\n".join(f"  • {msg}" for msg in detector.leak_messages)
            pytest.fail(
                f"❌ NANOBIND MEMORY LEAK DETECTED ❌\n\n"
                f"This change caused nanobind memory leaks, which can lead to dangerous memory issues.\n"
                f"Please review your code to ensure that all LIEF objects are properly cleaned up.\n\n"
                f"Leak messages detected:\n{leak_summary}\n\n"
            )
