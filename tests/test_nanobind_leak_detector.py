"""Test to verify nanobind leak detector is working by intentionally creating leaks."""

from __future__ import annotations

import gc

from pathlib import Path
from typing import Any

import pytest

try:
    import lief
except ImportError:
    pytest.skip("LIEF not available for testing", allow_module_level=True)

# Global variable to hold leaked objects
_leaked_objects: list[Any] = []


def test_intentional_nanobind_leak(nanobind_leak_detector: Any) -> None:
    """Test that intentionally creates nanobind leaks to verify the detector works."""
    # Get a test binary to parse
    test_artifacts_dir = Path(__file__).parent / "_fixtures"
    test_binary = None

    # Look for any binary file in the test fixtures
    for binary_path in test_artifacts_dir.rglob("*"):
        if binary_path.is_file() and binary_path.suffix not in [".plist", ".txt", ".md"]:
            try:
                # Try to parse it with LIEF to see if it's a valid binary
                parsed = lief.MachO.parse(str(binary_path))  # type: ignore
                if parsed and parsed.size > 0:
                    test_binary = binary_path
                    break
            except Exception:
                continue

    if not test_binary:
        pytest.skip("No suitable test binary found in fixtures")

    # Intentionally create leaked LIEF objects
    # Parse the binary multiple times and store references globally
    for _ in range(3):
        fat_binary = lief.MachO.parse(str(test_binary))  # type: ignore
        if fat_binary and fat_binary.size > 0:
            binary = fat_binary.at(0)

            # Store references globally to prevent garbage collection
            _leaked_objects.append(fat_binary)
            _leaked_objects.append(binary)

            # Create more objects that won't be cleaned up
            if binary.symbols:
                for j, symbol in enumerate(binary.symbols):
                    _leaked_objects.append(symbol)
                    if j >= 10:  # Don't leak too many
                        break

    # Don't clean up _leaked_objects - this should trigger the leak detector
    print(f"Intentionally leaked {len(_leaked_objects)} nanobind objects")


def test_proper_cleanup_no_leak(nanobind_leak_detector: Any) -> None:
    """Test that demonstrates proper cleanup doesn't trigger leak detector."""
    # Get a test binary to parse
    test_artifacts_dir = Path(__file__).parent / "_fixtures"
    test_binary = None

    # Look for any binary file in the test fixtures
    for binary_path in test_artifacts_dir.rglob("*"):
        if binary_path.is_file() and binary_path.suffix not in [".plist", ".txt", ".md"]:
            try:
                # Try to parse it with LIEF to see if it's a valid binary
                parsed = lief.MachO.parse(str(binary_path))  # type: ignore
                if parsed and parsed.size > 0:
                    test_binary = binary_path
                    break
            except Exception:
                continue

    if not test_binary:
        pytest.skip("No suitable test binary found in fixtures")

    # Properly use LIEF objects without leaking
    fat_binary = lief.MachO.parse(str(test_binary))  # type: ignore
    if fat_binary and fat_binary.size > 0:
        binary = fat_binary.at(0)

        # Use the objects but don't store global references
        symbol_count = len(binary.symbols)

        print(f"Analyzed binary with {symbol_count} symbols")

        # Objects will be properly garbage collected when they go out of scope
        del binary
        del fat_binary

        # Force garbage collection to clean up
        gc.collect()
