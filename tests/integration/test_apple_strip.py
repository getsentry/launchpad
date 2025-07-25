"""Integration tests for AppleStrip."""

import shutil
import tempfile
import zipfile

from pathlib import Path

import pytest

from launchpad.utils.apple.apple_strip import AppleStrip


class TestAppleStrip:
    """Test AppleStrip against real binaries."""

    @pytest.fixture
    def sentry_zip_path(self) -> Path:
        """Path to the Sentry iOS binary zip file."""
        return Path("tests/_fixtures/ios/Sentry-ios-arm64_arm64e.zip")

    def test_strip_sentry_binary(self, sentry_zip_path: Path) -> None:
        """Test stripping the main Sentry binary from the iOS framework."""
        # Create a temporary directory for extraction
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Extract the zip file
            with zipfile.ZipFile(sentry_zip_path, "r") as zip_ref:
                zip_ref.extractall(temp_path)

            # Find the main Sentry binary
            sentry_binary_path = temp_path / "Sentry-ios-arm64_arm64e" / "Sentry.framework" / "Sentry"
            assert sentry_binary_path.exists(), f"Sentry binary not found at {sentry_binary_path}"

            # Get original size for reference
            original_size = sentry_binary_path.stat().st_size
            assert original_size > 0, "Original binary should have non-zero size"

            # Create a copy for stripping (preserve original for comparison)
            stripped_binary_path = temp_path / "Sentry_stripped"
            shutil.copy2(sentry_binary_path, stripped_binary_path)

            # Strip the binary
            apple_strip = AppleStrip()
            result = apple_strip.strip(
                input_file=stripped_binary_path,
                output_file=None,  # Strip in-place
                flags=["-STx"],
            )

            # Verify the strip command succeeded
            assert result.returncode == 0, f"Strip command failed with return code {result.returncode}"

            # Check the stripped binary size
            stripped_size = stripped_binary_path.stat().st_size
            expected_size = 14355952

            assert stripped_size == expected_size, (
                f"Stripped binary size {stripped_size} does not match expected size {expected_size}. "
                f"Original size was {original_size}"
            )

            # Verify the binary was actually stripped (should be smaller than original)
            assert stripped_size < original_size, (
                f"Stripped binary ({stripped_size} bytes) should be smaller than original ({original_size} bytes)"
            )

    def test_strip_with_output_file(self, sentry_zip_path: Path) -> None:
        """Test stripping with explicit output file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Extract the zip file
            with zipfile.ZipFile(sentry_zip_path, "r") as zip_ref:
                zip_ref.extractall(temp_path)

            # Find the main Sentry binary
            sentry_binary_path = temp_path / "Sentry-ios-arm64_arm64e" / "Sentry.framework" / "Sentry"
            assert sentry_binary_path.exists(), f"Sentry binary not found at {sentry_binary_path}"

            # Strip to a new output file
            output_path = temp_path / "Sentry_output_stripped"
            apple_strip = AppleStrip()
            result = apple_strip.strip(
                input_file=sentry_binary_path,
                output_file=output_path,
                flags=["-STx"],  # Strip debug symbols
            )

            # Verify the strip command succeeded
            assert result.returncode == 0, f"Strip command failed with return code {result.returncode}"

            # Check the output file exists and has expected size
            assert output_path.exists(), f"Output file not created at {output_path}"
            stripped_size = output_path.stat().st_size
            expected_size = 14355952

            assert stripped_size == expected_size, (
                f"Stripped binary size {stripped_size} does not match expected size {expected_size}"
            )

            # Verify original file is unchanged
            original_size = sentry_binary_path.stat().st_size
            assert stripped_size < original_size, (
                f"Stripped binary ({stripped_size} bytes) should be smaller than original ({original_size} bytes)"
            )

    def test_strip_nonexistent_file_raises_error(self) -> None:
        """Test that stripping a non-existent file raises FileNotFoundError."""
        apple_strip = AppleStrip()

        with pytest.raises(FileNotFoundError, match="Input file not found"):
            apple_strip.strip("/path/to/nonexistent/file")
