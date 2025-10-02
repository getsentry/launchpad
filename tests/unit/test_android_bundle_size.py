import gzip
import random
import tempfile

from pathlib import Path

import pytest

from launchpad.size.utils.android_bundle_size import (
    calculate_apk_download_size,
)


class TestAndroidBundleSize:
    def test_calculate_apk_download_size_with_fixture(self, hn_apk: Path) -> None:
        assert hn_apk.exists(), f"Test APK not found at {hn_apk}"

        download_size = calculate_apk_download_size(hn_apk)
        original_size = hn_apk.stat().st_size

        assert download_size == 3670839
        assert original_size - download_size == 4288082

    def test_calculate_apk_download_size_with_simple_file(self) -> None:
        # Create a test file with some content
        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as temp_file:
            # Create some test data that should compress well
            test_data = b"Hello, World! " * 1000  # Repetitive data that compresses well
            temp_file.write(test_data)
            temp_file_path = Path(temp_file.name)

        try:
            download_size = calculate_apk_download_size(temp_file_path)

            # Verify the download size is smaller than the original (compression worked)
            original_size = len(test_data)
            assert download_size < original_size

            # Verify the compressed data is valid gzip
            with open(temp_file_path, "rb") as f:
                original_data = f.read()
            compressed_data = gzip.compress(original_data, compresslevel=9)
            expected_size = len(compressed_data)
            assert download_size == expected_size

        finally:
            temp_file_path.unlink()

    def test_calculate_apk_download_size_with_random_data(self) -> None:
        # Create a test file with random data
        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as temp_file:
            # Create random data that won't compress well
            random.seed(42)  # For reproducible tests
            test_data = bytes(random.getrandbits(8) for _ in range(1000))
            temp_file.write(test_data)
            temp_file_path = Path(temp_file.name)

        try:
            download_size = calculate_apk_download_size(temp_file_path)

            # For random data, compressed size might be larger due to gzip overhead
            original_size = len(test_data)
            # The compressed size should be reasonable (not much larger than original)
            assert download_size <= original_size + 100  # Allow some overhead

        finally:
            temp_file_path.unlink()

    def test_calculate_apk_download_size_file_not_found(self) -> None:
        non_existent_path = Path("/non/existent/file.apk")

        with pytest.raises(FileNotFoundError):
            calculate_apk_download_size(non_existent_path)

    def test_calculate_apk_download_size_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            with pytest.raises(ValueError, match="Path is not a file"):
                calculate_apk_download_size(temp_path)
