import tempfile
import zipfile

from pathlib import Path

import pytest

from launchpad.artifacts.providers.zip_provider import (
    UnreasonableZipError,
    UnsafePathError,
    ZipProvider,
    check_reasonable_zip,
    is_safe_path,
)


class TestZipProvider:
    @pytest.fixture
    def malicious_zip(self) -> Path:
        with tempfile.NamedTemporaryFile(suffix=".zip") as temp_file:
            temp_path = Path(temp_file.name)

            with zipfile.ZipFile(temp_path, "w") as zf:
                zf.writestr("normal.txt", "normal content")
                zf.writestr("../../../etc/passwd", "malicious content")

            yield temp_path

    def test_init(self, hackernews_xcarchive: Path) -> None:
        provider = ZipProvider(hackernews_xcarchive)
        assert provider.path == hackernews_xcarchive

    def test_extract_to_temp_directory_ios(self, hackernews_xcarchive: Path) -> None:
        provider = ZipProvider(hackernews_xcarchive)
        temp_dir = provider.extract_to_temp_directory()

        assert temp_dir.exists()
        assert temp_dir.is_dir()
        assert len(provider._temp_dirs) == 1
        assert provider._temp_dirs[0] == temp_dir
        extracted_files = list(temp_dir.rglob("*"))
        assert len(extracted_files) > 0

    def test_extract_to_temp_directory_android(self, zipped_apk: Path) -> None:
        provider = ZipProvider(zipped_apk)
        temp_dir = provider.extract_to_temp_directory()

        assert temp_dir.exists()
        assert temp_dir.is_dir()
        assert len(provider._temp_dirs) == 1

        extracted_files = list(temp_dir.rglob("*"))
        assert len(extracted_files) > 0

    def test_multiple_extractions(self, hackernews_xcarchive: Path) -> None:
        provider = ZipProvider(hackernews_xcarchive)

        temp_dir1 = provider.extract_to_temp_directory()
        temp_dir2 = provider.extract_to_temp_directory()

        assert temp_dir1 != temp_dir2
        assert len(provider._temp_dirs) == 2
        assert temp_dir1 in provider._temp_dirs
        assert temp_dir2 in provider._temp_dirs
        assert temp_dir1.exists()
        assert temp_dir2.exists()

    def test_safe_extract_blocks_traversal(self, malicious_zip: Path) -> None:
        provider = ZipProvider(malicious_zip)

        with pytest.raises(UnsafePathError, match="Potential path traversal attack"):
            provider.extract_to_temp_directory()

    def test_nonexistent_zip_file(self) -> None:
        nonexistent_path = Path("/nonexistent/file.zip")
        provider = ZipProvider(nonexistent_path)

        with pytest.raises(FileNotFoundError):
            provider.extract_to_temp_directory()

    def test_invalid_zip_file(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".zip") as temp_file:
            temp_path = Path(temp_file.name)
            temp_file.write(b"not a zip file")

            provider = ZipProvider(temp_path)

            with pytest.raises(zipfile.BadZipFile):
                provider.extract_to_temp_directory()


class TestIsSafePath:
    def test_valid_paths(self) -> None:
        base_dir = Path("/tmp/test")
        assert is_safe_path(base_dir, "file.txt")
        assert is_safe_path(base_dir, "subdir/file.txt")
        assert is_safe_path(base_dir, "a/b/c/file.txt")

    def test_path_traversal_attempts(self) -> None:
        base_dir = Path("/tmp/test")
        assert not is_safe_path(base_dir, "../file.txt")
        assert not is_safe_path(base_dir, "../../file.txt")
        assert not is_safe_path(base_dir, "../../../etc/passwd")
        assert not is_safe_path(base_dir, "subdir/../../file.txt")

    def test_absolute_paths(self) -> None:
        base_dir = Path("/tmp/test")
        assert not is_safe_path(base_dir, "/etc/passwd")
        assert not is_safe_path(base_dir, "/tmp/other/file.txt")


class TestCheckReasonableZip:
    def test_reasonable_zip_passes(self, hackernews_xcarchive: Path) -> None:
        with zipfile.ZipFile(hackernews_xcarchive, "r") as zf:
            check_reasonable_zip(zf)

    def test_max_file_count(self, hackernews_xcarchive: Path) -> None:
        with zipfile.ZipFile(hackernews_xcarchive, "r") as zf:
            # iOS fixture has 113 files, so limit of 50 should fail
            with pytest.raises(UnreasonableZipError, match="exceeding the limit of 50"):
                check_reasonable_zip(zf, max_file_count=50)

    def test_max_file_size(self, hackernews_xcarchive: Path) -> None:
        with zipfile.ZipFile(hackernews_xcarchive, "r") as zf:
            # iOS fixture is ~32MB uncompressed, so limit of 10MB should fail
            with pytest.raises(UnreasonableZipError, match="exceeding the limit of 10.0MB"):
                check_reasonable_zip(zf, max_uncompressed_size=10 * 1024 * 1024)

    def test_extract_zstd_zip(self) -> None:
        """Test that zstd-compressed zips can be extracted."""
        with tempfile.NamedTemporaryFile(suffix=".zip") as temp_file:
            temp_path = Path(temp_file.name)

            # Create a zstd-compressed zip
            with zipfile.ZipFile(temp_path, "w") as zf:
                zf.writestr("test.txt", "content", zipfile.ZIP_ZSTANDARD)

            try:
                provider = ZipProvider(temp_path)
                temp_dir = provider.extract_to_temp_directory()

                assert temp_dir.exists()
                assert (temp_dir / "test.txt").exists()
                assert (temp_dir / "test.txt").read_text() == "content"
            finally:
                temp_path.unlink(missing_ok=True)
