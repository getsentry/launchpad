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


@pytest.fixture
def sample_ios_zip() -> Path:
    return Path("tests/_fixtures/ios/HackerNews.xcarchive.zip")


@pytest.fixture
def sample_android_zip() -> Path:
    return Path("tests/_fixtures/android/zipped_apk.zip")


class TestZipProvider:
    @pytest.fixture
    def malicious_zip(self) -> Path:
        with tempfile.NamedTemporaryFile(suffix=".zip") as temp_file:
            temp_path = Path(temp_file.name)

            with zipfile.ZipFile(temp_path, "w") as zf:
                zf.writestr("normal.txt", "normal content")
                zf.writestr("../../../etc/passwd", "malicious content")

            yield temp_path

    def test_init(self, sample_ios_zip: Path) -> None:
        provider = ZipProvider(sample_ios_zip)
        assert provider.path == sample_ios_zip

    def test_extract_to_temp_directory_ios(self, sample_ios_zip: Path) -> None:
        provider = ZipProvider(sample_ios_zip)
        temp_dir = provider.extract_to_temp_directory()

        assert temp_dir.exists()
        assert temp_dir.is_dir()
        assert len(provider._temp_dirs) == 1
        assert provider._temp_dirs[0] == temp_dir
        extracted_files = list(temp_dir.rglob("*"))
        assert len(extracted_files) > 0

    def test_extract_to_temp_directory_android(self, sample_android_zip: Path) -> None:
        provider = ZipProvider(sample_android_zip)
        temp_dir = provider.extract_to_temp_directory()

        assert temp_dir.exists()
        assert temp_dir.is_dir()
        assert len(provider._temp_dirs) == 1

        extracted_files = list(temp_dir.rglob("*"))
        assert len(extracted_files) > 0

    def test_multiple_extractions(self, sample_ios_zip: Path) -> None:
        provider = ZipProvider(sample_ios_zip)

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
    def test_reasonable_zip_passes(self, sample_ios_zip: Path) -> None:
        with zipfile.ZipFile(sample_ios_zip, "r") as zf:
            check_reasonable_zip(zf)

    def test_max_file_count(self, sample_ios_zip: Path) -> None:
        with zipfile.ZipFile(sample_ios_zip, "r") as zf:
            # iOS fixture has 113 files, so limit of 50 should fail
            with pytest.raises(UnreasonableZipError, match="exceeding the limit of 50"):
                check_reasonable_zip(zf, max_file_count=50)

    def test_max_file_size(self, sample_ios_zip: Path) -> None:
        with zipfile.ZipFile(sample_ios_zip, "r") as zf:
            # iOS fixture is ~32MB uncompressed, so limit of 10MB should fail
            with pytest.raises(UnreasonableZipError, match="exceeding the limit of 10.0MB"):
                check_reasonable_zip(zf, max_uncompressed_size=10 * 1024 * 1024)
