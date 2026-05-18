import tempfile
import zipfile

from pathlib import Path

import pytest

from launchpad.artifacts.providers.exceptions import UnsafePathError
from launchpad.artifacts.providers.safe_directory import SafeDirectory
from launchpad.artifacts.providers.zip_provider import (
    UnreasonableZipError,
    ZipProvider,
    check_reasonable_zip,
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
        safe_dir = provider.extract_to_temp_directory()

        assert isinstance(safe_dir, SafeDirectory)
        assert safe_dir.exists()
        assert safe_dir.is_dir()
        assert len(provider._temp_dirs) == 1
        extracted_files = list(safe_dir.rglob("*"))
        assert len(extracted_files) > 0

    def test_extract_to_temp_directory_android(self, zipped_apk: Path) -> None:
        provider = ZipProvider(zipped_apk)
        safe_dir = provider.extract_to_temp_directory()

        assert isinstance(safe_dir, SafeDirectory)
        assert safe_dir.exists()
        assert safe_dir.is_dir()
        assert len(provider._temp_dirs) == 1

        extracted_files = list(safe_dir.rglob("*"))
        assert len(extracted_files) > 0

    def test_multiple_extractions(self, hackernews_xcarchive: Path) -> None:
        provider = ZipProvider(hackernews_xcarchive)

        safe_dir1 = provider.extract_to_temp_directory()
        safe_dir2 = provider.extract_to_temp_directory()

        assert safe_dir1.path != safe_dir2.path
        assert len(provider._temp_dirs) == 2
        assert safe_dir1.exists()
        assert safe_dir2.exists()

    def test_safe_extract_blocks_traversal(self, malicious_zip: Path) -> None:
        provider = ZipProvider(malicious_zip)

        with pytest.raises(UnsafePathError, match="Path traversal attempt"):
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


class TestSafeDirectory:
    def test_resolve_valid_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            safe_dir = SafeDirectory(Path(tmpdir))
            assert safe_dir.resolve("file.txt") == Path(tmpdir).resolve() / "file.txt"
            assert safe_dir.resolve("subdir/file.txt") == Path(tmpdir).resolve() / "subdir" / "file.txt"

    def test_resolve_rejects_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            safe_dir = SafeDirectory(Path(tmpdir))
            with pytest.raises(UnsafePathError):
                safe_dir.resolve("../file.txt")
            with pytest.raises(UnsafePathError):
                safe_dir.resolve("../../etc/passwd")
            with pytest.raises(UnsafePathError):
                safe_dir.resolve("subdir/../../file.txt")

    def test_resolve_rejects_absolute_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            safe_dir = SafeDirectory(Path(tmpdir))
            with pytest.raises(UnsafePathError):
                safe_dir.resolve("/etc/passwd")

    def test_child_creates_scoped_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            (base / "sub").mkdir()
            safe_dir = SafeDirectory(base)
            child = safe_dir.child("sub")
            assert child.path == base.resolve() / "sub"
            with pytest.raises(UnsafePathError):
                child.resolve("../../etc/passwd")

    def test_path_property(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            safe_dir = SafeDirectory(Path(tmpdir))
            assert safe_dir.path == Path(tmpdir).resolve()

    def test_truediv_delegates_to_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            safe_dir = SafeDirectory(Path(tmpdir))
            result = safe_dir / "subdir" / "file.txt"
            assert result == Path(tmpdir).resolve() / "subdir" / "file.txt"
            assert isinstance(result, Path)

    def test_glob_and_rglob(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            (base / "a.txt").write_text("a")
            (base / "sub").mkdir()
            (base / "sub" / "b.txt").write_text("b")
            safe_dir = SafeDirectory(base)
            assert len(list(safe_dir.glob("*.txt"))) == 1
            assert len(list(safe_dir.rglob("*.txt"))) == 2

    def test_fspath(self) -> None:
        import os

        with tempfile.TemporaryDirectory() as tmpdir:
            safe_dir = SafeDirectory(Path(tmpdir))
            assert os.fspath(safe_dir) == str(Path(tmpdir).resolve())


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
                safe_dir = provider.extract_to_temp_directory()

                assert safe_dir.exists()
                assert (safe_dir / "test.txt").exists()
                assert (safe_dir / "test.txt").read_text() == "content"
            finally:
                temp_path.unlink(missing_ok=True)
