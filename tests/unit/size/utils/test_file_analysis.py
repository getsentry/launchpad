"""Tests for file analysis functionality."""

import subprocess
import tempfile

from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from launchpad.artifacts.apple.zipped_xcarchive import (
    AssetCatalogElement,
    ZippedXCArchive,
)
from launchpad.size.constants import APPLE_FILESYSTEM_BLOCK_SIZE
from launchpad.size.models.common import FileAnalysis
from launchpad.size.models.treemap import TreemapType
from launchpad.size.utils.file_analysis import analyze_apple_files
from launchpad.utils.file_utils import to_nearest_block_size


class TestAnalyzeAppleFiles:
    """Test the analyze_apple_files function with various scenarios."""

    BASE_EXPECTED_FILES = {
        "Info.plist": 38,  # "<?xml version='1.0' encoding='UTF-8'?>"
        "TestApp": 1900,  # len(b"fake_binary_content") == 19; *100
        "Assets.car": 800,  # len(b"fake_car_content") == 16; *50
        "Frameworks/Framework1.framework/Framework1": 1600,  # len(b"framework_binary") == 16; *100
        "Resources/image.png": 260,  # len(b"fake_png_data") == 13; *20
        "Resources/data.json": 16,  # '{"key": "value"}'
    }
    BASE_EXPECTED_DIRS = {
        "",
        "Frameworks",
        "Frameworks/Framework1.framework",
        "Resources",
    }

    @pytest.fixture
    def mock_xcarchive(self):
        """Create a mock ZippedXCArchive for testing."""
        mock = Mock(spec=ZippedXCArchive)
        return mock

    @pytest.fixture
    def temp_app_bundle(self):
        """Create a temporary app bundle structure for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            app_path = Path(temp_dir) / "TestApp.app"
            app_path.mkdir()

            (app_path / "Info.plist").write_text("<?xml version='1.0' encoding='UTF-8'?>")
            (app_path / "TestApp").write_bytes(b"fake_binary_content" * 100)  # 1900 bytes
            (app_path / "Assets.car").write_bytes(b"fake_car_content" * 50)  # 800 bytes

            frameworks_dir = app_path / "Frameworks"
            frameworks_dir.mkdir()
            (frameworks_dir / "Framework1.framework").mkdir()
            (frameworks_dir / "Framework1.framework" / "Framework1").write_bytes(b"framework_binary" * 100)

            resources_dir = app_path / "Resources"
            resources_dir.mkdir()
            (resources_dir / "image.png").write_bytes(b"fake_png_data" * 20)
            (resources_dir / "data.json").write_text('{"key": "value"}')

            yield app_path

    def test_basic_file_analysis(self, mock_xcarchive, temp_app_bundle):
        """Test basic file and directory analysis."""
        mock_xcarchive.get_app_bundle_path.return_value = temp_app_bundle
        mock_xcarchive.get_asset_catalog_details.return_value = []

        result = analyze_apple_files(mock_xcarchive)

        assert isinstance(result, FileAnalysis)

        files = {f.path: f for f in result.files}
        assert set(files.keys()) == set(self.BASE_EXPECTED_FILES.keys())
        assert len(result.files) == len(self.BASE_EXPECTED_FILES)

        directories = {d.path for d in result.directories}
        assert directories == self.BASE_EXPECTED_DIRS
        assert len(result.directories) == len(self.BASE_EXPECTED_DIRS)

        root_dirs = [d for d in result.directories if d.path == ""]
        assert len(root_dirs) == 1
        root_dir = root_dirs[0]
        assert root_dir.is_dir
        assert root_dir.file_type == "directory"

        assert "Info.plist" in files
        assert "TestApp" in files
        assert "Assets.car" in files

        plist_file = files["Info.plist"]
        assert plist_file.file_type == "plist"
        assert plist_file.size == to_nearest_block_size(
            self.BASE_EXPECTED_FILES["Info.plist"], APPLE_FILESYSTEM_BLOCK_SIZE
        )
        assert plist_file.hash
        assert not plist_file.is_dir

        for path, expected_size in self.BASE_EXPECTED_FILES.items():
            assert files[path].size == to_nearest_block_size(expected_size, APPLE_FILESYSTEM_BLOCK_SIZE)

    def test_max_depth_limiting(self, mock_xcarchive, temp_app_bundle):
        """Test that max_depth parameter creates omitted subtree nodes."""
        mock_xcarchive.get_app_bundle_path.return_value = temp_app_bundle
        mock_xcarchive.get_asset_catalog_details.return_value = []

        deep_dir = temp_app_bundle / "level1" / "level2" / "level3"
        deep_dir.mkdir(parents=True)
        (deep_dir / "deep_file.txt").write_text("deep content")

        result = analyze_apple_files(mock_xcarchive, max_depth=2)

        omitted_files = [f for f in result.files if f.file_type == "directory_omitted"]
        assert any(
            ("__omitted__" in f.path)
            and (f.size == to_nearest_block_size(len("deep content".encode("utf-8")), APPLE_FILESYSTEM_BLOCK_SIZE))
            and (f.treemap_type == TreemapType.FILES)
            for f in omitted_files
        )

    def test_symlink_handling_ignore(self, mock_xcarchive, temp_app_bundle):
        """Test that symlinks are ignored when follow_symlinks=False."""
        mock_xcarchive.get_app_bundle_path.return_value = temp_app_bundle
        mock_xcarchive.get_asset_catalog_details.return_value = []

        target_file = temp_app_bundle / "target.txt"
        target_file.write_text("target content")
        symlink_file = temp_app_bundle / "symlink.txt"

        try:
            symlink_file.symlink_to(target_file)
        except OSError:
            pytest.skip("Symlinks not supported on this system")

        result = analyze_apple_files(mock_xcarchive)

        # Symlink should not be included
        file_paths = [f.path for f in result.files]
        assert "target.txt" in file_paths
        assert "symlink.txt" not in file_paths

    def test_asset_catalog_analysis(self, mock_xcarchive, temp_app_bundle):
        """Test .car file analysis creates child nodes."""
        mock_xcarchive.get_app_bundle_path.return_value = temp_app_bundle

        mock_elements = [
            AssetCatalogElement(
                name="AppIcon",
                image_id="app_icon_id",
                size=1024,
                type=1,
                vector=False,
                filename="AppIcon.png",
                full_path=temp_app_bundle / "AppIcon.png",
            ),
            AssetCatalogElement(
                name="LaunchImage",
                image_id="launch_image_id",
                size=2048,
                type=2,
                vector=False,
                filename="LaunchImage.png",
                full_path=temp_app_bundle / "LaunchImage.png",
            ),
        ]
        mock_xcarchive.get_asset_catalog_details.return_value = mock_elements

        result = analyze_apple_files(mock_xcarchive)

        car_files = [f for f in result.files if f.file_type == "car"]
        assert len(car_files) == 1
        car_file = car_files[0]

        assert len(car_file.children) == 3
        assert {c.size for c in car_file.children} == {1024, 2048, 1024}
        assert car_file.size == to_nearest_block_size(
            self.BASE_EXPECTED_FILES["Assets.car"], APPLE_FILESYSTEM_BLOCK_SIZE
        )

    def test_file_type_detection(self, mock_xcarchive, temp_app_bundle):
        """Test file type detection for various file extensions."""
        mock_xcarchive.get_app_bundle_path.return_value = temp_app_bundle
        mock_xcarchive.get_asset_catalog_details.return_value = []

        (temp_app_bundle / "test.json").write_text('{"test": true}')
        (temp_app_bundle / "test.png").write_bytes(b"fake_png")
        (temp_app_bundle / "test.dylib").write_bytes(b"fake_dylib")
        (temp_app_bundle / "no_extension").write_text("no extension file")

        result = analyze_apple_files(mock_xcarchive)

        files = {f.path: f for f in result.files}

        assert files["test.json"].file_type == "json"
        assert files["test.png"].file_type == "png"
        assert files["test.dylib"].file_type == "dylib"
        assert files["no_extension"].file_type in ["text", "unknown"]

    def test_directory_size_calculation(self, mock_xcarchive, temp_app_bundle):
        """Test that directory sizes are calculated correctly from children."""
        mock_xcarchive.get_app_bundle_path.return_value = temp_app_bundle
        mock_xcarchive.get_asset_catalog_details.return_value = []

        result = analyze_apple_files(mock_xcarchive)

        root_dirs = [d for d in result.directories if d.path == ""]
        assert len(root_dirs) == 1
        root_dir = root_dirs[0]

        # Root directory size should be sum of all file sizes
        assert root_dir.size == sum(
            to_nearest_block_size(size, APPLE_FILESYSTEM_BLOCK_SIZE) for size in self.BASE_EXPECTED_FILES.values()
        )

    def test_directory_hashing(self, mock_xcarchive, temp_app_bundle):
        """Test that directory hashes are computed from child hashes."""
        mock_xcarchive.get_app_bundle_path.return_value = temp_app_bundle
        mock_xcarchive.get_asset_catalog_details.return_value = []

        result = analyze_apple_files(mock_xcarchive)

        # All directories should have hashes
        for directory in result.directories:
            assert directory.hash
            assert len(directory.hash) > 0

        empty_dir = temp_app_bundle / "empty_dir"
        empty_dir.mkdir()

        result2 = analyze_apple_files(mock_xcarchive)
        empty_dirs = [d for d in result2.directories if d.path == "empty_dir"]
        if empty_dirs:
            assert empty_dirs[0].hash

    @patch("os.walk")
    def test_os_error_handling(self, mock_walk, mock_xcarchive, temp_app_bundle):
        """Test handling of OSError during file system traversal."""
        mock_xcarchive.get_app_bundle_path.return_value = temp_app_bundle
        mock_xcarchive.get_asset_catalog_details.return_value = []

        # Mock os.walk to raise OSError for some paths
        def walk_side_effect(path, **kwargs):
            if "problematic" in str(path):
                raise OSError("Permission denied")
            return [(str(temp_app_bundle), ["subdir"], ["file.txt"])]

        mock_walk.side_effect = walk_side_effect

        # Should not raise an exception
        result = analyze_apple_files(mock_xcarchive)
        assert isinstance(result, FileAnalysis)

    def test_inode_deduplication(self, mock_xcarchive, temp_app_bundle):
        """Test that files with same inode are deduplicated."""
        mock_xcarchive.get_app_bundle_path.return_value = temp_app_bundle
        mock_xcarchive.get_asset_catalog_details.return_value = []

        original_file = temp_app_bundle / "original.txt"
        original_file.write_text("shared content")
        hardlink_file = temp_app_bundle / "hardlink.txt"

        try:
            hardlink_file.hardlink_to(original_file)
        except OSError:
            pytest.skip("Hard links not supported on this system")

        result = analyze_apple_files(mock_xcarchive)

        file_paths = [f.path for f in result.files]
        has_original = "original.txt" in file_paths
        has_hardlink = "hardlink.txt" in file_paths

        assert has_original != has_hardlink

    def test_hash_consistency(self, mock_xcarchive, temp_app_bundle):
        """Test that file hashes are consistent across multiple runs."""
        mock_xcarchive.get_app_bundle_path.return_value = temp_app_bundle
        mock_xcarchive.get_asset_catalog_details.return_value = []

        result1 = analyze_apple_files(mock_xcarchive)
        result2 = analyze_apple_files(mock_xcarchive)

        assert len(result1.files) == len(result2.files)

        files1 = {f.path: f for f in result1.files}
        files2 = {f.path: f for f in result2.files}

        for path in files1:
            if path in files2:
                assert files1[path].hash == files2[path].hash

    def test_empty_bundle(self, mock_xcarchive):
        """Test analysis of an empty app bundle."""
        with tempfile.TemporaryDirectory() as temp_dir:
            empty_bundle = Path(temp_dir) / "Empty.app"
            empty_bundle.mkdir()

            mock_xcarchive.get_app_bundle_path.return_value = empty_bundle
            mock_xcarchive.get_asset_catalog_details.return_value = []

            result = analyze_apple_files(mock_xcarchive)

            assert isinstance(result, FileAnalysis)
            assert len(result.files) == 0
            # Should still have root directory
            assert len(result.directories) == 1
            root_dir = result.directories[0]
            assert root_dir.path == ""
            assert root_dir.size == 0

    @patch("subprocess.run")
    def test_file_type_detection_fallback(self, mock_subprocess, mock_xcarchive, temp_app_bundle):
        """Test file type detection fallback when file command fails."""
        mock_xcarchive.get_app_bundle_path.return_value = temp_app_bundle
        mock_xcarchive.get_asset_catalog_details.return_value = []

        unknown_file = temp_app_bundle / "unknown_file"
        unknown_file.write_bytes(b"some binary data")

        mock_subprocess.side_effect = subprocess.CalledProcessError(1, "file")

        result = analyze_apple_files(mock_xcarchive)

        files = {f.path: f for f in result.files}
        assert files["unknown_file"].file_type == "unknown"
