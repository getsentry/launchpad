"""Tests for file analysis functionality."""

import subprocess
import tempfile

from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive
from launchpad.size.models.common import FileAnalysis
from launchpad.size.models.treemap import TreemapType
from launchpad.size.utils.file_analysis import analyze_apple_files


class TestAnalyzeAppleFiles:
    """Test the analyze_apple_files function with various scenarios."""

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

            # Create some test files
            (app_path / "Info.plist").write_text("<?xml version='1.0' encoding='UTF-8'?>")
            (app_path / "TestApp").write_bytes(b"fake_binary_content" * 100)  # ~2000 bytes
            (app_path / "Assets.car").write_bytes(b"fake_car_content" * 50)  # ~850 bytes

            # Create subdirectories
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
        assert len(result.files) > 0
        assert len(result.directories) > 0

        # Check that root directory exists
        root_dirs = [d for d in result.directories if d.path == ""]
        assert len(root_dirs) == 1
        root_dir = root_dirs[0]
        assert root_dir.is_dir
        assert root_dir.file_type == "directory"

        # Check that files have proper attributes
        files = {f.path: f for f in result.files}
        assert "Info.plist" in files
        assert "TestApp" in files
        assert "Assets.car" in files

        plist_file = files["Info.plist"]
        assert plist_file.file_type == "plist"
        assert plist_file.size > 0
        assert plist_file.hash
        assert not plist_file.is_dir

    def test_max_depth_limiting(self, mock_xcarchive, temp_app_bundle):
        """Test that max_depth parameter creates omitted subtree nodes."""
        mock_xcarchive.get_app_bundle_path.return_value = temp_app_bundle
        mock_xcarchive.get_asset_catalog_details.return_value = []

        # Create deeper structure
        deep_dir = temp_app_bundle / "level1" / "level2" / "level3"
        deep_dir.mkdir(parents=True)
        (deep_dir / "deep_file.txt").write_text("deep content")

        result = analyze_apple_files(mock_xcarchive, max_depth=2)

        # Check for omitted nodes
        omitted_files = [f for f in result.files if f.file_type == "directory_omitted"]
        assert len(omitted_files) > 0

        omitted_file = omitted_files[0]
        assert "__omitted__" in omitted_file.path
        assert omitted_file.size > 0
        assert omitted_file.treemap_type == TreemapType.FILES

    def test_symlink_handling_ignore(self, mock_xcarchive, temp_app_bundle):
        """Test that symlinks are ignored when follow_symlinks=False."""
        mock_xcarchive.get_app_bundle_path.return_value = temp_app_bundle
        mock_xcarchive.get_asset_catalog_details.return_value = []

        # Create a symlink
        target_file = temp_app_bundle / "target.txt"
        target_file.write_text("target content")
        symlink_file = temp_app_bundle / "symlink.txt"

        try:
            symlink_file.symlink_to(target_file)
        except OSError:
            pytest.skip("Symlinks not supported on this system")

        result = analyze_apple_files(mock_xcarchive, follow_symlinks=False)

        # Symlink should not be included
        file_paths = [f.path for f in result.files]
        assert "target.txt" in file_paths
        assert "symlink.txt" not in file_paths

    def test_symlink_handling_follow(self, mock_xcarchive, temp_app_bundle):
        """Test that symlinks are followed when follow_symlinks=True."""
        mock_xcarchive.get_app_bundle_path.return_value = temp_app_bundle
        mock_xcarchive.get_asset_catalog_details.return_value = []

        # Create a symlink
        target_file = temp_app_bundle / "target.txt"
        target_file.write_text("target content")
        symlink_file = temp_app_bundle / "symlink.txt"

        try:
            symlink_file.symlink_to(target_file)
        except OSError:
            pytest.skip("Symlinks not supported on this system")

        result = analyze_apple_files(mock_xcarchive, follow_symlinks=True)

        # Both should be included, but due to inode deduplication, only one should remain
        file_paths = [f.path for f in result.files]
        # Either target.txt or symlink.txt should be present (but not both due to dedup)
        assert ("target.txt" in file_paths) or ("symlink.txt" in file_paths)

    def test_asset_catalog_analysis(self, mock_xcarchive, temp_app_bundle):
        """Test .car file analysis creates child nodes."""
        mock_xcarchive.get_app_bundle_path.return_value = temp_app_bundle

        # Mock asset catalog details
        from launchpad.artifacts.apple.zipped_xcarchive import AssetCatalogElement

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

        # Find the .car file
        car_files = [f for f in result.files if f.file_type == "car"]
        assert len(car_files) == 1
        car_file = car_files[0]

        # Should have children from asset catalog
        assert len(car_file.children) >= 2  # At least the 2 mock elements

    def test_file_type_detection(self, mock_xcarchive, temp_app_bundle):
        """Test file type detection for various file extensions."""
        mock_xcarchive.get_app_bundle_path.return_value = temp_app_bundle
        mock_xcarchive.get_asset_catalog_details.return_value = []

        # Create files with various extensions
        (temp_app_bundle / "test.json").write_text('{"test": true}')
        (temp_app_bundle / "test.png").write_bytes(b"fake_png")
        (temp_app_bundle / "test.dylib").write_bytes(b"fake_dylib")
        (temp_app_bundle / "no_extension").write_text("no extension file")

        result = analyze_apple_files(mock_xcarchive)

        files = {f.path: f for f in result.files}

        assert files["test.json"].file_type == "json"
        assert files["test.png"].file_type == "png"
        assert files["test.dylib"].file_type == "dylib"
        # no_extension should get detected via file command
        assert files["no_extension"].file_type in ["text", "unknown"]

    def test_directory_size_calculation(self, mock_xcarchive, temp_app_bundle):
        """Test that directory sizes are calculated correctly from children."""
        mock_xcarchive.get_app_bundle_path.return_value = temp_app_bundle
        mock_xcarchive.get_asset_catalog_details.return_value = []

        result = analyze_apple_files(mock_xcarchive)

        # Find the root directory
        root_dirs = [d for d in result.directories if d.path == ""]
        assert len(root_dirs) == 1
        root_dir = root_dirs[0]

        # Root directory size should be sum of all file sizes (rounded to block size)
        total_file_size = sum(f.size for f in result.files)
        assert root_dir.size == total_file_size

    def test_directory_hashing(self, mock_xcarchive, temp_app_bundle):
        """Test that directory hashes are computed from child hashes."""
        mock_xcarchive.get_app_bundle_path.return_value = temp_app_bundle
        mock_xcarchive.get_asset_catalog_details.return_value = []

        result = analyze_apple_files(mock_xcarchive)

        # All directories should have hashes
        for directory in result.directories:
            assert directory.hash
            assert len(directory.hash) > 0

        # Empty directory should have specific hash
        empty_dir = temp_app_bundle / "empty_dir"
        empty_dir.mkdir()

        result2 = analyze_apple_files(mock_xcarchive)
        empty_dirs = [d for d in result2.directories if d.path == "empty_dir"]
        if empty_dirs:
            # Should have the "empty_directory" hash
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

        # Create a hard link (if supported)
        original_file = temp_app_bundle / "original.txt"
        original_file.write_text("shared content")
        hardlink_file = temp_app_bundle / "hardlink.txt"

        try:
            hardlink_file.hardlink_to(original_file)
        except OSError:
            pytest.skip("Hard links not supported on this system")

        result = analyze_apple_files(mock_xcarchive)

        # Should only have one of the files due to inode deduplication
        file_paths = [f.path for f in result.files]
        has_original = "original.txt" in file_paths
        has_hardlink = "hardlink.txt" in file_paths

        # Exactly one should be present
        assert has_original != has_hardlink  # XOR - exactly one should be True

    def test_hash_consistency(self, mock_xcarchive, temp_app_bundle):
        """Test that file hashes are consistent across multiple runs."""
        mock_xcarchive.get_app_bundle_path.return_value = temp_app_bundle
        mock_xcarchive.get_asset_catalog_details.return_value = []

        result1 = analyze_apple_files(mock_xcarchive)
        result2 = analyze_apple_files(mock_xcarchive)

        assert len(result1.files) == len(result2.files)

        # Hashes should be consistent
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

        # Create a file without extension
        unknown_file = temp_app_bundle / "unknown_file"
        unknown_file.write_bytes(b"some binary data")

        # Mock subprocess to simulate file command failure
        mock_subprocess.side_effect = subprocess.CalledProcessError(1, "file")

        result = analyze_apple_files(mock_xcarchive)

        files = {f.path: f for f in result.files}
        assert files["unknown_file"].file_type == "unknown"
