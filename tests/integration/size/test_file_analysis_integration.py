"""Integration tests for file analysis using real xcarchive fixtures."""

import time

import pytest

from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive
from launchpad.size.models.common import FileAnalysis
from launchpad.size.models.treemap import TreemapType
from launchpad.size.utils.file_analysis import analyze_apple_files


class TestFileAnalysisIntegration:
    """Integration tests using real xcarchive fixtures."""

    @pytest.fixture
    def hackernews_xcarchive_obj(self, hackernews_xcarchive):
        """Create ZippedXCArchive from HackerNews fixture."""
        return ZippedXCArchive(hackernews_xcarchive)

    def test_analyze_hackernews(self, hackernews_xcarchive_obj):
        """Test analysis of a real xcarchive produces expected structure."""

        start = time.time()
        result = analyze_apple_files(hackernews_xcarchive_obj)
        duration = time.time() - start

        assert duration < 1

        assert isinstance(result, FileAnalysis)
        assert len(result.files) == 32
        assert len(result.directories) == 13

        file_paths = {f.path for f in result.files}

        main_binary_files = [f for f in result.files if f.path == "HackerNews"]
        assert len(main_binary_files) == 1
        main_binary = main_binary_files[0]
        assert main_binary.size > 0
        assert main_binary.file_type in ["macho", "executable"]

        assert "Info.plist" in file_paths
        plist_files = [f for f in result.files if f.path == "Info.plist"]
        assert len(plist_files) == 1
        assert plist_files[0].file_type == "plist"

        car_files = [f for f in result.files if f.file_type == "car"]
        assert len(car_files) > 0

        dir_paths = {d.path for d in result.directories}
        assert "" in dir_paths  # root directory
        assert "Frameworks" in dir_paths  # frameworks folder exists

        total_size = sum(f.size for f in result.files)
        assert total_size > 1000  # at least 1KB

        root_dirs = [d for d in result.directories if d.path == ""]
        assert len(root_dirs) == 1
        assert root_dirs[0].size == total_size

        car_files = [f for f in result.files if f.file_type == "car"]
        if car_files:
            car_file = car_files[0]
            for child in car_file.children:
                assert child.path.startswith(car_file.path)
                assert child.size >= 0
                assert child.hash is not None
                assert child.treemap_type == TreemapType.ASSETS

        file_types = {f.file_type for f in result.files}
        assert {
            "plist",
            "png",
            "car",
            "json",
            "strings",
            "macho",
            "executable",
        } & file_types

        framework_dirs = [d for d in result.directories if d.path.endswith(".framework")]
        assert len(framework_dirs) > 0
        if framework_dirs:
            framework_binaries = [
                f.path for f in result.files if ".framework/" in f.path and f.file_type in ["macho", "executable"]
            ]
            assert len(framework_binaries) > 0

            for binary_path in framework_binaries:
                assert ".framework/" in binary_path, f"Framework binary should contain .framework/: {binary_path}"

    def test_analyze_with_max_depth_keeps_sizes(self, hackernews_xcarchive_obj):
        """Depth limiting should omit deep children but preserve parent sizes."""
        baseline = analyze_apple_files(hackernews_xcarchive_obj)
        limited = analyze_apple_files(hackernews_xcarchive_obj, max_depth=2)

        omitted_files = [f for f in limited.files if f.file_type == "directory_omitted"]
        assert omitted_files, "Expected synthetic omitted nodes when max_depth is set"

        base_root = next(d for d in baseline.directories if d.path == "")
        lim_root = next(d for d in limited.directories if d.path == "")
        assert lim_root.size == base_root.size, "Root size must be preserved with max_depth pruning"

    def test_root_dir_hash_deterministic(self, hackernews_xcarchive_obj):
        """Directory hashing should be stable for the same inputs."""
        r1 = analyze_apple_files(hackernews_xcarchive_obj)
        r2 = analyze_apple_files(hackernews_xcarchive_obj)
        d1 = next(d for d in r1.directories if d.path == "")
        d2 = next(d for d in r2.directories if d.path == "")
        assert d1.hash == d2.hash
