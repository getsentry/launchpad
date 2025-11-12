"""Integration tests for file analysis using real xcarchive fixtures."""

import time

import pytest

from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive
from launchpad.size.models.common import FileAnalysis
from launchpad.size.models.treemap import TreemapType
from launchpad.size.utils.file_analysis import analyze_apple_files


class TestFileAnalysisIntegration:
    @pytest.fixture
    def hackernews_xcarchive_obj(self, hackernews_xcarchive):
        return ZippedXCArchive(hackernews_xcarchive)

    def test_analyze_hackernews(self, hackernews_xcarchive_obj):
        start = time.time()
        result = analyze_apple_files(hackernews_xcarchive_obj)
        duration = time.time() - start

        assert duration < 1

        assert isinstance(result, FileAnalysis)
        assert len(result.files) == 32
        assert len(result.directories) == 13
        assert len(result.items) == 45
        assert result.total_size == 9728000

        hackernews_file = next(f for f in result.files if f.path == "HackerNews")
        assert hackernews_file.size == 3153920
        assert hackernews_file.file_type == "macho"
        assert hackernews_file.hash == "9d10abfc90f6f027d19d4c990329d6ffc3419a28bd1ab4a9f86344e5a921c263"
        assert hackernews_file.is_dir is False
        assert len(hackernews_file.children) == 0

        asset_catalog_file = next(f for f in result.files if f.path == "Assets.car")
        assert asset_catalog_file.size == 4788224
        assert asset_catalog_file.file_type == "car"
        assert asset_catalog_file.hash == "adf5fdc8ac633ba5840a047c8d77877057f85f822fa70c6690c467b8fb6d6505"
        assert asset_catalog_file.is_dir is False
        assert len(asset_catalog_file.children) == 14

        for child in asset_catalog_file.children:
            assert child.size > 0
            assert child.treemap_type == TreemapType.ASSETS

        for file in result.files:
            assert file.size > 0
            assert file.file_type is not None
            assert file.hash is not None
            assert file.is_dir is False
            if "Assets.car" not in file.path:
                assert len(file.children) == 0

        for directory in result.directories:
            assert directory.size > 0
            assert directory.file_type == "directory"
            assert directory.hash is not None
            assert directory.is_dir is True
            assert len(directory.children) == 0

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
