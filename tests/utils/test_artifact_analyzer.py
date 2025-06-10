"""Tests for artifact analyzer utility."""

import pytest
from launchpad.models.artifacts import (
    ArtifactCollection,
    ArtifactType,
    BaseArtifact,
    BinaryArtifact,
    CompressionType,
    FrameworkArtifact,
    LocalizationArtifact,
    MetadataArtifact,
    ResourceArtifact,
    ResourceType,
    SizeBreakdown,
)
from launchpad.utils.artifact_analyzer import ArtifactAnalyzer


class TestArtifactAnalyzer:
    """Test ArtifactAnalyzer functionality."""

    def test_detect_artifact_type(self):
        """Test artifact type detection."""
        test_cases = [
            ("libexample.a", ArtifactType.LIBRARY),
            ("libtest.so", ArtifactType.LIBRARY),
            ("MyApp.exe", ArtifactType.BINARY),
            ("UIKit.framework", ArtifactType.FRAMEWORK),
            ("icon.png", ArtifactType.RESOURCE),
            ("Localizable.strings", ArtifactType.LOCALIZATION),
            ("Info.plist", ArtifactType.METADATA),
            ("script.py", ArtifactType.SCRIPT),
            ("unknown.xyz", ArtifactType.OTHER),
        ]
        
        for path, expected_type in test_cases:
            assert ArtifactAnalyzer.detect_artifact_type(path) == expected_type
            
    def test_detect_resource_type(self):
        """Test resource type detection."""
        test_cases = [
            ("image.png", ResourceType.IMAGE),
            ("video.mp4", ResourceType.VIDEO),
            ("audio.mp3", ResourceType.AUDIO),
            ("font.ttf", ResourceType.FONT),
            ("Main.storyboard", ResourceType.STORYBOARD),
            ("data.json", ResourceType.JSON),
            ("unknown.xyz", ResourceType.OTHER),
        ]
        
        for path, expected_type in test_cases:
            assert ArtifactAnalyzer.detect_resource_type(path) == expected_type
            
    def test_detect_compression(self):
        """Test compression detection."""
        test_cases = [
            (b"\x1f\x8b\x08\x00", CompressionType.GZIP),
            (b"\x78\x9c\x00\x00", CompressionType.ZLIB),
            (b"\xfd\x37\x7a\x00", CompressionType.LZMA),
            (b"\x28\xb5\x2f\xfd", CompressionType.ZSTD),
            (b"NORMAL", CompressionType.NONE),
            (b"", CompressionType.NONE),
        ]
        
        for data, expected_compression in test_cases:
            assert ArtifactAnalyzer.detect_compression(data) == expected_compression
            
    def test_group_artifacts_by_type(self):
        """Test grouping artifacts by type."""
        artifacts = [
            BinaryArtifact(
                path="MyApp",
                size=1000,
                architectures=["arm64"],
            ),
            FrameworkArtifact(
                path="UIKit.framework",
                size=2000,
                name="UIKit",
            ),
            ResourceArtifact(
                path="icon.png",
                size=300,
                resource_type=ResourceType.IMAGE,
            ),
            LocalizationArtifact(
                path="en.lproj/Localizable.strings",
                size=100,
                language="en",
            ),
            MetadataArtifact(
                path="Info.plist",
                size=50,
                format="plist",
                purpose="App metadata",
            ),
            BaseArtifact(
                path="other.file",
                size=25,
                artifact_type=ArtifactType.OTHER,
            ),
        ]
        
        collection = ArtifactAnalyzer.group_artifacts_by_type(artifacts)
        
        assert len(collection.binaries) == 1
        assert len(collection.frameworks) == 1
        assert len(collection.resources) == 1
        assert len(collection.localizations) == 1
        assert len(collection.metadata) == 1
        assert len(collection.other) == 1
        assert collection.total_count == 6
        assert collection.total_size == 3475
        
    def test_create_size_breakdown_by_type(self):
        """Test creating size breakdown by type."""
        artifacts = [
            BaseArtifact(path="bin1", size=1000, artifact_type=ArtifactType.BINARY),
            BaseArtifact(path="bin2", size=2000, artifact_type=ArtifactType.BINARY),
            BaseArtifact(path="res1", size=500, artifact_type=ArtifactType.RESOURCE),
            BaseArtifact(path="small", size=10, artifact_type=ArtifactType.OTHER),
        ]
        
        breakdowns = ArtifactAnalyzer.create_size_breakdown(
            artifacts, group_by="type", min_percentage=10.0
        )
        
        assert len(breakdowns) == 2  # Binary and Resource (Other is too small)
        
        binary_breakdown = next(b for b in breakdowns if b.category == "binary")
        assert binary_breakdown.size == 3000
        assert binary_breakdown.percentage == pytest.approx(85.47, rel=0.01)
        assert binary_breakdown.item_count == 2
        
        resource_breakdown = next(b for b in breakdowns if b.category == "resource")
        assert resource_breakdown.size == 500
        assert resource_breakdown.percentage == pytest.approx(14.25, rel=0.01)
        
    def test_create_size_breakdown_by_extension(self):
        """Test creating size breakdown by extension."""
        artifacts = [
            BaseArtifact(path="file1.png", size=1000, artifact_type=ArtifactType.RESOURCE),
            BaseArtifact(path="file2.png", size=500, artifact_type=ArtifactType.RESOURCE),
            BaseArtifact(path="file.mp4", size=2000, artifact_type=ArtifactType.RESOURCE),
            BaseArtifact(path="noext", size=100, artifact_type=ArtifactType.OTHER),
        ]
        
        breakdowns = ArtifactAnalyzer.create_size_breakdown(
            artifacts, group_by="extension", min_percentage=1.0
        )
        
        assert len(breakdowns) == 3
        
        png_breakdown = next(b for b in breakdowns if b.category == ".png")
        assert png_breakdown.size == 1500
        assert png_breakdown.item_count == 2
        
        mp4_breakdown = next(b for b in breakdowns if b.category == ".mp4")
        assert mp4_breakdown.size == 2000
        assert mp4_breakdown.item_count == 1
        
    def test_create_size_breakdown_with_other(self):
        """Test size breakdown includes 'Other' category for small items."""
        artifacts = [
            BaseArtifact(path="big", size=9000, artifact_type=ArtifactType.BINARY),
            BaseArtifact(path="small1", size=50, artifact_type=ArtifactType.OTHER),
            BaseArtifact(path="small2", size=50, artifact_type=ArtifactType.CONFIG),
        ]
        
        breakdowns = ArtifactAnalyzer.create_size_breakdown(
            artifacts, group_by="type", min_percentage=10.0
        )
        
        assert len(breakdowns) == 2
        
        # Big item
        binary_breakdown = next(b for b in breakdowns if b.category == "binary")
        assert binary_breakdown.size == 9000
        
        # Other category for small items
        other_breakdown = next(b for b in breakdowns if b.category == "Other")
        assert other_breakdown.size == 100
        assert other_breakdown.item_count == 2
        
    def test_find_duplicate_artifacts_by_hash(self):
        """Test finding duplicate artifacts by hash."""
        artifacts = [
            BaseArtifact(
                path="file1.txt",
                size=100,
                artifact_type=ArtifactType.OTHER,
                hash_sha256="abc123",
            ),
            BaseArtifact(
                path="file2.txt",
                size=100,
                artifact_type=ArtifactType.OTHER,
                hash_sha256="abc123",
            ),
            BaseArtifact(
                path="file3.txt",
                size=200,
                artifact_type=ArtifactType.OTHER,
                hash_sha256="def456",
            ),
            BaseArtifact(
                path="file4.txt",
                size=100,
                artifact_type=ArtifactType.OTHER,
                hash_sha256="abc123",
            ),
        ]
        
        duplicates = ArtifactAnalyzer.find_duplicate_artifacts(artifacts, by_hash=True)
        
        assert len(duplicates) == 1
        assert len(duplicates[0]) == 3  # Three files with same hash
        assert all(a.hash_sha256 == "abc123" for a in duplicates[0])
        
    def test_find_duplicate_artifacts_by_size_and_name(self):
        """Test finding duplicate artifacts by size and name."""
        artifacts = [
            BaseArtifact(path="dir1/same.txt", size=100, artifact_type=ArtifactType.OTHER),
            BaseArtifact(path="dir2/same.txt", size=100, artifact_type=ArtifactType.OTHER),
            BaseArtifact(path="dir3/same.txt", size=200, artifact_type=ArtifactType.OTHER),
            BaseArtifact(path="dir4/different.txt", size=100, artifact_type=ArtifactType.OTHER),
        ]
        
        duplicates = ArtifactAnalyzer.find_duplicate_artifacts(artifacts, by_hash=False)
        
        assert len(duplicates) == 1
        assert len(duplicates[0]) == 2  # Two files with same name and size
        
    def test_estimate_download_size(self):
        """Test download size estimation."""
        artifacts = [
            # Already compressed
            BaseArtifact(
                path="compressed.gz",
                size=1000,
                artifact_type=ArtifactType.OTHER,
                compression=CompressionType.GZIP,
            ),
            # Has compressed size
            BaseArtifact(
                path="with_compressed",
                size=2000,
                compressed_size=800,
                artifact_type=ArtifactType.OTHER,
            ),
            # Needs compression estimate
            BaseArtifact(
                path="uncompressed",
                size=3000,
                artifact_type=ArtifactType.OTHER,
                compression=CompressionType.NONE,
            ),
        ]
        
        # Default 30% compression ratio
        download_size = ArtifactAnalyzer.estimate_download_size(artifacts)
        
        expected = 1000 + 800 + (3000 * 0.7)  # 1000 + 800 + 2100 = 3900
        assert download_size == 3900
        
    def test_estimate_download_size_custom_ratio(self):
        """Test download size estimation with custom compression ratio."""
        artifacts = [
            BaseArtifact(
                path="uncompressed",
                size=1000,
                artifact_type=ArtifactType.OTHER,
                compression=CompressionType.NONE,
            ),
        ]
        
        # 50% compression ratio
        download_size = ArtifactAnalyzer.estimate_download_size(
            artifacts, compression_ratio=0.5
        )
        
        assert download_size == 500