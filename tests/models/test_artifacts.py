"""Tests for artifact models."""

import pytest
from launchpad.models.artifacts import (
    AndroidSpecificArtifacts,
    ArtifactCollection,
    ArtifactType,
    AssetCatalog,
    BaseArtifact,
    BinaryArtifact,
    CompressionType,
    FrameworkArtifact,
    IOSSpecificArtifacts,
    LocalizationArtifact,
    MetadataArtifact,
    ResourceArtifact,
    ResourceType,
    SizeBreakdown,
)


class TestBaseArtifact:
    """Test BaseArtifact model."""

    def test_create_base_artifact(self):
        """Test creating a base artifact."""
        artifact = BaseArtifact(
            path="lib/libexample.a",
            size=1024 * 1024,  # 1MB
            compressed_size=512 * 1024,  # 512KB
            artifact_type=ArtifactType.LIBRARY,
            hash_sha256="abc123",
            compression=CompressionType.GZIP,
        )
        
        assert artifact.path == "lib/libexample.a"
        assert artifact.size == 1024 * 1024
        assert artifact.compressed_size == 512 * 1024
        assert artifact.artifact_type == ArtifactType.LIBRARY
        assert artifact.hash_sha256 == "abc123"
        assert artifact.compression == CompressionType.GZIP
        
    def test_compression_ratio(self):
        """Test compression ratio calculation."""
        artifact = BaseArtifact(
            path="test.bin",
            size=1000,
            compressed_size=300,
            artifact_type=ArtifactType.BINARY,
        )
        
        assert artifact.compression_ratio == pytest.approx(0.7)
        
    def test_compression_ratio_none(self):
        """Test compression ratio when no compressed size."""
        artifact = BaseArtifact(
            path="test.bin",
            size=1000,
            artifact_type=ArtifactType.BINARY,
        )
        
        assert artifact.compression_ratio is None


class TestBinaryArtifact:
    """Test BinaryArtifact model."""

    def test_create_binary_artifact(self):
        """Test creating a binary artifact."""
        binary = BinaryArtifact(
            path="Frameworks/MyApp",
            size=5 * 1024 * 1024,  # 5MB
            architectures=["arm64", "x86_64"],
            is_encrypted=True,
            is_stripped=False,
            linked_libraries=["libSystem.dylib", "libSwift.dylib"],
            exported_symbols=1500,
            imported_symbols=3000,
            sections={
                "__TEXT": 2 * 1024 * 1024,
                "__DATA": 1 * 1024 * 1024,
                "__LINKEDIT": 2 * 1024 * 1024,
            },
        )
        
        assert binary.artifact_type == ArtifactType.BINARY
        assert binary.architectures == ["arm64", "x86_64"]
        assert binary.is_encrypted is True
        assert binary.is_stripped is False
        assert len(binary.linked_libraries) == 2
        assert binary.exported_symbols == 1500
        assert binary.imported_symbols == 3000
        assert len(binary.sections) == 3


class TestFrameworkArtifact:
    """Test FrameworkArtifact model."""

    def test_create_framework_artifact(self):
        """Test creating a framework artifact."""
        framework = FrameworkArtifact(
            path="Frameworks/Alamofire.framework",
            size=10 * 1024 * 1024,  # 10MB
            name="Alamofire",
            version="5.6.1",
            is_dynamic=True,
            is_system=False,
            bundle_id="com.alamofire.Alamofire",
        )
        
        assert framework.artifact_type == ArtifactType.FRAMEWORK
        assert framework.name == "Alamofire"
        assert framework.version == "5.6.1"
        assert framework.is_dynamic is True
        assert framework.is_system is False
        assert framework.bundle_id == "com.alamofire.Alamofire"


class TestResourceArtifact:
    """Test ResourceArtifact model."""

    def test_create_image_resource(self):
        """Test creating an image resource artifact."""
        image = ResourceArtifact(
            path="Assets.xcassets/AppIcon.appiconset/icon-1024.png",
            size=256 * 1024,  # 256KB
            resource_type=ResourceType.IMAGE,
            dimensions={"width": 1024, "height": 1024},
            encoding="PNG",
        )
        
        assert image.artifact_type == ArtifactType.RESOURCE
        assert image.resource_type == ResourceType.IMAGE
        assert image.dimensions["width"] == 1024
        assert image.dimensions["height"] == 1024
        assert image.encoding == "PNG"
        
    def test_create_video_resource(self):
        """Test creating a video resource artifact."""
        video = ResourceArtifact(
            path="Resources/intro.mp4",
            size=5 * 1024 * 1024,  # 5MB
            resource_type=ResourceType.VIDEO,
            dimensions={"width": 1920, "height": 1080},
            duration=30.5,
            encoding="H.264",
        )
        
        assert video.resource_type == ResourceType.VIDEO
        assert video.duration == 30.5
        assert video.encoding == "H.264"


class TestLocalizationArtifact:
    """Test LocalizationArtifact model."""

    def test_create_localization_artifact(self):
        """Test creating a localization artifact."""
        localization = LocalizationArtifact(
            path="en.lproj/Localizable.strings",
            size=10 * 1024,  # 10KB
            language="en",
            region="US",
            string_count=150,
            resource_type="strings",
        )
        
        assert localization.artifact_type == ArtifactType.LOCALIZATION
        assert localization.language == "en"
        assert localization.region == "US"
        assert localization.string_count == 150


class TestAssetCatalog:
    """Test AssetCatalog model."""

    def test_create_asset_catalog(self):
        """Test creating an asset catalog."""
        assets = [
            ResourceArtifact(
                path="icon.png",
                size=100 * 1024,
                resource_type=ResourceType.IMAGE,
            ),
            ResourceArtifact(
                path="logo.png",
                size=200 * 1024,
                resource_type=ResourceType.IMAGE,
            ),
        ]
        
        catalog = AssetCatalog(
            name="Assets.xcassets",
            path="MyApp/Assets.xcassets",
            total_size=300 * 1024,
            asset_count=2,
            assets=assets,
        )
        
        assert catalog.name == "Assets.xcassets"
        assert catalog.total_size == 300 * 1024
        assert catalog.asset_count == 2
        assert len(catalog.assets) == 2
        assert catalog.average_asset_size == 150 * 1024


class TestArtifactCollection:
    """Test ArtifactCollection model."""

    def test_artifact_collection(self):
        """Test artifact collection functionality."""
        collection = ArtifactCollection(
            binaries=[
                BinaryArtifact(
                    path="MyApp",
                    size=5 * 1024 * 1024,
                    architectures=["arm64"],
                ),
            ],
            frameworks=[
                FrameworkArtifact(
                    path="UIKit.framework",
                    size=10 * 1024 * 1024,
                    name="UIKit",
                    is_system=True,
                ),
            ],
            resources=[
                ResourceArtifact(
                    path="image.png",
                    size=100 * 1024,
                    resource_type=ResourceType.IMAGE,
                ),
                ResourceArtifact(
                    path="sound.mp3",
                    size=200 * 1024,
                    resource_type=ResourceType.AUDIO,
                ),
            ],
        )
        
        assert collection.total_count == 4
        assert collection.total_size == (5 + 10) * 1024 * 1024 + 300 * 1024
        
        binaries = collection.get_by_type(ArtifactType.BINARY)
        assert len(binaries) == 1
        assert binaries[0].path == "MyApp"


class TestSizeBreakdown:
    """Test SizeBreakdown model."""

    def test_size_breakdown(self):
        """Test size breakdown functionality."""
        items = [
            BaseArtifact(
                path="file1.bin",
                size=100,
                artifact_type=ArtifactType.BINARY,
            ),
            BaseArtifact(
                path="file2.bin",
                size=200,
                artifact_type=ArtifactType.BINARY,
            ),
        ]
        
        breakdown = SizeBreakdown(
            category="Binaries",
            size=300,
            percentage=30.0,
            items=items,
        )
        
        assert breakdown.category == "Binaries"
        assert breakdown.size == 300
        assert breakdown.percentage == 30.0
        assert breakdown.item_count == 2
        
    def test_nested_size_breakdown(self):
        """Test nested size breakdown."""
        sub_breakdown = SizeBreakdown(
            category="Images",
            size=100,
            percentage=10.0,
            items=[],
        )
        
        main_breakdown = SizeBreakdown(
            category="Resources",
            size=1000,
            percentage=50.0,
            items=[sub_breakdown],
        )
        
        assert main_breakdown.item_count == 1
        assert isinstance(main_breakdown.items[0], SizeBreakdown)


class TestPlatformSpecificArtifacts:
    """Test platform-specific artifact collections."""

    def test_ios_specific_artifacts(self):
        """Test iOS-specific artifacts."""
        ios_artifacts = IOSSpecificArtifacts(
            asset_catalogs=[
                AssetCatalog(
                    name="Assets.xcassets",
                    path="MyApp/Assets.xcassets",
                    total_size=1024 * 1024,
                    asset_count=10,
                ),
            ],
            storyboards=[
                ResourceArtifact(
                    path="Main.storyboard",
                    size=50 * 1024,
                    resource_type=ResourceType.STORYBOARD,
                ),
            ],
            metal_libraries=[
                BinaryArtifact(
                    path="default.metallib",
                    size=100 * 1024,
                    architectures=["air64"],
                ),
            ],
        )
        
        assert len(ios_artifacts.asset_catalogs) == 1
        assert len(ios_artifacts.storyboards) == 1
        assert len(ios_artifacts.metal_libraries) == 1
        
    def test_android_specific_artifacts(self):
        """Test Android-specific artifacts."""
        android_artifacts = AndroidSpecificArtifacts(
            dex_files=[
                BinaryArtifact(
                    path="classes.dex",
                    size=2 * 1024 * 1024,
                    architectures=["dalvik"],
                ),
            ],
            native_libraries={
                "arm64-v8a": [
                    BinaryArtifact(
                        path="libnative.so",
                        size=500 * 1024,
                        architectures=["arm64"],
                    ),
                ],
                "x86_64": [
                    BinaryArtifact(
                        path="libnative.so",
                        size=600 * 1024,
                        architectures=["x86_64"],
                    ),
                ],
            },
            manifest=MetadataArtifact(
                path="AndroidManifest.xml",
                size=10 * 1024,
                format="xml",
                purpose="Android app manifest",
            ),
        )
        
        assert len(android_artifacts.dex_files) == 1
        assert len(android_artifacts.native_libraries) == 2
        assert android_artifacts.manifest is not None
        assert android_artifacts.manifest.format == "xml"