"""Integration tests for treemap generation."""

import json
from pathlib import Path
from typing import cast

import pytest

from launchpad.analyzers.android import AndroidAnalyzer
from launchpad.analyzers.apple import AppleAppAnalyzer
from launchpad.artifacts.artifact import AndroidArtifact, AppleArtifact
from launchpad.artifacts.artifact_factory import ArtifactFactory
from launchpad.models.treemap import TreemapElement


class TestTreemapGeneration:
    """Test treemap generation functionality."""

    @pytest.fixture
    def sample_ios_app_path(self) -> Path:
        """Path to sample iOS app for testing."""
        return Path("tests/_fixtures/ios/HackerNews.xcarchive.zip")

    @pytest.fixture
    def sample_android_apk_path(self) -> Path:
        """Path to sample Android APK for testing."""
        return Path("tests/_fixtures/android/hn.apk")

    @pytest.fixture
    def sample_android_aab_path(self) -> Path:
        """Path to sample Android AAB for testing."""
        return Path("tests/_fixtures/android/hn.aab")

    def test_android_apk_treemap_matches_reference(self, sample_android_apk_path: Path) -> None:
        """Test Android APK treemap generation functionality."""

        analyzer = AndroidAnalyzer()
        artifact = ArtifactFactory.from_path(sample_android_apk_path)

        results = analyzer.analyze(cast(AndroidArtifact, artifact))

        # Verify treemap was generated
        assert results.treemap is not None
        treemap = results.treemap
        assert treemap.file_count == 177
        assert treemap.total_install_size == 9175040
        # assert treemap.total_download_size > 0

        # Verify root element
        root = treemap.root
        assert root.name == results.app_info.name
        assert len(root.children) == 14

        # Verify size calculations work
        assert root.total_install_size == 9175040
        assert root.total_download_size == 9175040
        assert root.total_download_size <= root.total_install_size  # Download should be <= install

        # Verify platform
        assert treemap.platform == "android"

        # Verify app info
        assert results.app_info.name == "Hacker News"
        assert results.app_info.package_name == "com.emergetools.hackernews"
        assert results.app_info.version == "1.0.2"
        assert results.app_info.build == "13"

        # Verify expected file structure
        def find_node_by_path(root: TreemapElement, path: str) -> TreemapElement | None:
            if root.path == path:
                return root
            for child in root.children:
                if result := find_node_by_path(child, path):
                    return result
            return None

        # Verify AndroidManifest.xml exists
        manifest = find_node_by_path(treemap.root, "AndroidManifest.xml")
        assert manifest is not None
        assert manifest.install_size == 20480
        assert manifest.element_type == "manifests"

        # Verify classes.dex exists
        classes_dex = find_node_by_path(treemap.root, "classes.dex")
        assert classes_dex is not None
        assert classes_dex.install_size == 4366336
        assert classes_dex.element_type == "dex_files"

        # Verify resources.arsc exists
        resources = find_node_by_path(treemap.root, "resources.arsc")
        assert resources is not None
        assert resources.install_size == 94208
        assert resources.element_type == "resources"

        # Verify expected totals
        assert treemap.total_install_size == 9175040
        assert treemap.total_download_size == 9175040
        assert treemap.file_count == 177

        # Verify category breakdown exists
        assert "dex_files" in treemap.category_breakdown
        assert "resources" in treemap.category_breakdown
        assert "manifests" in treemap.category_breakdown

    def test_android_aab_treemap_matches_reference(self, sample_android_aab_path: Path) -> None:
        """Test Android AAB treemap generation functionality."""

        analyzer = AndroidAnalyzer()
        artifact = ArtifactFactory.from_path(sample_android_aab_path)

        results = analyzer.analyze(cast(AndroidArtifact, artifact))

        # Verify treemap was generated
        assert results.treemap is not None
        treemap = results.treemap
        assert treemap.file_count == 169
        assert treemap.total_install_size == 7221248
        assert treemap.total_download_size == 7221248

        # Verify root element
        root = treemap.root
        assert root.name == results.app_info.name
        assert len(root.children) == 14

        # Verify size calculations work
        assert root.total_install_size == 7221248
        assert root.total_download_size == 7221248
        assert root.total_download_size <= root.total_install_size  # Download should be <= install

        # Verify platform
        assert treemap.platform == "android"

        # Verify app info
        assert results.app_info.name == "Hacker News"
        assert results.app_info.package_name == "com.emergetools.hackernews"
        assert results.app_info.version == "1.0.2"
        assert results.app_info.build == "13"

        # Verify expected file structure
        def find_node_by_path(root: TreemapElement, path: str) -> TreemapElement | None:
            if root.path == path:
                return root
            for child in root.children:
                if result := find_node_by_path(child, path):
                    return result
            return None

        # Verify AndroidManifest.xml exists
        manifest = find_node_by_path(treemap.root, "AndroidManifest.xml")
        assert manifest is not None
        assert manifest.install_size == 24576
        assert manifest.element_type == "manifests"

        # Verify classes.dex exists
        classes_dex = find_node_by_path(treemap.root, "classes.dex")
        assert classes_dex is not None
        assert classes_dex.install_size == 4366336
        assert classes_dex.element_type == "dex_files"

        # Verify resources.arsc exists
        resources = find_node_by_path(treemap.root, "resources.arsc")
        assert resources is not None
        assert resources.install_size == 24576
        assert resources.element_type == "resources"

        # Verify expected totals
        assert treemap.total_install_size == 7221248
        assert treemap.total_download_size == 7221248
        assert treemap.file_count == 123

        # Verify category breakdown exists
        assert "dex_files" in treemap.category_breakdown
        assert "resources" in treemap.category_breakdown
        assert "manifests" in treemap.category_breakdown

    def test_apple_treemap_json_serialization(self, sample_ios_app_path: Path) -> None:
        """Test that treemap can be serialized to JSON."""

        analyzer = AppleAppAnalyzer(skip_treemap=False)
        artifact = ArtifactFactory.from_path(sample_ios_app_path)

        results = analyzer.analyze(cast(AppleArtifact, artifact))

        # Verify treemap was generated
        assert results.treemap is not None
        treemap = results.treemap

        # Convert treemap to JSON using Pydantic's standard serialization
        treemap_dict = treemap.model_dump()

        # Verify standard Pydantic structure
        assert "root" in treemap_dict
        assert "total_install_size" in treemap_dict
        assert "total_download_size" in treemap_dict
        assert "file_count" in treemap_dict
        assert "category_breakdown" in treemap_dict
        assert "platform" in treemap_dict

        # Verify root structure
        root_data = treemap_dict["root"]
        assert "name" in root_data
        assert "install_size" in root_data
        assert "download_size" in root_data
        assert "is_directory" in root_data
        assert "children" in root_data

        # Verify children have expected structure
        children = root_data["children"]
        assert len(children) > 0

        for child in children:
            assert "name" in child
            assert "install_size" in child
            assert "download_size" in child
            assert "is_directory" in child

        # Test that it's actually serializable to JSON
        json_str = json.dumps(treemap_dict)
        assert len(json_str) > 0

        # Test deserialization works
        parsed = json.loads(json_str)
        assert parsed == treemap_dict

    def test_android_treemap_json_serialization(self, sample_android_apk_path: Path) -> None:
        """Test that Android treemap can be serialized to JSON."""

        analyzer = AndroidAnalyzer()
        artifact = ArtifactFactory.from_path(sample_android_apk_path)

        results = analyzer.analyze(cast(AndroidArtifact, artifact))

        # Verify treemap was generated
        assert results.treemap is not None
        treemap = results.treemap

        # Convert treemap to JSON using Pydantic's standard serialization
        treemap_dict = treemap.model_dump()

        # Verify standard Pydantic structure
        assert "root" in treemap_dict
        assert "total_install_size" in treemap_dict
        assert "total_download_size" in treemap_dict
        assert "file_count" in treemap_dict
        assert "category_breakdown" in treemap_dict
        assert "platform" in treemap_dict
        assert treemap_dict["platform"] == "android"

        # Verify root structure
        root_data = treemap_dict["root"]
        assert "name" in root_data
        assert "install_size" in root_data
        assert "download_size" in root_data
        assert "is_directory" in root_data
        assert "children" in root_data

        # Verify children have expected structure
        children = root_data["children"]
        assert len(children) > 0

        for child in children:
            assert "name" in child
            assert "install_size" in child
            assert "download_size" in child
            assert "is_directory" in child

        # Test that it's actually serializable to JSON
        json_str = json.dumps(treemap_dict)
        assert len(json_str) > 0

        # Test deserialization works
        parsed = json.loads(json_str)
        assert parsed == treemap_dict

    def test_apple_treemap_generation_basic(self, sample_ios_app_path: Path) -> None:
        """Test basic treemap generation functionality."""

        analyzer = AppleAppAnalyzer(skip_treemap=False)
        artifact = ArtifactFactory.from_path(sample_ios_app_path)

        results = analyzer.analyze(cast(AppleArtifact, artifact))

        # Verify treemap was generated
        assert results.treemap is not None
        treemap = results.treemap
        assert treemap.file_count > 0
        assert treemap.total_install_size > 0
        assert treemap.total_download_size > 0

        # Verify root element
        root = treemap.root
        assert root.name == results.app_info.name
        assert len(root.children) > 0

        # Verify size calculations work
        assert root.total_install_size > 0
        assert root.total_download_size > 0
        assert root.total_download_size <= root.total_install_size  # Download should be <= install

    def test_apple_treemap_matches_reference(self, sample_ios_app_path: Path) -> None:
        """Test that treemap structure matches reference report."""

        analyzer = AppleAppAnalyzer(skip_treemap=False)
        artifact = ArtifactFactory.from_path(sample_ios_app_path)

        results = analyzer.analyze(cast(AppleArtifact, artifact))

        # Verify treemap was generated
        assert results.treemap is not None
        treemap = results.treemap

        # Helper function to find a node by path
        def find_node_by_path(root: TreemapElement, path: str) -> TreemapElement | None:
            if root.path == path:
                return root
            for child in root.children:
                if result := find_node_by_path(child, path):
                    return result
            return None

        # Verify root node
        assert treemap.root.name == "HackerNews"
        assert treemap.root.is_directory is True
        assert treemap.root.element_type is None

        # Verify main executable
        main_exe = find_node_by_path(treemap.root, "HackerNews")
        assert main_exe is not None
        assert main_exe.install_size == 3152944
        assert main_exe.download_size == 3152944
        assert main_exe.element_type == "executables"
        assert main_exe.is_directory is True

        # Verify main executable sections
        main_exe_sections = {child.name: child for child in main_exe.children}
        assert "text_segment" in main_exe_sections
        assert main_exe_sections["text_segment"].install_size == 1842548
        assert "objc_classes" in main_exe_sections
        assert main_exe_sections["objc_classes"].install_size == 430336
        assert "data_segment" in main_exe_sections
        assert main_exe_sections["data_segment"].install_size == 114666

        # Verify Frameworks directory
        frameworks = find_node_by_path(treemap.root, "Frameworks")
        assert frameworks is not None
        assert frameworks.element_type == "frameworks"
        assert frameworks.is_directory is True

        # Verify Sentry framework
        sentry = find_node_by_path(treemap.root, "Frameworks/Sentry.framework")
        assert sentry is not None
        assert sentry.element_type == "frameworks"
        assert sentry.is_directory is True

        # Verify Sentry binary
        sentry_binary = find_node_by_path(treemap.root, "Frameworks/Sentry.framework/Sentry")
        assert sentry_binary is not None
        assert sentry_binary.install_size == 51456
        assert sentry_binary.download_size == 51456
        assert sentry_binary.element_type == "executables"

        # Verify Common framework
        common = find_node_by_path(treemap.root, "Frameworks/Common.framework")
        assert common is not None
        assert common.element_type == "frameworks"
        assert common.is_directory is True

        # Verify Common binary
        common_binary = find_node_by_path(treemap.root, "Frameworks/Common.framework/Common")
        assert common_binary is not None
        assert common_binary.install_size == 189840
        assert common_binary.download_size == 189840
        assert common_binary.element_type == "executables"

        # Verify Reaper framework
        reaper = find_node_by_path(treemap.root, "Frameworks/Reaper.framework")
        assert reaper is not None
        assert reaper.element_type == "frameworks"
        assert reaper.is_directory is True

        # Verify Reaper binary
        reaper_binary = find_node_by_path(treemap.root, "Frameworks/Reaper.framework/Reaper")
        assert reaper_binary is not None
        assert reaper_binary.install_size == 51440
        assert reaper_binary.download_size == 51440
        assert reaper_binary.element_type == "executables"

        # Verify PlugIns directory
        plugins = find_node_by_path(treemap.root, "PlugIns")
        assert plugins is not None
        assert plugins.element_type == "extensions"
        assert plugins.is_directory is True

        # Verify HomeWidget extension
        widget = find_node_by_path(treemap.root, "PlugIns/HackerNewsHomeWidgetExtension.appex")
        assert widget is not None
        assert widget.element_type == "extensions"
        assert widget.is_directory is True

        # Verify widget binary
        widget_binary = find_node_by_path(
            treemap.root, "PlugIns/HackerNewsHomeWidgetExtension.appex/HackerNewsHomeWidgetExtension"
        )
        assert widget_binary is not None
        assert widget_binary.install_size == 152288
        assert widget_binary.download_size == 152288
        assert widget_binary.element_type == "executables"

        # Verify Assets.car
        assets = find_node_by_path(treemap.root, "Assets.car")
        assert assets is not None
        assert assets.install_size == 4788224
        assert assets.download_size == 3830579
        assert assets.element_type == "assets"

        # Verify category breakdown
        assert treemap.category_breakdown["files"] == {"install": 122880, "download": 98298}
        assert treemap.category_breakdown["assets"] == {"install": 4841472, "download": 3873176}
        assert treemap.category_breakdown["plists"] == {"install": 28672, "download": 22932}
        assert treemap.category_breakdown["executables"] == {"download": 2886859, "install": 3608576}
        assert treemap.category_breakdown["fonts"] == {"download": 858520, "install": 1073152}

        # Verify totals
        assert treemap.total_install_size == 13278496
        assert treemap.total_download_size == 12061966
        assert treemap.file_count == 32
        assert treemap.platform == "ios"
