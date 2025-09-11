"""Integration tests for treemap generation."""

import json
import platform

from pathlib import Path
from typing import cast

import pytest

from launchpad.artifacts.artifact import AndroidArtifact, AppleArtifact
from launchpad.artifacts.artifact_factory import ArtifactFactory
from launchpad.size.analyzers.android import AndroidAnalyzer
from launchpad.size.analyzers.apple import AppleAppAnalyzer
from launchpad.size.models.treemap import TreemapElement


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
        treemap = results.treemap
        assert treemap is not None
        file_count = treemap.file_count
        assert file_count == 177
        # install_size = results.install_size
        # assert install_size == 8542503
        # download_size = results.download_size
        # assert download_size == 8542503

        # Verify root element
        root = treemap.root
        root_name = root.name
        app_name = results.app_info.name
        assert root_name == app_name
        children_count = len(root.children)
        assert children_count == 14

        # Verify size calculations work
        root_size = root.size
        assert root_size == 9126880

        # Verify platform
        platform_val = treemap.platform
        assert platform_val == "android"

        # Verify app info
        app_info_name = results.app_info.name
        assert app_info_name == "Hacker News"
        app_info_app_id = results.app_info.app_id
        assert app_info_app_id == "com.emergetools.hackernews"
        app_info_version = results.app_info.version
        assert app_info_version == "1.0.2"
        app_info_build = results.app_info.build
        assert app_info_build == "13"

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
        manifest_size = manifest.size
        assert manifest_size == 20480
        manifest_element_type = manifest.type
        assert manifest_element_type == "manifests"

        # Verify classes.dex exists
        dex = find_node_by_path(treemap.root, "Dex")
        assert dex is not None
        dex_size = dex.size
        assert dex_size == 4363232
        dex_element_type = dex.type
        assert dex_element_type == "dex"

        # Verify resources.arsc exists
        resources = find_node_by_path(treemap.root, "resources.arsc")
        assert resources is not None
        resources_size = resources.size
        assert resources_size == 94208
        resources_element_type = resources.type
        assert resources_element_type == "resources"

        # Verify expected totals
        file_count_check = treemap.file_count
        assert file_count_check == 177

        # Verify category breakdown exists
        category_breakdown = treemap.category_breakdown
        assert "dex" in category_breakdown
        assert "resources" in category_breakdown
        assert "manifests" in category_breakdown

    def test_android_aab_treemap_matches_reference(self, sample_android_aab_path: Path) -> None:
        """Test Android AAB treemap generation functionality."""

        analyzer = AndroidAnalyzer()
        artifact = ArtifactFactory.from_path(sample_android_aab_path)

        results = analyzer.analyze(cast(AndroidArtifact, artifact))

        # Verify treemap was generated
        treemap = results.treemap
        assert treemap is not None
        file_count = treemap.file_count
        assert file_count == 169
        # install_size = results.install_size
        # assert install_size == 6596287
        # download_size = results.download_size
        # assert download_size == 6596287

        # Verify root element
        root = treemap.root
        root_name = root.name
        app_name = results.app_info.name
        assert root_name == app_name
        children_count = len(root.children)
        assert children_count == 14

        # Verify size calculations work
        root_size = root.size
        assert root_size == 7173088

        # Verify platform
        platform_val = treemap.platform
        assert platform_val == "android"

        # Verify app info
        app_info_name = results.app_info.name
        assert app_info_name == "Hacker News"
        app_info_app_id = results.app_info.app_id
        assert app_info_app_id == "com.emergetools.hackernews"
        app_info_version = results.app_info.version
        assert app_info_version == "1.0.2"
        app_info_build = results.app_info.build
        assert app_info_build == "13"

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
        manifest_size = manifest.size
        assert manifest_size == 24576
        manifest_element_type = manifest.type
        assert manifest_element_type == "manifests"

        # Verify classes.dex exists
        dex = find_node_by_path(treemap.root, "Dex")
        assert dex is not None
        dex_size = dex.size
        assert dex_size == 4363232
        dex_element_type = dex.type
        assert dex_element_type == "dex"

        # Verify resources.arsc exists
        resources = find_node_by_path(treemap.root, "resources.arsc")
        assert resources is not None
        resources_size = resources.size
        assert resources_size == 24576
        resources_element_type = resources.type
        assert resources_element_type == "resources"

        # Verify category breakdown exists
        category_breakdown = treemap.category_breakdown
        assert "dex" in category_breakdown
        assert "resources" in category_breakdown
        assert "manifests" in category_breakdown

    def test_apple_treemap_json_serialization(self, sample_ios_app_path: Path) -> None:
        """Test that treemap can be serialized to JSON."""

        analyzer = AppleAppAnalyzer(skip_treemap=False)
        artifact = ArtifactFactory.from_path(sample_ios_app_path)

        results = analyzer.analyze(cast(AppleArtifact, artifact))

        # Verify treemap was generated
        treemap = results.treemap
        assert treemap is not None

        # Convert treemap to JSON using Pydantic's standard serialization
        treemap_dict = treemap.model_dump()

        # Verify standard Pydantic structure
        assert "root" in treemap_dict
        assert "file_count" in treemap_dict
        assert "category_breakdown" in treemap_dict
        assert "platform" in treemap_dict

        # Verify root structure
        root_data = treemap_dict["root"]
        assert "name" in root_data
        assert "size" in root_data
        assert "is_dir" in root_data
        assert "children" in root_data

        # Verify children have expected structure
        children = root_data["children"]
        children_len = len(children)
        assert children_len > 0

        for child in children:
            assert "name" in child
            assert "size" in child
            assert "is_dir" in child

        # Test that it's actually serializable to JSON
        json_str = json.dumps(treemap_dict)
        json_str_len = len(json_str)
        assert json_str_len > 0

        # Test deserialization works
        parsed = json.loads(json_str)
        assert parsed == treemap_dict

    def test_android_treemap_json_serialization(self, sample_android_apk_path: Path) -> None:
        """Test that Android treemap can be serialized to JSON."""

        analyzer = AndroidAnalyzer()
        artifact = ArtifactFactory.from_path(sample_android_apk_path)

        results = analyzer.analyze(cast(AndroidArtifact, artifact))

        # Verify treemap was generated
        treemap = results.treemap
        assert treemap is not None

        # Convert treemap to JSON using Pydantic's standard serialization
        treemap_dict = treemap.model_dump()

        # Verify standard Pydantic structure
        assert "root" in treemap_dict
        assert "file_count" in treemap_dict
        assert "category_breakdown" in treemap_dict
        assert "platform" in treemap_dict
        platform_val = treemap_dict["platform"]
        assert platform_val == "android"

        # Verify root structure
        root_data = treemap_dict["root"]
        assert "name" in root_data
        assert "size" in root_data
        assert "is_dir" in root_data
        assert "children" in root_data

        # Verify children have expected structure
        children = root_data["children"]
        children_len = len(children)
        assert children_len > 0

        for child in children:
            assert "name" in child
            assert "size" in child
            assert "is_dir" in child

        # Test that it's actually serializable to JSON
        json_str = json.dumps(treemap_dict)
        json_str_len = len(json_str)
        assert json_str_len > 0

        # Test deserialization works
        parsed = json.loads(json_str)
        assert parsed == treemap_dict

    def test_apple_treemap_generation_basic(self, sample_ios_app_path: Path) -> None:
        """Test basic treemap generation functionality."""

        analyzer = AppleAppAnalyzer(skip_treemap=False)
        artifact = ArtifactFactory.from_path(sample_ios_app_path)

        results = analyzer.analyze(cast(AppleArtifact, artifact))

        # Verify treemap was generated
        treemap = results.treemap
        assert treemap is not None
        file_count = treemap.file_count
        assert file_count > 0

        # Verify root element
        root = treemap.root
        root_name = root.name
        app_name = results.app_info.name
        assert root_name == app_name
        children_count = len(root.children)
        assert children_count > 0

        # Verify size calculations work
        root_size = root.size
        assert root_size > 0

    def test_apple_treemap_matches_reference(self, sample_ios_app_path: Path) -> None:
        """Test that treemap structure matches reference report."""

        analyzer = AppleAppAnalyzer(skip_treemap=False)
        artifact = ArtifactFactory.from_path(sample_ios_app_path)

        results = analyzer.analyze(cast(AppleArtifact, artifact))

        # Verify treemap was generated
        treemap = results.treemap
        assert treemap is not None

        # Helper function to find a node by path
        def find_node_by_path(root: TreemapElement, path: str) -> TreemapElement | None:
            if root.path == path:
                return root
            for child in root.children:
                if result := find_node_by_path(child, path):
                    return result
            return None

        # Verify root node
        root_name = treemap.root.name
        assert root_name == "HackerNews"
        root_is_dir = treemap.root.is_dir
        assert root_is_dir is True
        root_element_type = treemap.root.type
        assert root_element_type is None

        # Verify main executable
        main_exe = find_node_by_path(treemap.root, "HackerNews")
        assert main_exe is not None
        # main_exe_size = main_exe.size
        # assert main_exe_size == 3190648
        main_exe_element_type = main_exe.type
        assert main_exe_element_type == "executables"
        main_exe_is_dir = main_exe.is_dir
        assert main_exe_is_dir is False

        # Verify main executable sections
        main_exe_sections = {child.name: child for child in main_exe.children}
        has_text = "__TEXT" in main_exe_sections
        assert has_text
        text_size = main_exe_sections["__TEXT"].size
        assert text_size == 732246

        has_data = "__DATA" in main_exe_sections
        assert has_data
        data_size = main_exe_sections["__DATA"].size
        assert data_size == 129704

        has_data_const = "__DATA_CONST" in main_exe_sections
        assert has_data_const
        data_const_size = main_exe_sections["__DATA_CONST"].size
        assert data_const_size == 89880

        has_linkedit = "__LINKEDIT" in main_exe_sections
        assert has_linkedit
        linkedit_size = main_exe_sections["__LINKEDIT"].size
        assert linkedit_size == 269360

        has_hackernews = "HackerNews" in main_exe_sections
        assert has_hackernews
        hackernews_size = main_exe_sections["HackerNews"].size
        assert hackernews_size == 257340

        # Verify Frameworks directory
        frameworks = find_node_by_path(treemap.root, "Frameworks")
        assert frameworks is not None
        frameworks_element_type = frameworks.type
        assert frameworks_element_type == "frameworks"
        frameworks_is_dir = frameworks.is_dir
        assert frameworks_is_dir is True

        # Verify Sentry framework
        sentry = find_node_by_path(treemap.root, "Frameworks/Sentry.framework")
        assert sentry is not None
        sentry_element_type = sentry.type
        assert sentry_element_type == "frameworks"
        sentry_is_dir = sentry.is_dir
        assert sentry_is_dir is True

        # Verify Sentry binary
        sentry_binary = find_node_by_path(treemap.root, "Frameworks/Sentry.framework/Sentry")
        assert sentry_binary is not None
        sentry_binary_size = sentry_binary.size
        assert sentry_binary_size == 53248
        sentry_binary_element_type = sentry_binary.type
        assert sentry_binary_element_type == "executables"

        # Verify Common framework
        common = find_node_by_path(treemap.root, "Frameworks/Common.framework")
        assert common is not None
        common_element_type = common.type
        assert common_element_type == "frameworks"
        common_is_dir = common.is_dir
        assert common_is_dir is True

        # Verify Common binary
        common_binary = find_node_by_path(treemap.root, "Frameworks/Common.framework/Common")
        assert common_binary is not None
        # common_binary_size = common_binary.size
        # assert common_binary_size == 199376
        common_binary_element_type = common_binary.type
        assert common_binary_element_type == "executables"

        # Verify Reaper framework
        reaper = find_node_by_path(treemap.root, "Frameworks/Reaper.framework")
        assert reaper is not None
        reaper_element_type = reaper.type
        assert reaper_element_type == "frameworks"
        reaper_is_dir = reaper.is_dir
        assert reaper_is_dir is True

        # Verify Reaper binary
        reaper_binary = find_node_by_path(treemap.root, "Frameworks/Reaper.framework/Reaper")
        assert reaper_binary is not None
        # reaper_binary_size = reaper_binary.size
        # assert reaper_binary_size == 51440
        reaper_binary_element_type = reaper_binary.type
        assert reaper_binary_element_type == "executables"

        # Verify PlugIns directory
        plugins = find_node_by_path(treemap.root, "PlugIns")
        assert plugins is not None
        plugins_element_type = plugins.type
        assert plugins_element_type == "extensions"
        plugins_is_dir = plugins.is_dir
        assert plugins_is_dir is True

        # Verify HomeWidget extension
        widget = find_node_by_path(treemap.root, "PlugIns/HackerNewsHomeWidgetExtension.appex")
        assert widget is not None
        widget_element_type = widget.type
        assert widget_element_type == "extensions"
        widget_is_dir = widget.is_dir
        assert widget_is_dir is True

        # Verify widget binary
        widget_binary = find_node_by_path(
            treemap.root,
            "PlugIns/HackerNewsHomeWidgetExtension.appex/HackerNewsHomeWidgetExtension",
        )
        assert widget_binary is not None
        # widget_binary_size = widget_binary.size
        # assert widget_binary_size == 153016
        widget_binary_element_type = widget_binary.type
        assert widget_binary_element_type == "executables"

        # Verify Assets.car
        assets = find_node_by_path(treemap.root, "Assets.car")
        assert assets is not None
        assert assets.size == 4788224
        assert assets.type == "assets"
        assert len(assets.children) == 14

        assert treemap.file_count == 32
        assert treemap.platform == "ios"

    @pytest.mark.skipif(platform.system() != "Darwin", reason="CwlDemangle tool only available on macOS")
    def test_apple_treemap_swift_symbols_darwin_only(self, sample_ios_app_path: Path) -> None:
        """Test Swift symbol demangling functionality (Darwin only due to CwlDemangle dependency)."""

        analyzer = AppleAppAnalyzer(skip_treemap=False)
        artifact = ArtifactFactory.from_path(sample_ios_app_path)

        results = analyzer.analyze(cast(AppleArtifact, artifact))

        # Verify treemap was generated
        treemap = results.treemap
        assert treemap is not None

        # Helper function to find a node by name (for Swift types)
        def find_node_by_name(root: TreemapElement, name: str) -> TreemapElement | None:
            if root.name == name:
                return root
            for child in root.children:
                if result := find_node_by_name(child, name):
                    return result
            return None

        app_view_model = find_node_by_name(treemap.root, "AppViewModel")
        assert app_view_model is not None
        app_view_model_size = app_view_model.size
        assert app_view_model_size == 25648
        app_view_model_element_type = app_view_model.type
        assert app_view_model_element_type == "modules"

        app_view_model = find_node_by_name(treemap.root, "SentryUserFeedbackFormViewModel")
        assert app_view_model is not None
        app_view_model_size = app_view_model.size
        assert app_view_model_size == 27620
        app_view_model_element_type = app_view_model.type
        assert app_view_model_element_type == "modules"
