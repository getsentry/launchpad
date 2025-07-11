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
        total_install_size = treemap.total_install_size
        assert total_install_size == 9171936
        total_download_size = treemap.total_download_size
        assert total_download_size == 8552372

        # Verify root element
        root = treemap.root
        root_name = root.name
        app_name = results.app_info.name
        assert root_name == app_name
        children_count = len(root.children)
        assert children_count == 14

        # Verify size calculations work
        root_install_size = root.install_size
        assert root_install_size == 9171936
        root_download_size = root.download_size
        assert root_download_size == 8552372
        assert root_download_size <= root_install_size  # Download should be <= install

        # Verify platform
        platform_val = treemap.platform
        assert platform_val == "android"

        # Verify app info
        app_info_name = results.app_info.name
        assert app_info_name == "Hacker News"
        app_info_package_name = results.app_info.package_name
        assert app_info_package_name == "com.emergetools.hackernews"
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
        manifest_install_size = manifest.install_size
        assert manifest_install_size == 20480
        manifest_element_type = manifest.element_type
        assert manifest_element_type == "manifests"

        # Verify classes.dex exists
        dex = find_node_by_path(treemap.root, "Dex")
        assert dex is not None
        dex_install_size = dex.install_size
        assert dex_install_size == 4363232
        dex_element_type = dex.element_type
        assert dex_element_type == "dex"

        # Verify resources.arsc exists
        resources = find_node_by_path(treemap.root, "resources.arsc")
        assert resources is not None
        resources_install_size = resources.install_size
        assert resources_install_size == 94208
        resources_element_type = resources.element_type
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
        total_install_size = treemap.total_install_size
        assert total_install_size == 7218144
        total_download_size = treemap.total_download_size
        assert total_download_size == 6606156

        # Verify root element
        root = treemap.root
        root_name = root.name
        app_name = results.app_info.name
        assert root_name == app_name
        children_count = len(root.children)
        assert children_count == 14

        # Verify size calculations work
        root_install_size = root.install_size
        assert root_install_size == 7218144
        root_download_size = root.download_size
        assert root_download_size == 6606156
        assert root_download_size <= root_install_size  # Download should be <= install

        # Verify platform
        platform_val = treemap.platform
        assert platform_val == "android"

        # Verify app info
        app_info_name = results.app_info.name
        assert app_info_name == "Hacker News"
        app_info_package_name = results.app_info.package_name
        assert app_info_package_name == "com.emergetools.hackernews"
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
        manifest_install_size = manifest.install_size
        assert manifest_install_size == 24576
        manifest_element_type = manifest.element_type
        assert manifest_element_type == "manifests"

        # Verify classes.dex exists
        dex = find_node_by_path(treemap.root, "Dex")
        assert dex is not None
        dex_install_size = dex.install_size
        assert dex_install_size == 4363232
        dex_element_type = dex.element_type
        assert dex_element_type == "dex"

        # Verify resources.arsc exists
        resources = find_node_by_path(treemap.root, "resources.arsc")
        assert resources is not None
        resources_install_size = resources.install_size
        assert resources_install_size == 24576
        resources_element_type = resources.element_type
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
        children_len = len(children)
        assert children_len > 0

        for child in children:
            assert "name" in child
            assert "install_size" in child
            assert "download_size" in child
            assert "is_directory" in child

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
        assert "total_install_size" in treemap_dict
        assert "total_download_size" in treemap_dict
        assert "file_count" in treemap_dict
        assert "category_breakdown" in treemap_dict
        assert "platform" in treemap_dict
        platform_val = treemap_dict["platform"]
        assert platform_val == "android"

        # Verify root structure
        root_data = treemap_dict["root"]
        assert "name" in root_data
        assert "install_size" in root_data
        assert "download_size" in root_data
        assert "is_directory" in root_data
        assert "children" in root_data

        # Verify children have expected structure
        children = root_data["children"]
        children_len = len(children)
        assert children_len > 0

        for child in children:
            assert "name" in child
            assert "install_size" in child
            assert "download_size" in child
            assert "is_directory" in child

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
        total_install_size = treemap.total_install_size
        assert total_install_size > 0
        total_download_size = treemap.total_download_size
        assert total_download_size > 0

        # Verify root element
        root = treemap.root
        root_name = root.name
        app_name = results.app_info.name
        assert root_name == app_name
        children_count = len(root.children)
        assert children_count > 0

        # Verify size calculations work
        root_install_size = root.install_size
        assert root_install_size > 0
        root_download_size = root.download_size
        assert root_download_size > 0
        assert root_download_size <= root_install_size

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
        root_is_directory = treemap.root.is_directory
        assert root_is_directory is True
        root_element_type = treemap.root.element_type
        assert root_element_type is None

        # Verify main executable
        main_exe = find_node_by_path(treemap.root, "HackerNews")
        assert main_exe is not None
        # main_exe_install_size = main_exe.install_size
        # assert main_exe_install_size == 3190648 TODO: fix these values
        # main_exe_download_size = main_exe.download_size
        # assert main_exe_download_size == 3190648
        main_exe_element_type = main_exe.element_type
        assert main_exe_element_type == "executables"
        main_exe_is_directory = main_exe.is_directory
        assert main_exe_is_directory is False

        # Verify main executable sections
        main_exe_sections = {child.name: child for child in main_exe.children}
        has_text = "__text" in main_exe_sections
        assert has_text
        text_install_size = main_exe_sections["__text"].install_size
        assert text_install_size == 154660
        has_objc_classlist = "__objc_classlist" in main_exe_sections
        assert has_objc_classlist
        objc_classlist_install_size = main_exe_sections["__objc_classlist"].install_size
        assert objc_classlist_install_size == 3096
        has_data = "__data" in main_exe_sections
        assert has_data
        data_install_size = main_exe_sections["__data"].install_size
        assert data_install_size == 4541

        # Verify Frameworks directory
        frameworks = find_node_by_path(treemap.root, "Frameworks")
        assert frameworks is not None
        frameworks_element_type = frameworks.element_type
        assert frameworks_element_type == "frameworks"
        frameworks_is_directory = frameworks.is_directory
        assert frameworks_is_directory is True

        # Verify Sentry framework
        sentry = find_node_by_path(treemap.root, "Frameworks/Sentry.framework")
        assert sentry is not None
        sentry_element_type = sentry.element_type
        assert sentry_element_type == "frameworks"
        sentry_is_directory = sentry.is_directory
        assert sentry_is_directory is True

        # Verify Sentry binary
        sentry_binary = find_node_by_path(treemap.root, "Frameworks/Sentry.framework/Sentry")
        assert sentry_binary is not None
        sentry_binary_install_size = sentry_binary.install_size
        assert sentry_binary_install_size == 51456
        sentry_binary_download_size = sentry_binary.download_size
        assert sentry_binary_download_size == 51456
        sentry_binary_element_type = sentry_binary.element_type
        assert sentry_binary_element_type == "executables"

        # Verify Common framework
        common = find_node_by_path(treemap.root, "Frameworks/Common.framework")
        assert common is not None
        common_element_type = common.element_type
        assert common_element_type == "frameworks"
        common_is_directory = common.is_directory
        assert common_is_directory is True

        # Verify Common binary
        common_binary = find_node_by_path(treemap.root, "Frameworks/Common.framework/Common")
        assert common_binary is not None
        # common_binary_install_size = common_binary.install_size
        # assert common_binary_install_size == 199376
        # common_binary_download_size = common_binary.download_size
        # assert common_binary_download_size == 199376
        common_binary_element_type = common_binary.element_type
        assert common_binary_element_type == "executables"

        # Verify Reaper framework
        reaper = find_node_by_path(treemap.root, "Frameworks/Reaper.framework")
        assert reaper is not None
        reaper_element_type = reaper.element_type
        assert reaper_element_type == "frameworks"
        reaper_is_directory = reaper.is_directory
        assert reaper_is_directory is True

        # Verify Reaper binary
        reaper_binary = find_node_by_path(treemap.root, "Frameworks/Reaper.framework/Reaper")
        assert reaper_binary is not None
        # reaper_binary_install_size = reaper_binary.install_size
        # assert reaper_binary_install_size == 51440
        # reaper_binary_download_size = reaper_binary.download_size
        # assert reaper_binary_download_size == 51440
        reaper_binary_element_type = reaper_binary.element_type
        assert reaper_binary_element_type == "executables"

        # Verify PlugIns directory
        plugins = find_node_by_path(treemap.root, "PlugIns")
        assert plugins is not None
        plugins_element_type = plugins.element_type
        assert plugins_element_type == "extensions"
        plugins_is_directory = plugins.is_directory
        assert plugins_is_directory is True

        # Verify HomeWidget extension
        widget = find_node_by_path(treemap.root, "PlugIns/HackerNewsHomeWidgetExtension.appex")
        assert widget is not None
        widget_element_type = widget.element_type
        assert widget_element_type == "extensions"
        widget_is_directory = widget.is_directory
        assert widget_is_directory is True

        # Verify widget binary
        widget_binary = find_node_by_path(
            treemap.root,
            "PlugIns/HackerNewsHomeWidgetExtension.appex/HackerNewsHomeWidgetExtension",
        )
        assert widget_binary is not None
        # widget_binary_install_size = widget_binary.install_size
        # assert widget_binary_install_size == 153016
        # widget_binary_download_size = widget_binary.download_size
        # assert widget_binary_download_size == 153016
        widget_binary_element_type = widget_binary.element_type
        assert widget_binary_element_type == "executables"

        # Verify Assets.car
        assets = find_node_by_path(treemap.root, "Assets.car")
        assert assets is not None
        # assets_install_size = assets.install_size
        # assert assets_install_size == 4788000
        # assets_download_size = assets.download_size
        # assert assets_download_size == 3830400
        assets_element_type = assets.element_type
        assert assets_element_type == "assets"
        assets_children_len = len(assets.children)
        assert assets_children_len == 14

        # Verify category breakdown
        # files_breakdown = treemap.category_breakdown["files"]
        # assert files_breakdown == {
        #     "install": 120000,
        #     "download": 96000,
        # }
        # assets_breakdown = treemap.category_breakdown["assets"]
        # assert assets_breakdown == {
        #     "install": 4840000,
        #     "download": 3872000,
        # }
        # plists_breakdown = treemap.category_breakdown["plists"]
        # assert plists_breakdown == {
        #     "install": 28000,
        #     "download": 22400,
        # }
        # executables_breakdown = treemap.category_breakdown["executables"]
        # assert executables_breakdown == {
        #     "download": 2886400,
        #     "install": 3608000,
        # }
        # fonts_breakdown = treemap.category_breakdown["fonts"]
        # assert fonts_breakdown == {
        #     "download": 854400,
        #     "install": 1068000,
        # }

        # Verify totals
        # total_install_size = treemap.total_install_size
        # assert total_install_size == 13278496
        # total_download_size = treemap.total_download_size
        # assert total_download_size == 12061966
        file_count = treemap.file_count
        assert file_count == 31
        platform_val = treemap.platform
        assert platform_val == "ios"

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
        app_view_model_install_size = app_view_model.install_size
        assert app_view_model_install_size == 25648
        app_view_model_download_size = app_view_model.download_size
        assert app_view_model_download_size == 25648
        app_view_model_element_type = app_view_model.element_type
        assert app_view_model_element_type == "modules"

        app_view_model = find_node_by_name(treemap.root, "SentryUserFeedbackFormViewModel")
        assert app_view_model is not None
        app_view_model_install_size = app_view_model.install_size
        assert app_view_model_install_size == 27620
        app_view_model_download_size = app_view_model.download_size
        assert app_view_model_download_size == 27620
        app_view_model_element_type = app_view_model.element_type
        assert app_view_model_element_type == "modules"
