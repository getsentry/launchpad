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

    def test_android_apk_treemap_matches_reference(self, hn_apk: Path) -> None:
        """Test Android APK treemap generation functionality."""

        analyzer = AndroidAnalyzer()
        artifact = ArtifactFactory.from_path(hn_apk)

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
        assert root_size == 7886041

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
        assert dex_size == 3122393
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

    def test_android_aab_treemap_matches_reference(self, hn_aab: Path) -> None:
        """Test Android AAB treemap generation functionality."""

        analyzer = AndroidAnalyzer()
        artifact = ArtifactFactory.from_path(hn_aab)

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
        assert root_size == 5932249

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
        assert dex_size == 3122393
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

    def test_apple_treemap_json_serialization(self, hackernews_xcarchive: Path) -> None:
        """Test that treemap can be serialized to JSON."""

        analyzer = AppleAppAnalyzer(skip_treemap=False)
        artifact = ArtifactFactory.from_path(hackernews_xcarchive)

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

    def test_android_treemap_json_serialization(self, hn_apk: Path) -> None:
        """Test that Android treemap can be serialized to JSON."""

        analyzer = AndroidAnalyzer()
        artifact = ArtifactFactory.from_path(hn_apk)

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

    def test_apple_treemap_generation_basic(self, hackernews_xcarchive: Path) -> None:
        """Test basic treemap generation functionality."""

        analyzer = AppleAppAnalyzer(skip_treemap=False)
        artifact = ArtifactFactory.from_path(hackernews_xcarchive)

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

    def test_apple_treemap_matches_reference(self, hackernews_xcarchive: Path) -> None:
        """Test that treemap structure matches reference report."""

        analyzer = AppleAppAnalyzer(skip_treemap=False)
        artifact = ArtifactFactory.from_path(hackernews_xcarchive)

        results = analyzer.analyze(cast(AppleArtifact, artifact))

        treemap = results.treemap
        assert treemap is not None

        def find_node_by_path(root: TreemapElement, path: str) -> TreemapElement | None:
            if root.path == path:
                return root
            for child in root.children:
                if result := find_node_by_path(child, path):
                    return result
            return None

        root_name = treemap.root.name
        assert root_name == "HackerNews"
        root_is_dir = treemap.root.is_dir
        assert root_is_dir is True
        root_element_type = treemap.root.type
        assert root_element_type is None

        main_exe = find_node_by_path(treemap.root, "HackerNews")
        assert main_exe is not None
        assert main_exe.size == 3153920
        main_exe_element_type = main_exe.type
        assert main_exe_element_type == "executables"
        main_exe_is_dir = main_exe.is_dir
        assert main_exe_is_dir is False

        main_exe_sections = {child.name: child for child in main_exe.children}

        assert "__TEXT" in main_exe_sections
        text_size = main_exe_sections["__TEXT"].size
        assert text_size == 391451

        has_linkedit = "__LINKEDIT" in main_exe_sections
        assert has_linkedit
        linkedit = main_exe_sections["__LINKEDIT"]
        linkedit_size = linkedit.size
        assert linkedit_size == 269360

        linkedit_children = {child.name: child for child in linkedit.children}
        assert len(linkedit_children) == 7, (
            "__LINKEDIT should have exactly 7 child components (including unmapped space)"
        )

        assert "Symbol Table" in linkedit_children, "Symbol table should be present"
        assert "String Table" in linkedit_children, "String table should be present"
        assert "Function Starts" in linkedit_children, "Function starts should be present"
        assert "Unmapped" in linkedit_children, "Unmapped space should be present"

        assert linkedit_children["Symbol Table"].size == 11072, "Symbol table size mismatch"
        assert linkedit_children["String Table"].size == 16584, "String table size mismatch"
        assert linkedit_children["Function Starts"].size == 13584, "Function starts size mismatch"
        assert linkedit_children["Chained Fixups"].size == 87616, "Chained fixups size mismatch"
        assert linkedit_children["Export Trie"].size == 85056, "Export trie size mismatch"
        assert linkedit_children["Code Signature"].size == 43488, "Code signature size mismatch"
        assert linkedit_children["Unmapped"].size == 11960, "Unmapped space size mismatch"

        assert "Mach-O Header" in main_exe_sections
        assert main_exe_sections["Mach-O Header"].size == 32

        assert "Load Commands" in main_exe_sections
        assert main_exe_sections["Load Commands"].size == 8312

        assert "__DATA" in main_exe_sections
        assert main_exe_sections["__DATA"].size == 31947

        assert "__DATA_CONST" in main_exe_sections
        assert main_exe_sections["__DATA_CONST"].size == 72784

        assert "HackerNews" in main_exe_sections
        hackernews_module = main_exe_sections["HackerNews"]
        assert hackernews_module.size == 262392
        assert hackernews_module.type == "modules"
        assert len(hackernews_module.children) == 40

        assert main_exe.size == 3153920

        # Children will sum slightly higher than parent due to accounting precision (7368 bytes = 0.23%)
        # This includes per-segment unmapped space (padding/alignment) shown as separate children
        total_children_size = sum(child.size for child in main_exe.children)
        assert total_children_size == 3161288, f"Children sum should be 3161288, got {total_children_size}"
        expected_difference = 7368  # 0.23% accounting difference (includes per-segment unmapped space)
        actual_difference = total_children_size - main_exe.size
        assert actual_difference == expected_difference, (
            f"Expected {expected_difference} byte difference, got {actual_difference}"
        )

        def assert_no_negative_sizes(node: TreemapElement, path: str = "") -> None:
            """Recursively check that no node has negative size."""
            current_path = f"{path}/{node.name}" if path else node.name
            assert node.size >= 0, f"Node {current_path} has negative size: {node.size}"
            for child in node.children:
                assert_no_negative_sizes(child, current_path)

        assert_no_negative_sizes(main_exe)

        frameworks = find_node_by_path(treemap.root, "Frameworks")
        assert frameworks is not None
        frameworks_element_type = frameworks.type
        assert frameworks_element_type == "frameworks"
        frameworks_is_dir = frameworks.is_dir
        assert frameworks_is_dir is True

        sentry = find_node_by_path(treemap.root, "Frameworks/Sentry.framework")
        assert sentry is not None
        sentry_element_type = sentry.type
        assert sentry_element_type == "frameworks"
        sentry_is_dir = sentry.is_dir
        assert sentry_is_dir is True

        sentry_binary = find_node_by_path(treemap.root, "Frameworks/Sentry.framework/Sentry")
        assert sentry_binary is not None
        sentry_binary_size = sentry_binary.size
        assert sentry_binary_size == 53248
        sentry_binary_element_type = sentry_binary.type
        assert sentry_binary_element_type == "executables"

        common = find_node_by_path(treemap.root, "Frameworks/Common.framework")
        assert common is not None
        common_element_type = common.type
        assert common_element_type == "frameworks"
        common_is_dir = common.is_dir
        assert common_is_dir is True

        common_binary = find_node_by_path(treemap.root, "Frameworks/Common.framework/Common")
        assert common_binary is not None
        assert common_binary.size == 192512
        common_binary_element_type = common_binary.type
        assert common_binary_element_type == "executables"

        reaper = find_node_by_path(treemap.root, "Frameworks/Reaper.framework")
        assert reaper is not None
        reaper_element_type = reaper.type
        assert reaper_element_type == "frameworks"
        reaper_is_dir = reaper.is_dir
        assert reaper_is_dir is True

        reaper_binary = find_node_by_path(treemap.root, "Frameworks/Reaper.framework/Reaper")
        assert reaper_binary is not None
        assert reaper_binary.size == 53248
        reaper_binary_element_type = reaper_binary.type
        assert reaper_binary_element_type == "executables"

        plugins = find_node_by_path(treemap.root, "PlugIns")
        assert plugins is not None
        plugins_element_type = plugins.type
        assert plugins_element_type == "extensions"
        plugins_is_dir = plugins.is_dir
        assert plugins_is_dir is True

        widget = find_node_by_path(treemap.root, "PlugIns/HackerNewsHomeWidgetExtension.appex")
        assert widget is not None
        widget_element_type = widget.type
        assert widget_element_type == "extensions"
        widget_is_dir = widget.is_dir
        assert widget_is_dir is True

        widget_binary = find_node_by_path(
            treemap.root,
            "PlugIns/HackerNewsHomeWidgetExtension.appex/HackerNewsHomeWidgetExtension",
        )
        assert widget_binary is not None
        assert widget_binary.size == 155648
        widget_binary_element_type = widget_binary.type
        assert widget_binary_element_type == "executables"

        assets = find_node_by_path(treemap.root, "Assets.car")
        assert assets is not None
        assert assets.size == 4788224
        assert assets.type == "assets"
        assert len(assets.children) == 14

        assert treemap.file_count == 32
        assert treemap.platform == "ios"

    @pytest.mark.skipif(platform.system() != "Darwin", reason="CwlDemangle tool only available on macOS")
    def test_apple_treemap_swift_symbols_darwin_only(self, hackernews_xcarchive: Path) -> None:
        """Test Swift symbol demangling functionality (Darwin only due to CwlDemangle dependency)."""

        analyzer = AppleAppAnalyzer(skip_treemap=False)
        artifact = ArtifactFactory.from_path(hackernews_xcarchive)

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
        assert app_view_model_size == 24944  # Updated after accounting fixes
        app_view_model_element_type = app_view_model.type
        assert app_view_model_element_type == "modules"

        sentry_feedback_model = find_node_by_name(treemap.root, "SentryUserFeedbackFormViewModel")
        assert sentry_feedback_model is not None
        sentry_feedback_model_size = sentry_feedback_model.size
        assert sentry_feedback_model_size == 27612  # Updated after accounting fixes
        sentry_feedback_model_element_type = sentry_feedback_model.type
        assert sentry_feedback_model_element_type == "modules"
