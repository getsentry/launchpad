import json
import tempfile

from pathlib import Path
from unittest.mock import patch

from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive


class TestZippedXCArchive:
    """Test ZippedXCArchive asset catalog parsing."""

    def test_top_level_asset_catalog_parsing(self) -> None:
        """Test that top-level Assets.car parent_path is constructed correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Create directory structure
            xcarchive_dir = tmpdir_path / "Test.xcarchive"
            parsed_assets_dir = xcarchive_dir / "ParsedAssets" / "Products" / "Applications" / "Test.app"
            parsed_assets_dir.mkdir(parents=True)

            # Create Assets.json
            assets_json = parsed_assets_dir / "Assets.json"
            assets_data = [
                {
                    "name": "icon.png",
                    "imageId": "ABC123",
                    "size": 1024,
                    "type": 0,
                    "vector": False,
                    "filename": "icon.png",
                }
            ]
            assets_json.write_text(json.dumps(assets_data))

            # Create the actual image file
            image_file = parsed_assets_dir / "ABC123.png"
            image_file.write_bytes(b"fake png data")

            # Mock the archive
            with patch.object(ZippedXCArchive, "__init__", lambda self, path: None):
                archive = ZippedXCArchive(Path("dummy"))
                archive._extract_dir = tmpdir_path

                # Mock get_app_bundle_path to return expected path
                with patch.object(
                    archive,
                    "get_app_bundle_path",
                    return_value=xcarchive_dir / "Products" / "Applications" / "Test.app",
                ):
                    elements = archive.get_asset_catalog_details(Path("Assets.car"))

                    assert len(elements) == 1
                    element = elements[0]
                    assert element.name == "icon.png"
                    assert element.image_id == "ABC123"
                    assert element.full_path is not None
                    assert element.full_path.exists()
                    # Verify parent path does NOT include nested bundle directories for top-level
                    assert "ABC123.png" in str(element.full_path)
                    assert str(element.full_path).endswith("Test.app/ABC123.png")

    def test_nested_bundle_asset_catalog_parsing(self) -> None:
        """Test that nested bundle Assets.car parent_path includes the bundle directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Create directory structure for nested .appex bundle
            xcarchive_dir = tmpdir_path / "Test.xcarchive"
            parsed_assets_dir = xcarchive_dir / "ParsedAssets" / "Products" / "Applications" / "Test.app"
            appex_dir = parsed_assets_dir / "PlugIns" / "TestExtension.appex"
            appex_dir.mkdir(parents=True)

            # Create Assets.json in the .appex directory
            assets_json = appex_dir / "Assets.json"
            assets_data = [
                {
                    "name": "widget-icon.png",
                    "imageId": "XYZ789",
                    "size": 2048,
                    "type": 0,
                    "vector": False,
                    "filename": "widget-icon.png",
                }
            ]
            assets_json.write_text(json.dumps(assets_data))

            # Create the actual image file in the .appex directory
            image_file = appex_dir / "XYZ789.png"
            image_file.write_bytes(b"fake png data")

            # Mock the archive
            with patch.object(ZippedXCArchive, "__init__", lambda self, path: None):
                archive = ZippedXCArchive(Path("dummy"))
                archive._extract_dir = tmpdir_path

                # Mock get_app_bundle_path
                with patch.object(
                    archive,
                    "get_app_bundle_path",
                    return_value=xcarchive_dir / "Products" / "Applications" / "Test.app",
                ):
                    elements = archive.get_asset_catalog_details(Path("PlugIns/TestExtension.appex/Assets.car"))

                    assert len(elements) == 1
                    element = elements[0]
                    assert element.name == "widget-icon.png"
                    assert element.image_id == "XYZ789"
                    assert element.full_path is not None
                    assert element.full_path.exists()
                    # CRITICAL: Verify parent path INCLUDES the nested bundle directory
                    assert "TestExtension.appex" in str(element.full_path)
                    assert "XYZ789.png" in str(element.full_path)
                    assert str(element.full_path).endswith("TestExtension.appex/XYZ789.png")

    def test_nested_bundle_without_fix_would_fail(self) -> None:
        """Test that demonstrates the bug: nested bundle images wouldn't be found without the fix."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Create directory structure
            xcarchive_dir = tmpdir_path / "Test.xcarchive"
            parsed_assets_dir = xcarchive_dir / "ParsedAssets" / "Products" / "Applications" / "Test.app"
            bundle_dir = parsed_assets_dir / "MyFramework.bundle"
            bundle_dir.mkdir(parents=True)

            # Create Assets.json
            assets_json = bundle_dir / "Assets.json"
            assets_data = [
                {
                    "name": "resource.png",
                    "imageId": "DEF456",
                    "size": 512,
                    "type": 0,
                    "vector": False,
                    "filename": "resource.png",
                }
            ]
            assets_json.write_text(json.dumps(assets_data))

            # Image file is in the bundle directory (where it actually exists)
            image_file = bundle_dir / "DEF456.png"
            image_file.write_bytes(b"fake png data")

            # Mock the archive
            with patch.object(ZippedXCArchive, "__init__", lambda self, path: None):
                archive = ZippedXCArchive(Path("dummy"))
                archive._extract_dir = tmpdir_path

                with patch.object(
                    archive,
                    "get_app_bundle_path",
                    return_value=xcarchive_dir / "Products" / "Applications" / "Test.app",
                ):
                    elements = archive.get_asset_catalog_details(Path("MyFramework.bundle/Assets.car"))

                    # With the fix, full_path should be found
                    assert len(elements) == 1
                    element = elements[0]
                    assert element.full_path is not None, "full_path should be set with the fix"
                    assert element.full_path.exists()

                    # Without the fix, it would look in Test.app/DEF456.png (wrong!)
                    wrong_path = parsed_assets_dir / "DEF456.png"
                    assert not wrong_path.exists(), "Image should NOT exist at top-level"

                    # With the fix, it correctly looks in Test.app/MyFramework.bundle/DEF456.png
                    assert "MyFramework.bundle" in str(element.full_path)
