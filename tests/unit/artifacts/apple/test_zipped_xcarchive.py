import json
import tempfile

from pathlib import Path
from unittest.mock import patch

from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive


class TestZippedXCArchive:
    """Test ZippedXCArchive asset catalog parsing."""

    def test_top_level_asset_catalog_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            xcarchive_dir = tmpdir_path / "Test.xcarchive"
            parsed_assets_dir = xcarchive_dir / "ParsedAssets" / "Products" / "Applications" / "Test.app"
            parsed_assets_dir.mkdir(parents=True)

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

            image_file = parsed_assets_dir / "ABC123.png"
            image_file.write_bytes(b"fake png data")

            with patch.object(ZippedXCArchive, "__init__", lambda self, path: None):
                archive = ZippedXCArchive(Path("dummy"))
                archive._extract_dir = tmpdir_path

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
                    assert "ABC123.png" in str(element.full_path)
                    assert str(element.full_path).endswith("Test.app/ABC123.png")

    def test_nested_bundle_asset_catalog_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            xcarchive_dir = tmpdir_path / "Test.xcarchive"
            parsed_assets_dir = xcarchive_dir / "ParsedAssets" / "Products" / "Applications" / "Test.app"
            appex_dir = parsed_assets_dir / "PlugIns" / "TestExtension.appex"
            appex_dir.mkdir(parents=True)

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

            image_file = appex_dir / "XYZ789.png"
            image_file.write_bytes(b"fake png data")

            with patch.object(ZippedXCArchive, "__init__", lambda self, path: None):
                archive = ZippedXCArchive(Path("dummy"))
                archive._extract_dir = tmpdir_path

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
                    assert "TestExtension.appex" in str(element.full_path)
                    assert "XYZ789.png" in str(element.full_path)
                    assert str(element.full_path).endswith("TestExtension.appex/XYZ789.png")

    def test_framework_bundle_asset_catalog_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            xcarchive_dir = tmpdir_path / "Test.xcarchive"
            parsed_assets_dir = xcarchive_dir / "ParsedAssets" / "Products" / "Applications" / "Test.app"
            bundle_dir = parsed_assets_dir / "MyFramework.bundle"
            bundle_dir.mkdir(parents=True)

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

            image_file = bundle_dir / "DEF456.png"
            image_file.write_bytes(b"fake png data")

            with patch.object(ZippedXCArchive, "__init__", lambda self, path: None):
                archive = ZippedXCArchive(Path("dummy"))
                archive._extract_dir = tmpdir_path

                with patch.object(
                    archive,
                    "get_app_bundle_path",
                    return_value=xcarchive_dir / "Products" / "Applications" / "Test.app",
                ):
                    elements = archive.get_asset_catalog_details(Path("MyFramework.bundle/Assets.car"))

                    assert len(elements) == 1
                    element = elements[0]
                    assert element.full_path is not None, "full_path should be set for framework bundle images"
                    assert element.full_path.exists()

                    wrong_path = parsed_assets_dir / "DEF456.png"
                    assert not wrong_path.exists(), "Image should NOT exist at top-level"

                    assert "MyFramework.bundle" in str(element.full_path)
