import json
import plistlib
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


class TestMacOSBundleDetection:
    """Test macOS vs iOS bundle structure detection."""

    def test_is_macos_app_bundle_with_contents_dir(self) -> None:
        """Test that apps with Contents/ directory are detected as macOS."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            xcarchive_dir = tmpdir_path / "Test.xcarchive"
            app_path = xcarchive_dir / "Products" / "Applications" / "Test.app"
            contents_path = app_path / "Contents"
            contents_path.mkdir(parents=True)

            with patch.object(ZippedXCArchive, "__init__", lambda self, path: None):
                archive = ZippedXCArchive(Path("dummy"))
                archive._extract_dir = tmpdir_path
                archive._is_macos_bundle = None
                archive._app_bundle_path = app_path

                with patch.object(archive, "get_app_bundle_path", return_value=app_path):
                    assert archive._is_macos_app_bundle() is True
                    # Test caching
                    assert archive._is_macos_bundle is True
                    assert archive._is_macos_app_bundle() is True

    def test_is_ios_app_bundle_without_contents_dir(self) -> None:
        """Test that apps without Contents/ directory are detected as iOS."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            xcarchive_dir = tmpdir_path / "Test.xcarchive"
            app_path = xcarchive_dir / "Products" / "Applications" / "Test.app"
            app_path.mkdir(parents=True)

            with patch.object(ZippedXCArchive, "__init__", lambda self, path: None):
                archive = ZippedXCArchive(Path("dummy"))
                archive._extract_dir = tmpdir_path
                archive._is_macos_bundle = None
                archive._app_bundle_path = app_path

                with patch.object(archive, "get_app_bundle_path", return_value=app_path):
                    assert archive._is_macos_app_bundle() is False
                    assert archive._is_macos_bundle is False


class TestMacOSPlistPaths:
    """Test Info.plist path resolution for macOS vs iOS."""

    def test_get_plist_macos_contents_info_plist(self) -> None:
        """Test that macOS apps read Info.plist from Contents/."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            xcarchive_dir = tmpdir_path / "Test.xcarchive"
            app_path = xcarchive_dir / "Products" / "Applications" / "Test.app"
            contents_path = app_path / "Contents"
            contents_path.mkdir(parents=True)

            plist_path = contents_path / "Info.plist"
            plist_data = {"CFBundleExecutable": "TestApp", "CFBundleName": "Test"}
            with open(plist_path, "wb") as f:
                plistlib.dump(plist_data, f)

            with patch.object(ZippedXCArchive, "__init__", lambda self, path: None):
                archive = ZippedXCArchive(Path("dummy"))
                archive._extract_dir = tmpdir_path
                archive._plist = None
                archive._app_bundle_path = app_path

                with patch.object(archive, "get_app_bundle_path", return_value=app_path):
                    plist = archive.get_plist()
                    assert plist["CFBundleExecutable"] == "TestApp"
                    assert plist["CFBundleName"] == "Test"

    def test_get_plist_ios_direct_info_plist(self) -> None:
        """Test that iOS apps read Info.plist directly from bundle."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            xcarchive_dir = tmpdir_path / "Test.xcarchive"
            app_path = xcarchive_dir / "Products" / "Applications" / "Test.app"
            app_path.mkdir(parents=True)

            plist_path = app_path / "Info.plist"
            plist_data = {"CFBundleExecutable": "iOSApp", "CFBundleName": "iOS Test"}
            with open(plist_path, "wb") as f:
                plistlib.dump(plist_data, f)

            with patch.object(ZippedXCArchive, "__init__", lambda self, path: None):
                archive = ZippedXCArchive(Path("dummy"))
                archive._extract_dir = tmpdir_path
                archive._plist = None
                archive._app_bundle_path = app_path

                with patch.object(archive, "get_app_bundle_path", return_value=app_path):
                    plist = archive.get_plist()
                    assert plist["CFBundleExecutable"] == "iOSApp"
                    assert plist["CFBundleName"] == "iOS Test"


class TestMacOSBinaryPaths:
    """Test binary path resolution for macOS vs iOS."""

    def test_get_binary_path_macos(self) -> None:
        """Test binary path for macOS apps (Contents/MacOS/)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            xcarchive_dir = tmpdir_path / "Test.xcarchive"
            app_path = xcarchive_dir / "Products" / "Applications" / "Test.app"
            macos_path = app_path / "Contents" / "MacOS"
            macos_path.mkdir(parents=True)
            binary_path = macos_path / "TestApp"
            binary_path.write_bytes(b"fake binary")

            plist_path = app_path / "Contents" / "Info.plist"
            plist_data = {"CFBundleExecutable": "TestApp"}
            with open(plist_path, "wb") as f:
                plistlib.dump(plist_data, f)

            with patch.object(ZippedXCArchive, "__init__", lambda self, path: None):
                archive = ZippedXCArchive(Path("dummy"))
                archive._extract_dir = tmpdir_path
                archive._plist = None
                archive._is_macos_bundle = None
                archive._app_bundle_path = app_path

                with patch.object(archive, "get_app_bundle_path", return_value=app_path):
                    result = archive.get_binary_path()
                    assert result == binary_path
                    assert "Contents/MacOS/TestApp" in str(result)

    def test_get_binary_path_ios(self) -> None:
        """Test binary path for iOS apps (directly in bundle)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            xcarchive_dir = tmpdir_path / "Test.xcarchive"
            app_path = xcarchive_dir / "Products" / "Applications" / "Test.app"
            app_path.mkdir(parents=True)
            binary_path = app_path / "iOSApp"
            binary_path.write_bytes(b"fake binary")

            plist_path = app_path / "Info.plist"
            plist_data = {"CFBundleExecutable": "iOSApp"}
            with open(plist_path, "wb") as f:
                plistlib.dump(plist_data, f)

            with patch.object(ZippedXCArchive, "__init__", lambda self, path: None):
                archive = ZippedXCArchive(Path("dummy"))
                archive._extract_dir = tmpdir_path
                archive._plist = None
                archive._is_macos_bundle = None
                archive._app_bundle_path = app_path

                with patch.object(archive, "get_app_bundle_path", return_value=app_path):
                    result = archive.get_binary_path()
                    assert result == binary_path
                    assert str(result).endswith("Test.app/iOSApp")


class TestMacOSFrameworkDiscovery:
    """Test framework binary discovery for macOS vs iOS."""

    def test_discover_macos_framework_with_versions(self) -> None:
        """Test macOS frameworks with Versions/A/ structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            app_path = tmpdir_path / "Test.app"
            frameworks_path = app_path / "Contents" / "Frameworks"
            framework_path = frameworks_path / "MyFramework.framework"
            versions_path = framework_path / "Versions" / "A"
            versions_path.mkdir(parents=True)

            binary_path = versions_path / "MyFramework"
            binary_path.write_bytes(b"fake framework binary")

            (framework_path / "Versions" / "Current").mkdir(parents=True)

            with patch.object(ZippedXCArchive, "__init__", lambda self, path: None):
                archive = ZippedXCArchive(Path("dummy"))
                archive._extract_dir = tmpdir_path

                binaries = archive._discover_framework_binaries(app_path)
                assert len(binaries) == 1
                assert binaries[0] == binary_path
                assert "Versions/A/MyFramework" in str(binaries[0])

    def test_discover_ios_framework_direct(self) -> None:
        """Test iOS frameworks with binary directly in framework."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            app_path = tmpdir_path / "Test.app"
            frameworks_path = app_path / "Frameworks"
            framework_path = frameworks_path / "MyFramework.framework"
            framework_path.mkdir(parents=True)

            binary_path = framework_path / "MyFramework"
            binary_path.write_bytes(b"fake framework binary")

            with patch.object(ZippedXCArchive, "__init__", lambda self, path: None):
                archive = ZippedXCArchive(Path("dummy"))
                archive._extract_dir = tmpdir_path

                binaries = archive._discover_framework_binaries(app_path)
                assert len(binaries) == 1
                assert binaries[0] == binary_path
                assert str(binaries[0]).endswith("MyFramework.framework/MyFramework")


class TestMacOSExtensionDiscovery:
    """Test extension binary discovery for macOS vs iOS."""

    def test_discover_macos_extension_with_contents(self) -> None:
        """Test macOS extensions with Contents/MacOS/ structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            app_path = tmpdir_path / "Test.app"
            plugins_path = app_path / "Contents" / "PlugIns"
            extension_path = plugins_path / "MyExtension.appex"
            macos_path = extension_path / "Contents" / "MacOS"
            macos_path.mkdir(parents=True)

            binary_path = macos_path / "MyExtension"
            binary_path.write_bytes(b"fake extension binary")

            plist_path = extension_path / "Contents" / "Info.plist"
            plist_data = {"CFBundleExecutable": "MyExtension"}
            with open(plist_path, "wb") as f:
                plistlib.dump(plist_data, f)

            with patch.object(ZippedXCArchive, "__init__", lambda self, path: None):
                archive = ZippedXCArchive(Path("dummy"))
                archive._extract_dir = tmpdir_path

                binaries = archive._discover_extension_binaries(app_path)
                assert len(binaries) == 1
                assert binaries[0] == binary_path
                assert "Contents/MacOS/MyExtension" in str(binaries[0])

    def test_discover_ios_extension_direct(self) -> None:
        """Test iOS extensions with binary directly in appex."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            app_path = tmpdir_path / "Test.app"
            plugins_path = app_path / "PlugIns"
            extension_path = plugins_path / "MyExtension.appex"
            extension_path.mkdir(parents=True)

            binary_path = extension_path / "MyExtension"
            binary_path.write_bytes(b"fake extension binary")

            plist_path = extension_path / "Info.plist"
            plist_data = {"CFBundleExecutable": "MyExtension"}
            with open(plist_path, "wb") as f:
                plistlib.dump(plist_data, f)

            with patch.object(ZippedXCArchive, "__init__", lambda self, path: None):
                archive = ZippedXCArchive(Path("dummy"))
                archive._extract_dir = tmpdir_path

                binaries = archive._discover_extension_binaries(app_path)
                assert len(binaries) == 1
                assert binaries[0] == binary_path
                assert str(binaries[0]).endswith("MyExtension.appex/MyExtension")
