"""Integration tests for DexElementBuilder with real Android artifacts."""

from __future__ import annotations

from pathlib import Path
from typing import List

import pytest

from launchpad.artifacts.android.apk import APK
from launchpad.artifacts.android.zipped_apk import ZippedAPK
from launchpad.models.common import FileInfo
from launchpad.models.treemap import TreemapType
from launchpad.utils.treemap.dex_element_builder import DexElementBuilder


class TestDexElementBuilderIntegration:
    """Integration tests for DexElementBuilder with real Android artifacts."""

    def test_dex_element_builder_with_real_apk(self) -> None:
        """Test DexElementBuilder with a real APK file."""
        # Use the test APK file
        apk_path = Path("tests/_fixtures/android/hn.apk")
        if not apk_path.exists():
            pytest.skip("Test APK file not found")

        # Create APK artifact
        apk = APK(apk_path.read_bytes())

        # Extract DEX files from the APK
        dex_files = self._extract_dex_files_from_apk(apk)

        assert len(dex_files) > 0, "No DEX files found in APK"

        # Test DexElementBuilder with each DEX file
        builder = DexElementBuilder(
            download_compression_ratio=0.8,
            filesystem_block_size=4096,
        )

        for dex_file_path in dex_files:
            file_info = FileInfo(
                path=str(dex_file_path),
                size=dex_file_path.stat().st_size,
                file_type="dex",
                hash_md5="test_hash",
                treemap_type=TreemapType.DEX_FILES,
            )

            element = builder.build_element(file_info, dex_file_path.name)

            # Should return a valid element
            assert element is not None
            assert element.name == dex_file_path.name
            assert element.element_type == TreemapType.DEX_FILES
            assert element.install_size == dex_file_path.stat().st_size
            assert element.download_size == int(dex_file_path.stat().st_size * 0.8)

            # Should have class details
            assert "class_count" in element.details
            assert "method_count" in element.details
            assert "total_size" in element.details

            # Should have class children if classes exist
            if element.details["class_count"] > 0:
                assert len(element.children) > 0

                # Check that class elements have the correct type
                for class_element in element.children:
                    assert class_element.element_type == TreemapType.DEX_CLASSES
                    assert class_element.name is not None
                    assert class_element.install_size > 0

                    # Check that method elements have the correct type
                    for method_element in class_element.children:
                        assert method_element.element_type == TreemapType.DEX_METHODS
                        assert method_element.name is not None
                        assert method_element.install_size > 0

    def test_dex_element_builder_with_zipped_apk(self) -> None:
        """Test DexElementBuilder with a zipped APK file."""
        # Use the test zipped APK file
        zipped_apk_path = Path("tests/_fixtures/android/zipped_apk.zip")
        if not zipped_apk_path.exists():
            pytest.skip("Test zipped APK file not found")

        # Create zipped APK artifact
        zipped_apk = ZippedAPK(zipped_apk_path.read_bytes())

        # Get the primary APK and extract DEX files from it
        primary_apk = zipped_apk.get_primary_apk()
        dex_files = self._extract_dex_files_from_apk(primary_apk)

        assert len(dex_files) > 0, "No DEX files found in zipped APK"

        # Test DexElementBuilder with each DEX file
        builder = DexElementBuilder(
            download_compression_ratio=0.8,
            filesystem_block_size=4096,
        )

        for dex_file_path in dex_files:
            file_info = FileInfo(
                path=str(dex_file_path),
                size=dex_file_path.stat().st_size,
                file_type="dex",
                hash_md5="test_hash",
                treemap_type=TreemapType.DEX_FILES,
            )

            element = builder.build_element(file_info, dex_file_path.name)

            # Should return a valid element
            assert element is not None
            assert element.name == dex_file_path.name
            assert element.element_type == TreemapType.DEX_FILES

    def _extract_dex_files_from_apk(self, apk: APK) -> List[Path]:
        """Extract DEX files from an APK artifact."""
        dex_files = []

        # Get the extract path
        extract_path = apk.get_extract_path()

        # Find all DEX files
        for file_path in extract_path.rglob("*.dex"):
            if file_path.is_file():
                dex_files.append(file_path)

        return dex_files

    def _extract_dex_files_from_zipped_apk(self, zipped_apk: ZippedAPK) -> List[Path]:
        """Extract DEX files from a zipped APK artifact."""
        # This method is no longer needed since we get the primary APK directly
        # Keeping for backward compatibility but it's not used
        return []

    def test_dex_file_structure_validation(self) -> None:
        """Test that DEX files have the expected structure."""
        # Use the test APK file
        apk_path = Path("tests/_fixtures/android/hn.apk")
        if not apk_path.exists():
            pytest.skip("Test APK file not found")

        # Extract DEX files
        apk = APK(apk_path.read_bytes())
        dex_files = self._extract_dex_files_from_apk(apk)

        if not dex_files:
            pytest.skip("No DEX files found in APK")

        # Test with the first DEX file
        dex_file_path = dex_files[0]

        builder = DexElementBuilder(
            download_compression_ratio=0.8,
            filesystem_block_size=4096,
        )

        file_info = FileInfo(
            path=str(dex_file_path),
            size=dex_file_path.stat().st_size,
            file_type="dex",
            hash_md5="test_hash",
            treemap_type=TreemapType.DEX_FILES,
        )

        element = builder.build_element(file_info, dex_file_path.name)

        # Validate the structure
        assert element is not None

        # Check that the element has the expected structure
        assert element.name == dex_file_path.name
        assert element.element_type == TreemapType.DEX_FILES
        assert element.install_size > 0
        assert element.download_size > 0
        assert element.download_size <= element.install_size

        # Check details
        details = element.details
        assert "class_count" in details
        assert "method_count" in details
        assert "total_size" in details
        assert details["class_count"] >= 0
        assert details["method_count"] >= 0
        assert details["total_size"] > 0

        # If there are classes, validate their structure
        if element.children:
            for class_element in element.children:
                assert class_element.element_type == TreemapType.DEX_CLASSES
                assert class_element.name
                assert class_element.install_size > 0
                assert "signature" in class_element.details
                assert "method_count" in class_element.details

                # If there are methods, validate their structure
                if class_element.children:
                    for method_element in class_element.children:
                        assert method_element.element_type == TreemapType.DEX_METHODS
                        assert method_element.name
                        assert method_element.install_size > 0
                        assert "signature" in method_element.details
                        assert "class_name" in method_element.details
