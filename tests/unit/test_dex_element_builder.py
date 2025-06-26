"""Tests for DexElementBuilder."""

from __future__ import annotations

from pathlib import Path

from launchpad.models.common import FileInfo
from launchpad.models.treemap import TreemapType
from launchpad.utils.treemap.dex_element_builder import DexElementBuilder


class TestDexElementBuilder:
    """Test cases for DexElementBuilder."""

    def test_build_element_with_valid_dex_file(self, tmp_path: Path) -> None:
        """Test building a treemap element from a valid DEX file."""
        # Create a mock DEX file (this would normally be a real DEX file)
        # For testing, we'll create a minimal DEX file structure
        dex_file = tmp_path / "classes.dex"

        # Create a minimal DEX file header
        # This is a simplified DEX file structure for testing
        dex_header = b"dex\n035\x00" + b"\x00" * 124  # DEX header
        dex_file.write_bytes(dex_header)

        file_info = FileInfo(
            path=str(dex_file),
            size=dex_file.stat().st_size,
            file_type="dex",
            hash_md5="test_hash",
            treemap_type=TreemapType.DEX_FILES,
        )

        builder = DexElementBuilder(
            download_compression_ratio=0.8,
            filesystem_block_size=4096,
        )

        # This should handle the incomplete DEX file gracefully
        element = builder.build_element(file_info, "classes.dex")

        # Should return a valid element even for incomplete DEX files
        assert element is not None
        assert element.name == "classes.dex"
        assert element.element_type == TreemapType.DEX_FILES
        assert element.install_size == dex_file.stat().st_size
        assert element.download_size == int(dex_file.stat().st_size * 0.8)
        assert element.children == []  # No classes in incomplete DEX
        assert element.details["class_count"] == 0
        assert element.details["method_count"] == 0

    def test_build_element_with_nonexistent_file(self) -> None:
        """Test building a treemap element with a nonexistent file."""
        file_info = FileInfo(
            path="nonexistent.dex",
            size=0,
            file_type="dex",
            hash_md5="test_hash",
            treemap_type=TreemapType.DEX_FILES,
        )

        builder = DexElementBuilder(
            download_compression_ratio=0.8,
            filesystem_block_size=4096,
        )

        element = builder.build_element(file_info, "nonexistent.dex")

        # Should return None for nonexistent files
        assert element is None

    def test_access_flags_parsing(self) -> None:
        """Test parsing of DEX access flags."""
        builder = DexElementBuilder(
            download_compression_ratio=0.8,
            filesystem_block_size=4096,
        )

        # Test various access flag combinations
        flags = builder._get_access_flags(0x1)  # public
        assert "public" in flags

        flags = builder._get_access_flags(0x9)  # public + static
        assert "public" in flags
        assert "static" in flags

        flags = builder._get_access_flags(0x100)  # native
        assert "native" in flags

        flags = builder._get_access_flags(0x200)  # interface
        assert "interface" in flags

    def test_class_name_extraction(self) -> None:
        """Test extraction of class names from DEX format."""
        builder = DexElementBuilder(
            download_compression_ratio=0.8,
            filesystem_block_size=4096,
        )

        # Mock a DEX class object
        class MockDexClass:
            def __init__(self, name: str):
                self.name = name

        # Test various class name formats
        test_cases = [
            ("Lcom/example/MyClass;", "com.example.MyClass"),
            ("Ljava/lang/String;", "java.lang.String"),
            ("Landroid/app/Activity;", "android.app.Activity"),
        ]

        for dex_name, expected_name in test_cases:
            mock_class = MockDexClass(dex_name)
            extracted_name = builder._get_class_name(mock_class)
            assert extracted_name == expected_name

    def test_method_signature_generation(self) -> None:
        """Test generation of method signatures."""
        builder = DexElementBuilder(
            download_compression_ratio=0.8,
            filesystem_block_size=4096,
        )

        # Mock a DEX method object
        class MockPrototype:
            def __init__(self, parameters: list[str], return_type: str):
                self.parameters = parameters
                self.return_type = return_type

        class MockMethod:
            def __init__(self, name: str, prototype: MockPrototype | None = None):
                self.name = name
                self.prototype = prototype

        # Test method signature generation
        method = MockMethod("onCreate")
        signature = builder._get_method_signature(method)
        assert signature == "onCreate()V"

        # Test with parameters
        prototype = MockPrototype(["Landroid/os/Bundle;"], "V")
        method = MockMethod("onCreate", prototype)
        signature = builder._get_method_signature(method)
        assert signature == "onCreate(Landroid/os/Bundle;)V"

    def test_method_size_calculation(self) -> None:
        """Test calculation of method sizes."""
        builder = DexElementBuilder(
            download_compression_ratio=0.8,
            filesystem_block_size=4096,
        )

        # Mock a DEX method object
        class MockCode:
            def __init__(self, bytecode_size: int):
                self.bytecode_size = bytecode_size

        class MockMethod:
            def __init__(self, name: str, code: MockCode | None = None):
                self.name = name
                self.code = code

        # Test with code size available
        code = MockCode(256)
        method = MockMethod("testMethod", code)
        size = builder._calculate_method_size(method)
        assert size == 256

        # Test without code size (fallback calculation)
        method = MockMethod("testMethod")
        size = builder._calculate_method_size(method)
        assert size > 0  # Should return a positive size

    def test_builder_initialization(self) -> None:
        """Test DexElementBuilder initialization."""
        builder = DexElementBuilder(
            download_compression_ratio=0.8,
            filesystem_block_size=4096,
        )

        assert builder.download_compression_ratio == 0.8
        assert builder.filesystem_block_size == 4096

        # Test compression ratio clamping
        builder = DexElementBuilder(
            download_compression_ratio=1.5,  # Should be clamped to 1.0
            filesystem_block_size=4096,
        )
        assert builder.download_compression_ratio == 1.0

        builder = DexElementBuilder(
            download_compression_ratio=-0.5,  # Should be clamped to 0.0
            filesystem_block_size=4096,
        )
        assert builder.download_compression_ratio == 0.0
