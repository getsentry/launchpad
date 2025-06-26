"""Tests for DEX file parser."""

import pytest

from launchpad.parsers.android.dex.dex_file_parser import DexFileParser
from launchpad.parsers.android.dex.types import AccessFlag, ClassDefinition


class TestDexFileParser:
    """Test DEX file parser functionality."""

    def test_invalid_dex_file(self) -> None:
        """Test that invalid DEX files raise appropriate errors."""
        # Test with non-DEX file
        with pytest.raises(ValueError, match="Invalid dex file magic"):
            DexFileParser(b"not a dex file")

        # Test with empty file
        with pytest.raises(IndexError):
            DexFileParser(b"")

    def test_class_definition_size_calculation(self) -> None:
        """Test that class definition size calculation works."""
        # Create a minimal class definition
        class_def = ClassDefinition(
            signature="Lcom/example/TestClass;",
            source_file_name="TestClass.java",
            annotations=[],
            methods=[],
            access_flags=[AccessFlag.PUBLIC],
            superclass=None,
            interfaces=[],
        )

        # Basic size should be 32 bytes for class_def_item
        size = class_def.get_size()
        assert size >= 32

    def test_class_definition_with_interfaces(self) -> None:
        """Test class definition size calculation with interfaces."""
        interface1 = ClassDefinition(
            signature="Lcom/example/Interface1;",
            source_file_name=None,
            annotations=[],
            methods=[],
            access_flags=[AccessFlag.INTERFACE],
            superclass=None,
            interfaces=[],
        )

        interface2 = ClassDefinition(
            signature="Lcom/example/Interface2;",
            source_file_name=None,
            annotations=[],
            methods=[],
            access_flags=[AccessFlag.INTERFACE],
            superclass=None,
            interfaces=[],
        )

        class_def = ClassDefinition(
            signature="Lcom/example/TestClass;",
            source_file_name="TestClass.java",
            annotations=[],
            methods=[],
            access_flags=[AccessFlag.PUBLIC],
            superclass=None,
            interfaces=[interface1, interface2],
        )

        # Size should be larger due to interfaces
        size = class_def.get_size()
        assert size > 32

    def test_class_definition_with_annotations(self) -> None:
        """Test class definition size calculation with annotations."""
        from launchpad.parsers.android.dex.types import Annotation

        annotation = Annotation(
            type_name="Lcom/example/TestAnnotation;",
            elements={"value": "test"},
        )

        class_def = ClassDefinition(
            signature="Lcom/example/TestClass;",
            source_file_name="TestClass.java",
            annotations=[annotation],
            methods=[],
            access_flags=[AccessFlag.PUBLIC],
            superclass=None,
            interfaces=[],
        )

        # Size should be larger due to annotations
        size = class_def.get_size()
        assert size > 32
