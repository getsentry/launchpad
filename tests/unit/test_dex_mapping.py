"""Unit tests for DEX mapping functionality."""

from __future__ import annotations

from launchpad.parsers.android.dex.dex_mapping import (
    DexMapping,
    class_signature_to_fqn,
    fqn_to_class_signature,
    remove_kotlin_suffix_from_fqn,
    remove_kotlin_suffix_from_signature,
)


class TestDexMapping:
    """Test DexMapping class functionality."""

    def test_parse_simple_mapping(self) -> None:
        """Test parsing a simple proguard mapping file."""
        mapping_content = b"""# This is a comment
com.example.MyClass -> a:
    java.lang.String name -> a
    java.lang.String value -> b
    java.lang.String getName() -> a
    java.lang.String getValue() -> b

com.example.AnotherClass -> b:
    java.lang.String data -> a
    java.lang.String getData() -> a
"""
        dex_mapping = DexMapping(mapping_content)

        assert len(dex_mapping._classes) == 2

        # Test deobfuscation
        assert dex_mapping.deobfuscate("a") == "com.example.MyClass"
        assert dex_mapping.deobfuscate("b") == "com.example.AnotherClass"
        assert dex_mapping.deobfuscate("c") is None

        # Test signature deobfuscation
        assert dex_mapping.deobfuscate_signature("La;") == "Lcom/example/MyClass;"
        assert dex_mapping.deobfuscate_signature("Lb;") == "Lcom/example/AnotherClass;"
        assert dex_mapping.deobfuscate_signature("Lc;") is None

    def test_parse_with_source_file_info(self) -> None:
        """Test parsing mapping with source file information."""
        mapping_content = b"""# {"id":"sourceFile","fileName":"MyClass.kt"}
com.example.MyClass -> a:
    java.lang.String name -> a
"""
        dex_mapping = DexMapping(mapping_content)

        assert len(dex_mapping._classes) == 1

        # Look up the class and check source file info
        class_info = dex_mapping.lookup_obfuscated_class("a")
        assert class_info is not None
        assert class_info.name == "com.example.MyClass"
        assert class_info.file_name == "MyClass.kt"

    def test_parse_with_line_numbers(self) -> None:
        """Test parsing mapping with line number information."""
        mapping_content = b"""com.example.MyClass -> a:
    1:1:java.lang.String getName() -> a
    5:5:java.lang.String getValue() -> b
"""
        dex_mapping = DexMapping(mapping_content)

        assert len(dex_mapping._classes) == 1

        class_info = dex_mapping.lookup_obfuscated_class("a")
        assert class_info is not None
        assert class_info.start_line == 1  # Should use the first non-zero line number

    def test_lookup_methods(self) -> None:
        """Test lookup methods."""
        mapping_content = b"""com.example.MyClass -> a:
    java.lang.String name -> a
"""
        dex_mapping = DexMapping(mapping_content)

        # Test lookup by obfuscated signature
        class_info = dex_mapping.lookup_obfuscated_signature("La;")
        assert class_info is not None
        assert class_info.name == "com.example.MyClass"

        # Test lookup by deobfuscated signature
        class_info = dex_mapping.lookup_deobfuscated_signature("Lcom/example/MyClass;")
        assert class_info is not None
        assert class_info.obfuscated_name == "a"

    def test_empty_mapping(self) -> None:
        """Test parsing empty mapping file."""
        mapping_content = b""
        dex_mapping = DexMapping(mapping_content)

        assert len(dex_mapping._classes) == 0
        assert dex_mapping.deobfuscate("a") is None

    def test_mapping_with_comments_only(self) -> None:
        """Test parsing mapping file with only comments."""
        mapping_content = b"""# This is a comment
# Another comment
"""
        dex_mapping = DexMapping(mapping_content)

        assert len(dex_mapping._classes) == 0


class TestUtilityFunctions:
    """Test utility functions for DEX mapping."""

    def test_class_signature_to_fqn(self) -> None:
        """Test converting class signature to FQN."""
        assert class_signature_to_fqn("Lcom/example/MyClass;") == "com.example.MyClass"
        assert class_signature_to_fqn("Ljava/lang/String;") == "java.lang.String"
        assert class_signature_to_fqn("Landroid/app/Activity;") == "android.app.Activity"

        # Test without leading L and trailing ;
        assert class_signature_to_fqn("com/example/MyClass") == "com.example.MyClass"

    def test_fqn_to_class_signature(self) -> None:
        """Test converting FQN to class signature."""
        assert fqn_to_class_signature("com.example.MyClass") == "Lcom/example/MyClass;"
        assert fqn_to_class_signature("java.lang.String") == "Ljava/lang/String;"
        assert fqn_to_class_signature("android.app.Activity") == "Landroid/app/Activity;"

    def test_remove_kotlin_suffix_from_signature(self) -> None:
        """Test removing Kotlin suffix from class signature."""
        assert remove_kotlin_suffix_from_signature("Lcom/example/MyClassKt;") == "Lcom/example/MyClass;"
        assert remove_kotlin_suffix_from_signature("Lcom/example/MyClass;") == "Lcom/example/MyClass;"
        assert remove_kotlin_suffix_from_signature("Lcom/example/KtClass;") == "Lcom/example/KtClass;"

    def test_remove_kotlin_suffix_from_fqn(self) -> None:
        """Test removing Kotlin suffix from FQN."""
        assert remove_kotlin_suffix_from_fqn("com.example.MyClassKt") == "com.example.MyClass"
        assert remove_kotlin_suffix_from_fqn("com.example.MyClass") == "com.example.MyClass"
        assert remove_kotlin_suffix_from_fqn("com.example.KtClass") == "com.example.KtClass"
