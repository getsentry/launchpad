from __future__ import annotations

from launchpad.parsers.android.dex.dex_mapping import (
    DexMapping,
)


class TestDexMapping:
    def test_parse_simple_mapping(self) -> None:
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

        assert dex_mapping.deobfuscate("a") == "com.example.MyClass"
        assert dex_mapping.deobfuscate("b") == "com.example.AnotherClass"
        assert dex_mapping.deobfuscate("c") is None

        assert dex_mapping.deobfuscate_signature("La;") == "Lcom/example/MyClass;"
        assert dex_mapping.deobfuscate_signature("Lb;") == "Lcom/example/AnotherClass;"
        assert dex_mapping.deobfuscate_signature("Lc;") is None

    def test_parse_with_source_file_info(self) -> None:
        mapping_content = b"""# {"id":"sourceFile","fileName":"MyClass.kt"}
com.example.MyClass -> a:
    java.lang.String name -> a
"""
        dex_mapping = DexMapping(mapping_content)

        assert len(dex_mapping._classes) == 1

        class_info = dex_mapping.lookup_obfuscated_class("a")
        assert class_info is not None
        assert class_info.deobfuscated_fqn == "com.example.MyClass"
        assert class_info.file_name == "MyClass.kt"

    def test_parse_with_line_numbers(self) -> None:
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
        mapping_content = b"""com.example.MyClass -> a:
    java.lang.String name -> a
"""
        dex_mapping = DexMapping(mapping_content)

        class_info = dex_mapping.lookup_obfuscated_signature("La;")
        assert class_info is not None
        assert class_info.deobfuscated_fqn == "com.example.MyClass"

        class_info = dex_mapping.lookup_deobfuscated_signature("Lcom/example/MyClass;")
        assert class_info is not None
        assert class_info.obfuscated_fqn == "a"

    def test_empty_mapping(self) -> None:
        mapping_content = b""
        dex_mapping = DexMapping(mapping_content)

        assert len(dex_mapping._classes) == 0
        assert dex_mapping.deobfuscate("a") is None

    def test_mapping_with_comments_only(self) -> None:
        mapping_content = b"""# This is a comment
# Another comment
"""
        dex_mapping = DexMapping(mapping_content)

        assert len(dex_mapping._classes) == 0

    def test_method_and_field_deobfuscation(self) -> None:
        mapping_content = b"""com.example.MyClass -> a:
    java.lang.String foo -> x
    java.lang.String bar -> y
    void doSomething() -> z
    int getValue() -> w
"""
        dex_mapping = DexMapping(mapping_content)
        assert dex_mapping.deobfuscate_field("a", "x") == "foo"
        assert dex_mapping.deobfuscate_field("a", "y") == "bar"
        assert dex_mapping.deobfuscate_field("a", "notfound") is None

        assert dex_mapping.deobfuscate_method("a", "z") == "doSomething"
        assert dex_mapping.deobfuscate_method("a", "w") == "getValue"
        assert dex_mapping.deobfuscate_method("a", "notfound") is None

        assert dex_mapping.deobfuscate_field("com.example.MyClass", "x") == "foo"
        assert dex_mapping.deobfuscate_method("com.example.MyClass", "z") == "doSomething"
