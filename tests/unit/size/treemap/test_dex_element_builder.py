"""Unit tests for DEX treemap grouping by known libraries."""

from __future__ import annotations

from launchpad.parsers.android.dex.android_code_utils import AndroidCodeUtils
from launchpad.parsers.android.dex.types import ClassDefinition
from launchpad.size.models.common import FileInfo
from launchpad.size.models.treemap import TreemapElement, TreemapType
from launchpad.size.treemap.dex_element_builder import DexElementBuilder


def _class_def(fqn: str, size: int) -> ClassDefinition:
    return ClassDefinition(
        size=size,
        signature=AndroidCodeUtils.fqn_to_class_signature(fqn),
        source_file_name=None,
        interfaces=[],
        annotations=[],
        access_flags=[],
        fields=[],
        methods=[],
    )


def _file_info() -> FileInfo:
    return FileInfo(
        path="Dex",
        hash="",
        full_path=None,
        size=0,
        file_type="dex",
        treemap_type=TreemapType.DEX,
        is_dir=False,
    )


def _build(class_defs: list[ClassDefinition]) -> TreemapElement:
    builder = DexElementBuilder(filesystem_block_size=4096, class_definitions=class_defs)
    element = builder.build_element(_file_info(), "Dex")
    assert element is not None
    return element


def _find_child(element: TreemapElement, name: str) -> TreemapElement | None:
    for child in element.children:
        if child.name == name:
            return child
    return None


def test_known_library_grouped_first_party_stays_flat() -> None:
    element = _build(
        [
            _class_def("androidx.core.app.NotificationCompat", 500),
            _class_def("com.example.myapp.MainActivity", 300),
        ]
    )

    # First-party code stays in the normal package tree.
    assert _find_child(element, "Libraries") is not None
    com = _find_child(element, "com")
    assert com is not None
    assert com.size == 300

    # The recognized library is moved under the "Libraries" node.
    assert _find_child(element, "androidx") is None
    libraries = _find_child(element, "Libraries")
    assert libraries is not None
    assert libraries.type == TreemapType.DEX
    androidx = _find_child(libraries, "AndroidX")
    assert androidx is not None
    assert androidx.size == 500


def test_matched_prefix_is_stripped_inside_library_node() -> None:
    element = _build([_class_def("androidx.core.app.NotificationCompat", 500)])

    libraries = _find_child(element, "Libraries")
    assert libraries is not None
    androidx = _find_child(libraries, "AndroidX")
    assert androidx is not None

    # The "androidx" prefix is stripped: the hierarchy resumes at "core".
    core = _find_child(androidx, "core")
    assert core is not None
    assert _find_child(androidx, "androidx") is None
    # Class leaves keep their full FQN as the path.
    app = _find_child(core, "app")
    assert app is not None
    leaf = app.children[0]
    assert leaf.name == "NotificationCompat"
    assert leaf.path == "androidx.core.app.NotificationCompat"


def test_multiple_prefixes_collapse_into_one_library() -> None:
    element = _build(
        [
            _class_def("kotlin.collections.CollectionsKt", 400),
            _class_def("kotlinx.coroutines.CoroutineScope", 600),
        ]
    )

    libraries = _find_child(element, "Libraries")
    assert libraries is not None
    kotlin = _find_child(libraries, "Kotlin")
    assert kotlin is not None
    assert kotlin.size == 1000
    assert {child.name for child in kotlin.children} == {"collections", "coroutines"}


def test_no_libraries_node_when_nothing_recognized() -> None:
    element = _build([_class_def("com.example.myapp.MainActivity", 300)])

    assert _find_child(element, "Libraries") is None
    assert _find_child(element, "com") is not None


def test_total_size_preserved_and_libraries_sorted_by_size() -> None:
    element = _build(
        [
            _class_def("androidx.core.app.NotificationCompat", 500),
            _class_def("io.sentry.Sentry", 900),
            _class_def("com.example.myapp.MainActivity", 300),
        ]
    )

    assert element.size == 1700

    libraries = _find_child(element, "Libraries")
    assert libraries is not None
    assert libraries.size == 1400
    # Libraries are sorted by descending size (Sentry 900 before AndroidX 500).
    assert [child.name for child in libraries.children] == ["Sentry", "AndroidX"]
