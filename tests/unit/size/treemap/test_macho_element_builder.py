"""Unit tests for MachOElementBuilder architecture slice handling."""

from pathlib import Path

from launchpad.size.models.apple import (
    ArchitectureSlice,
    LinkEditInfo,
    LoadCommandInfo,
    MachOBinaryAnalysis,
    SectionInfo,
    SegmentInfo,
)
from launchpad.size.models.common import FileInfo
from launchpad.size.models.treemap import TreemapElement, TreemapType
from launchpad.size.symbols.macho_symbol_sizes import SymbolSize
from launchpad.size.symbols.partitioner import SymbolInfo
from launchpad.size.symbols.types import SwiftSymbolTypeGroup
from launchpad.size.treemap.macho_element_builder import MachOElementBuilder


def _swift_group(module: str, type_name: str, size: int) -> SwiftSymbolTypeGroup:
    """Build a SwiftSymbolTypeGroup with a single symbol living in __TEXT.__text."""
    symbol = SymbolSize(
        mangled_name=f"_{module}_{type_name}",
        section_name="__text",
        segment_name="__TEXT",
        address=0,
        size=size,
    )
    return SwiftSymbolTypeGroup(
        module=module,
        type_name=type_name,
        components=[module, type_name],
        symbol_count=1,
        symbols=[symbol],
    )


def _create_arch_slice_with_swift_modules(
    arch_name: str, size: int, groups: list[SwiftSymbolTypeGroup]
) -> ArchitectureSlice:
    """Like _create_arch_slice but attaches Swift symbol groups to the slice."""
    arch_slice = _create_arch_slice(arch_name, size)
    arch_slice.symbol_info = SymbolInfo(
        symbol_sizes=[s for g in groups for s in g.symbols],
        swift_type_groups=groups,
        objc_type_groups=[],
        cpp_type_groups=[],
        other_symbols=[],
        compiler_generated_symbols=[],
    )
    return arch_slice


def _find_child(element: TreemapElement, name: str) -> TreemapElement | None:
    for child in element.children:
        if child.name == name:
            return child
    return None


def _create_arch_slice(arch_name: str, size: int) -> ArchitectureSlice:
    """Helper to create an ArchitectureSlice with minimal required fields."""
    return ArchitectureSlice(
        arch_name=arch_name,
        size=size,
        segments=[
            SegmentInfo(
                name="__TEXT",
                sections=[SectionInfo(name="__text", size=size - 100, is_zerofill=False)],
                size=size - 100,
            ),
            SegmentInfo(
                name="__LINKEDIT",
                sections=[],
                size=100,
            ),
        ],
        load_commands=[LoadCommandInfo(name="LC_SEGMENT_64", size=72)],
        header_size=32,
        linkedit_info=LinkEditInfo(segment_size=100),
    )


def _create_binary_analysis(
    binary_path: str,
    slices: list[ArchitectureSlice],
) -> MachOBinaryAnalysis:
    """Helper to create MachOBinaryAnalysis with given architecture slices."""
    total_size = sum(s.size for s in slices)
    return MachOBinaryAnalysis(
        binary_absolute_path=Path(binary_path),
        binary_relative_path=Path(binary_path),
        executable_size=total_size,
        is_main_binary=True,
        architecture_slices=slices,
    )


def _create_file_info(path: str, size: int) -> FileInfo:
    """Helper to create FileInfo with all required fields."""
    return FileInfo(
        path=path,
        hash="fakehash",
        full_path=Path(path),
        size=size,
        file_type="executable",
        treemap_type=TreemapType.EXECUTABLES,
        is_dir=False,
    )


class TestMachOElementBuilderArchitectureHandling:
    """Tests for multi-architecture slice handling in treemap generation."""

    def test_single_architecture_no_wrapper_node(self):
        """Single architecture slice should not have a wrapper node."""
        arm64_slice = _create_arch_slice("ARM64", size=100000)
        binary_analysis = _create_binary_analysis("MyApp", [arm64_slice])

        builder = MachOElementBuilder(
            filesystem_block_size=4096,
            binary_analysis_map={"MyApp": binary_analysis},
        )

        file_info = _create_file_info("MyApp", 100000)
        element = builder.build_element(file_info, "MyApp")

        assert element is not None
        assert element.name == "MyApp"
        assert element.size == 100000

        child_names = [c.name for c in element.children]
        assert "ARM64" not in child_names
        assert "__TEXT" in child_names
        assert "__LINKEDIT" in child_names

    def test_multiple_architectures_with_wrapper_nodes(self):
        """Multiple architecture slices should each be wrapped in a parent node."""
        arm64_slice = _create_arch_slice("ARM64", size=50000)
        x86_64_slice = _create_arch_slice("X86_64", size=60000)
        binary_analysis = _create_binary_analysis("MyApp", [arm64_slice, x86_64_slice])

        builder = MachOElementBuilder(
            filesystem_block_size=4096,
            binary_analysis_map={"MyApp": binary_analysis},
        )

        file_info = _create_file_info("MyApp", 110000)
        element = builder.build_element(file_info, "MyApp")

        assert element is not None
        assert element.name == "MyApp"
        assert element.size == 110000

        assert len(element.children) == 2
        child_names = [c.name for c in element.children]
        assert "ARM64" in child_names
        assert "X86_64" in child_names

        children_by_name = {c.name: c for c in element.children}

        arm64_node = children_by_name["ARM64"]
        assert arm64_node.size == 50000
        assert arm64_node.type == TreemapType.EXECUTABLES
        assert "__TEXT" in [c.name for c in arm64_node.children]

        x86_64_node = children_by_name["X86_64"]
        assert x86_64_node.size == 60000
        assert x86_64_node.type == TreemapType.EXECUTABLES
        assert "__TEXT" in [c.name for c in x86_64_node.children]

    def test_empty_architecture_slices_returns_none(self):
        """Empty architecture slices should return None."""
        binary_analysis = _create_binary_analysis("MyApp", [])

        builder = MachOElementBuilder(
            filesystem_block_size=4096,
            binary_analysis_map={"MyApp": binary_analysis},
        )

        file_info = _create_file_info("MyApp", 0)
        element = builder.build_element(file_info, "MyApp")

        assert element is None

    def test_architecture_slice_sizes_are_preserved(self):
        """Each architecture wrapper node should have the correct slice size."""
        arm64_slice = _create_arch_slice("ARM64", size=45000)
        x86_64_slice = _create_arch_slice("X86_64", size=55000)
        armv7_slice = _create_arch_slice("ARMV7", size=40000)
        binary_analysis = _create_binary_analysis("MyApp", [arm64_slice, x86_64_slice, armv7_slice])

        builder = MachOElementBuilder(
            filesystem_block_size=4096,
            binary_analysis_map={"MyApp": binary_analysis},
        )

        file_info = _create_file_info("MyApp", 140000)
        element = builder.build_element(file_info, "MyApp")

        assert element is not None
        assert len(element.children) == 3

        sizes_by_arch = {c.name: c.size for c in element.children}
        assert sizes_by_arch["ARM64"] == 45000
        assert sizes_by_arch["X86_64"] == 55000
        assert sizes_by_arch["ARMV7"] == 40000

    def test_binary_not_in_map_returns_none(self):
        """Binary not in analysis map should return None."""
        builder = MachOElementBuilder(
            filesystem_block_size=4096,
            binary_analysis_map={},
        )

        file_info = _create_file_info("UnknownBinary", 100000)
        element = builder.build_element(file_info, "UnknownBinary")

        assert element is None


class TestMachOElementBuilderKnownLibraryGrouping:
    """Tests for grouping recognized library modules under a "Libraries" node."""

    def _build(self, groups: list[SwiftSymbolTypeGroup]) -> TreemapElement:
        arch_slice = _create_arch_slice_with_swift_modules("ARM64", size=100000, groups=groups)
        binary_analysis = _create_binary_analysis("MyApp", [arch_slice])
        builder = MachOElementBuilder(
            filesystem_block_size=4096,
            binary_analysis_map={"MyApp": binary_analysis},
        )
        element = builder.build_element(_create_file_info("MyApp", 100000), "MyApp")
        assert element is not None
        return element

    def test_known_library_grouped_app_module_stays_flat(self):
        element = self._build(
            [
                _swift_group("Alamofire", "Session", 500),
                _swift_group("MyApp", "ViewController", 300),
            ]
        )

        # App module remains a direct child of the binary.
        my_app = _find_child(element, "MyApp")
        assert my_app is not None
        assert my_app.size == 300

        # Recognized library is moved under a "Libraries" node.
        assert _find_child(element, "Alamofire") is None
        libraries = _find_child(element, "Libraries")
        assert libraries is not None
        assert libraries.type == TreemapType.MODULES

        alamofire = _find_child(libraries, "Alamofire")
        assert alamofire is not None
        assert alamofire.size == 500
        assert libraries.size == 500

    def test_multiple_modules_collapse_into_one_library(self):
        element = self._build(
            [
                _swift_group("FirebaseCore", "App", 400),
                _swift_group("FirebaseAnalytics", "Logger", 600),
            ]
        )

        libraries = _find_child(element, "Libraries")
        assert libraries is not None

        firebase = _find_child(libraries, "Firebase")
        assert firebase is not None
        assert firebase.size == 1000
        child_names = {c.name for c in firebase.children}
        assert child_names == {"FirebaseCore", "FirebaseAnalytics"}

    def test_no_libraries_node_when_nothing_recognized(self):
        element = self._build([_swift_group("MyApp", "ViewController", 300)])

        assert _find_child(element, "Libraries") is None
        assert _find_child(element, "MyApp") is not None
