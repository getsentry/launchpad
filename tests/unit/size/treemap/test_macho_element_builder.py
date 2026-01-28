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
from launchpad.size.models.treemap import TreemapType
from launchpad.size.treemap.macho_element_builder import MachOElementBuilder


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
