"""iOS app bundle analyzer using LIEF for Mach-O parsing."""

from __future__ import annotations

import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List

import lief

from ..artifacts import ZippedXCArchive
from ..models import (
    DuplicateFileGroup,
    FileAnalysis,
    FileInfo,
    IOSAnalysisResults,
    IOSAppInfo,
    IOSBinaryAnalysis,
    TreemapResults,
    TreemapType,
)
from ..parsers.ios.macho_parser import MachOParser
from ..parsers.ios.range_mapping_builder import RangeMappingBuilder
from ..utils.file_utils import calculate_file_hash, get_file_size
from ..utils.logging import get_logger
from ..utils.treemap_builder import TreemapBuilder

logger = get_logger(__name__)


class IOSAnalyzer:
    """Analyzer for iOS app bundles (.xcarchive directories)."""

    def __init__(
        self,
        working_dir: Path | None = None,
        skip_swift_metadata: bool = False,
        skip_symbols: bool = False,
        enable_range_mapping: bool = True,
        enable_treemap: bool = True,
    ) -> None:
        """Initialize the iOS analyzer.

        Args:
            working_dir: Directory for temporary files (None for system temp)
            skip_swift_metadata: Skip Swift metadata extraction for faster analysis
            skip_symbols: Skip symbol extraction for faster analysis
            enable_range_mapping: Enable range mapping for binary content categorization
            enable_treemap: Enable treemap generation for hierarchical size analysis
        """
        self.working_dir = working_dir
        self.skip_swift_metadata = skip_swift_metadata
        self.skip_symbols = skip_symbols
        self.enable_range_mapping = enable_range_mapping
        self.enable_treemap = enable_treemap
        self.binary_analysis: IOSBinaryAnalysis | None = None

    def analyze(self, input_path: Path) -> IOSAnalysisResults:
        """Analyze an iOS app bundle.

        Args:
            input_path: Path to zip archive

        Returns:
            Analysis results including file sizes, binary analysis, and treemap
        """
        logger.info(f"Starting iOS analysis of {input_path}")
        analysis_start_time = time.time()

        with open(input_path, "rb") as f:
            xcarchive = ZippedXCArchive(f.read())

        app_info = self._extract_app_info(xcarchive)
        logger.info(f"Analyzing app: {app_info.name} v{app_info.version}")

        file_analysis = self._analyze_files(xcarchive)
        logger.info(f"Found {file_analysis.file_count} files, " f"total size: {file_analysis.total_size} bytes")

        treemap = None
        binary_analysis: List[IOSBinaryAnalysis] = []

        if self.enable_treemap:
            treemap_builder = TreemapBuilder(
                app_name=app_info.name,
                platform="ios",
                download_compression_ratio=0.8,  # TODO: implement this
            )
            treemap = treemap_builder.build_file_treemap(file_analysis)

            # If range mapping is enabled, add binary section details to treemap
            if self.enable_range_mapping:
                binary_analysis_result = self._analyze_binary(xcarchive)
                if binary_analysis_result.range_map is not None:
                    binary_analysis.append(binary_analysis_result)
                    binary_treemap = treemap_builder.build_binary_treemap(
                        binary_analysis_result.range_map,
                        app_info.name,
                    )
                    # Find and replace the existing binary node
                    executable_name = xcarchive.get_plist().get("CFBundleExecutable", "Unknown")
                    for i, child in enumerate(treemap.root.children):
                        if child.name == executable_name and (
                            child.element_type == TreemapType.EXECUTABLES or child.element_type == TreemapType.FILES
                        ):
                            treemap.root.children[i] = binary_treemap
                            break
                    else:
                        # If no matching node found, append as a new child
                        treemap.root.children.append(binary_treemap)

        results = IOSAnalysisResults(
            app_info=app_info,
            file_analysis=file_analysis,
            binary_analysis=binary_analysis,
            analysis_duration=time.time() - analysis_start_time,
            treemap=treemap,
        )

        logger.info(f"Analysis complete in {results.analysis_duration:.1f}s")
        return results

    def _extract_app_info(self, xcarchive: ZippedXCArchive) -> IOSAppInfo:
        """Extract basic app information from Info.plist.

        Returns:
            App information

        Raises:
            RuntimeError: If Info.plist cannot be read
        """
        plist = xcarchive.get_plist()
        return IOSAppInfo(
            name=plist.get("CFBundleName", "Unknown"),
            bundle_id=plist.get("CFBundleIdentifier", "unknown.bundle.id"),
            version=plist.get("CFBundleShortVersionString", "Unknown"),
            build=plist.get("CFBundleVersion", "Unknown"),
            executable=plist.get("CFBundleExecutable", "Unknown"),
            minimum_os_version=plist.get("MinimumOSVersion", "Unknown"),
            supported_platforms=plist.get("CFBundleSupportedPlatforms", []),
            sdk_version=plist.get("DTSDKName"),
        )

    def _analyze_files(self, xcarchive: ZippedXCArchive) -> FileAnalysis:
        """Analyze all files in the app bundle.

        Args:
            app_bundle_path: Path to the .app bundle

        Returns:
            File analysis results
        """
        logger.debug("Analyzing files in app bundle")

        files: List[FileInfo] = []
        files_by_type: Dict[str, List[FileInfo]] = defaultdict(list)
        files_by_hash: Dict[str, List[FileInfo]] = defaultdict(list)
        total_size = 0

        # Walk through all files in the bundle
        app_bundle_path = xcarchive.get_app_bundle_path()
        for file_path in app_bundle_path.rglob("*"):
            if not file_path.is_file():
                continue

            relative_path = file_path.relative_to(app_bundle_path)
            file_size = get_file_size(file_path)
            file_type = file_path.suffix.lower().lstrip(".")

            # Calculate hash for duplicate detection
            file_hash = calculate_file_hash(file_path, algorithm="md5")

            file_info = FileInfo(
                path=str(relative_path),
                size=file_size,
                file_type=file_type or "unknown",
                hash_md5=file_hash,
            )

            files.append(file_info)
            files_by_type[file_info.file_type].append(file_info)
            files_by_hash[file_hash].append(file_info)
            total_size += file_size

        # Find duplicate files
        duplicate_groups: List[DuplicateFileGroup] = []
        for file_hash, file_list in files_by_hash.items():
            if len(file_list) > 1:
                # Calculate potential savings (all files except one)
                total_file_size = sum(f.size for f in file_list)
                savings = total_file_size - file_list[0].size

                if savings > 0:  # Only include if there are actual savings
                    duplicate_groups.append(
                        DuplicateFileGroup(
                            files=file_list,
                            potential_savings=savings,
                        )
                    )

        # Sort files by size for largest files list
        largest_files = sorted(files, key=lambda f: f.size, reverse=True)[:20]

        # Sort duplicate groups by potential savings
        duplicate_groups.sort(key=lambda g: g.potential_savings, reverse=True)

        return FileAnalysis(
            total_size=total_size,
            file_count=len(files),
            files_by_type=dict(files_by_type),
            duplicate_files=duplicate_groups,
            largest_files=largest_files,
        )

    def _generate_treemap(self, app_info: IOSAppInfo, file_analysis: FileAnalysis) -> TreemapResults:
        """Generate treemap for hierarchical size analysis."""
        logger.debug("Generating treemap for file hierarchy")

        # TODO: implement the compression ratio
        treemap_builder = TreemapBuilder(app_name=app_info.name, platform="ios", download_compression_ratio=0.75)
        return treemap_builder.build_file_treemap(file_analysis)

    def _analyze_binary(self, xcarchive: ZippedXCArchive) -> IOSBinaryAnalysis:
        """Analyze the main executable binary using LIEF.

        Args:
            app_bundle_path: Path to the .app bundle
            executable_name: Name of the main executable

        Returns:
            Binary analysis results
        """
        executable_name = xcarchive.get_plist().get("CFBundleExecutable", "Unknown")
        app_bundle_path = xcarchive.get_app_bundle_path()
        executable_path = app_bundle_path / executable_name

        if not executable_path.exists():
            logger.warning(f"Executable not found: {executable_path}")
            return IOSBinaryAnalysis(
                executable_size=0,
                architectures=[],
                linked_libraries=[],
                sections={},
                swift_metadata=None,
                range_map=None,
            )

        logger.debug(f"Analyzing binary: {executable_path}")

        # TODO: Potentially move this to the artifact impl
        fat_binary = lief.MachO.parse(str(executable_path))

        if fat_binary is None or fat_binary.size == 0:
            raise RuntimeError("Failed to parse binary with LIEF")

        binary = fat_binary.at(0)
        executable_size = get_file_size(executable_path)

        # Create parser for this binary
        parser = MachOParser(binary)

        # Extract basic information using the parser
        architectures = parser.extract_architectures()
        linked_libraries = parser.extract_linked_libraries()
        sections = parser.extract_sections()

        # Extract Swift metadata if requested
        # TODO: Implement Swift metadata extraction
        swift_metadata = None
        # if not self.skip_swift_metadata:
        #     swift_metadata = parser.extract_swift_metadata()

        # Create range mapping if enabled
        range_map = None
        if self.enable_range_mapping:
            range_builder = RangeMappingBuilder(parser, executable_size)
            range_map = range_builder.build_range_mapping()

        return IOSBinaryAnalysis(
            executable_size=executable_size,
            architectures=architectures,
            linked_libraries=linked_libraries,
            sections=sections,
            swift_metadata=swift_metadata,
            range_map=range_map,
        )
