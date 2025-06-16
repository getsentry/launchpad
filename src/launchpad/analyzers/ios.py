"""iOS app bundle analyzer using LIEF for Mach-O parsing."""

from __future__ import annotations

import os
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List

import lief

from launchpad.artifacts.artifact import IOSArtifact

from ..artifacts import ZippedXCArchive
from ..models import DuplicateFileGroup, FileAnalysis, FileInfo, IOSAnalysisResults, IOSAppInfo, IOSBinaryAnalysis
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
        skip_range_mapping: bool = False,
        skip_treemap: bool = False,
    ) -> None:
        """Initialize the iOS analyzer.

        Args:
            working_dir: Directory for temporary files (None for system temp)
            skip_swift_metadata: Skip Swift metadata extraction for faster analysis
            skip_symbols: Skip symbol extraction for faster analysis
            skip_range_mapping: Skip range mapping for binary content categorization
            skip_treemap: Skip treemap generation for hierarchical size analysis
        """
        self.working_dir = working_dir
        self.skip_swift_metadata = skip_swift_metadata
        self.skip_symbols = skip_symbols
        self.skip_range_mapping = skip_range_mapping
        self.skip_treemap = skip_treemap
        self.binary_analysis: IOSBinaryAnalysis | None = None

    def analyze(self, artifact: IOSArtifact) -> IOSAnalysisResults:
        """Analyze an iOS app bundle.

        Args:
            artifact: IOSArtifact to analyze

        Returns:
            Analysis results including file sizes, binary analysis, and treemap
        """
        if not isinstance(artifact, ZippedXCArchive):
            raise NotImplementedError(f"Only ZippedXCArchive artifacts are supported, got {type(artifact)}")

        analysis_start_time = time.time()

        # Extract basic app information
        app_info = self._extract_app_info(artifact)
        logger.info(f"Analyzing app: {app_info.name} v{app_info.version}")

        file_analysis = self._analyze_files(artifact)
        logger.info(f"Found {file_analysis.file_count} files, " f"total size: {file_analysis.total_size} bytes")

        treemap = None
        binary_analysis: List[IOSBinaryAnalysis] = []
        binary_analysis_map: Dict[str, IOSBinaryAnalysis] = {}

        if not self.skip_treemap:
            # Collect all binaries first if range mapping is enabled
            if not self.skip_range_mapping:
                # Analyze main executable
                main_executable = artifact.get_plist().get("CFBundleExecutable")
                if main_executable is None:
                    raise RuntimeError("CFBundleExecutable not found in Info.plist")
                app_bundle_path = artifact.get_app_bundle_path()
                main_binary_path = Path(os.path.join(str(app_bundle_path), main_executable))
                main_binary = self._analyze_binary(main_binary_path, skip_swift_metadata=self.skip_swift_metadata)
                if main_binary.range_map is not None:
                    binary_analysis.append(main_binary)
                    binary_analysis_map[main_executable] = main_binary

                # Analyze frameworks
                for framework_path in app_bundle_path.rglob("*.framework"):
                    if framework_path.is_dir():
                        framework_name = framework_path.stem
                        framework_binary_path = framework_path / framework_name
                        framework_binary = self._analyze_binary(framework_binary_path, skip_swift_metadata=True)
                        if framework_binary.range_map is not None:
                            binary_analysis.append(framework_binary)
                            binary_analysis_map[framework_name] = framework_binary

            treemap_builder = TreemapBuilder(
                app_name=app_info.name,
                platform="ios",
                download_compression_ratio=0.8,  # TODO: implement this
                binary_analysis_map=binary_analysis_map,
            )
            treemap = treemap_builder.build_file_treemap(file_analysis)

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

    def _analyze_binary(self, binary_path: Path, skip_swift_metadata: bool = False) -> IOSBinaryAnalysis:
        """Analyze a binary file using LIEF.

        Args:
            binary_path: Path to the binary file
            skip_swift_metadata: Whether to skip Swift metadata extraction

        Returns:
            Binary analysis results
        """
        if not binary_path.exists():
            logger.warning(f"Binary not found: {binary_path}")
            return IOSBinaryAnalysis(
                executable_size=0,
                architectures=[],
                linked_libraries=[],
                sections={},
                swift_metadata=None,
                range_map=None,
            )

        logger.debug(f"Analyzing binary: {binary_path}")

        fat_binary = lief.MachO.parse(str(binary_path))

        if fat_binary is None or fat_binary.size == 0:
            raise RuntimeError(f"Failed to parse binary with LIEF: {binary_path}")

        binary = fat_binary.at(0)
        executable_size = get_file_size(binary_path)

        # Create parser for this binary
        parser = MachOParser(binary)

        # Extract basic information using the parser
        architectures = parser.extract_architectures()
        linked_libraries = parser.extract_linked_libraries()
        sections = parser.extract_sections()

        # Extract Swift metadata if requested
        swift_metadata = None
        if not skip_swift_metadata:
            # TODO: Implement Swift metadata extraction
            pass

        # Create range mapping if enabled
        range_map = None
        if not self.skip_range_mapping:
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
