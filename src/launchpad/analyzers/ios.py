"""iOS app bundle analyzer using LIEF for Mach-O parsing."""

from __future__ import annotations

import plistlib
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List

import lief

from launchpad.models.ios import IOSAnalysisResults, IOSAppInfo
from launchpad.models.treemap import TreemapResults
from launchpad.utils.treemap_builder import TreemapBuilder

from ..models import DuplicateFileGroup, FileAnalysis, FileInfo, IOSBinaryAnalysis
from ..parsers.ios.macho_parser import MachOParser
from ..parsers.ios.range_mapping_builder import RangeMappingBuilder
from ..utils.file_utils import (
    calculate_file_hash,
    cleanup_directory,
    create_temp_directory,
    extract_archive,
    find_app_bundle,
    get_file_size,
)
from ..utils.logging import get_logger

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
        self._temp_dirs: List[Path] = []

    def analyze(self, input_path: Path) -> IOSAnalysisResults:
        """Analyze an iOS app bundle.

        Args:
            input_path: Path to zip archive

        Returns:
            Complete analysis results

        Raises:
            ValueError: If input is not a valid iOS app bundle
            RuntimeError: If analysis fails
        """
        logger.info(f"Starting iOS analysis of {input_path}")

        analysis_start_time = time.time()

        try:
            # Prepare app bundle for analysis
            app_bundle_path = self._prepare_app_bundle(input_path)

            # Extract basic app information
            app_info = self._extract_app_info(app_bundle_path)
            logger.info(f"Analyzing app: {app_info.name} v{app_info.version}")

            # Analyze files in the bundle
            file_analysis = self._analyze_files(app_bundle_path)
            logger.info(f"Found {file_analysis.file_count} files, " f"total size: {file_analysis.total_size} bytes")

            # Generate treemap if enabled
            treemap_results = None
            if self.enable_treemap:
                treemap_results = self._generate_treemap(app_info, file_analysis)
                logger.info(f"Generated treemap with {treemap_results.file_count} files")

            # Analyze the main executable binary
            binary_analysis = self._analyze_binary(app_bundle_path, app_info.executable)
            logger.info(f"Binary analysis complete, " f"executable size: {binary_analysis.executable_size} bytes")

            return IOSAnalysisResults(
                app_info=app_info,
                file_analysis=file_analysis,
                binary_analysis=binary_analysis,
                analysis_duration=time.time() - analysis_start_time,
                treemap=treemap_results,
            )

        finally:
            self._cleanup()

    def _prepare_app_bundle(self, input_path: Path) -> Path:
        """Prepare the app bundle for analysis, extracting if necessary.

        Args:
            input_path: Input path (could be .app, .ipa, or .zip)

        Returns:
            Path to the .app bundle directory
        """

        logger.debug("Extracting archive to temporary directory")
        temp_dir = create_temp_directory("ios-analysis-")
        self._temp_dirs.append(temp_dir)

        extract_archive(input_path, temp_dir)
        return find_app_bundle(temp_dir, platform="ios")

    def _extract_app_info(self, app_bundle_path: Path) -> IOSAppInfo:
        """Extract basic app information from Info.plist.

        Args:
            app_bundle_path: Path to the .app bundle

        Returns:
            App information

        Raises:
            RuntimeError: If Info.plist cannot be read
        """
        info_plist_path = app_bundle_path / "Info.plist"

        if not info_plist_path.exists():
            raise RuntimeError(f"Info.plist not found in {app_bundle_path}")

        try:
            with open(info_plist_path, "rb") as f:
                plist_data = plistlib.load(f)

            return IOSAppInfo(
                name=plist_data.get("CFBundleDisplayName") or plist_data.get("CFBundleName", "Unknown"),
                bundle_id=plist_data.get("CFBundleIdentifier", "unknown.bundle.id"),
                version=plist_data.get("CFBundleShortVersionString", "Unknown"),
                build=plist_data.get("CFBundleVersion", "Unknown"),
                executable=plist_data.get("CFBundleExecutable", "Unknown"),
                minimum_os_version=plist_data.get("MinimumOSVersion", "Unknown"),
                supported_platforms=plist_data.get("CFBundleSupportedPlatforms", []),
                sdk_version=plist_data.get("DTSDKName"),
            )

        except Exception as e:
            raise RuntimeError(f"Failed to parse Info.plist: {e}")

    def _analyze_files(self, app_bundle_path: Path) -> FileAnalysis:
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

    def _analyze_binary(self, app_bundle_path: Path, executable_name: str) -> IOSBinaryAnalysis:
        """Analyze the main executable binary using LIEF.

        Args:
            app_bundle_path: Path to the .app bundle
            executable_name: Name of the main executable

        Returns:
            Binary analysis results
        """
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

        try:
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

        except Exception as e:
            logger.error(f"Failed to analyze binary: {e}")
            return IOSBinaryAnalysis(
                executable_size=get_file_size(executable_path),
                architectures=[],
                linked_libraries=[],
                sections={},
                swift_metadata=None,
                range_map=None,
            )

    def _cleanup(self) -> None:
        """Clean up temporary directories."""
        for temp_dir in self._temp_dirs:
            try:
                cleanup_directory(temp_dir)
            except Exception as e:
                logger.warning(f"Failed to cleanup {temp_dir}: {e}")
        self._temp_dirs.clear()
