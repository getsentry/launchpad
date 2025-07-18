"""Apple app bundle analyzer using LIEF for Mach-O parsing."""

from __future__ import annotations

import subprocess

from pathlib import Path
from typing import Any, Dict, List, Tuple

import lief

from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive
from launchpad.artifacts.artifact import AppleArtifact
from launchpad.parsers.apple.macho_parser import MachOParser
from launchpad.parsers.apple.macho_size_analyzer import MachOSizeAnalyzer
from launchpad.parsers.apple.macho_symbol_sizes import MachOSymbolSizes
from launchpad.parsers.apple.objc_symbol_type_aggregator import ObjCSymbolTypeAggregator
from launchpad.parsers.apple.swift_symbol_type_aggregator import SwiftSymbolTypeAggregator
from launchpad.size.hermes.utils import make_hermes_reports
from launchpad.size.insights.apple.localized_strings import LocalizedStringsInsight
from launchpad.size.insights.apple.loose_images import LooseImagesInsight
from launchpad.size.insights.apple.small_files import SmallFilesInsight
from launchpad.size.insights.apple.strip_symbols import StripSymbolsInsight
from launchpad.size.insights.common.duplicate_files import DuplicateFilesInsight
from launchpad.size.insights.common.hermes_debug_info import (
    HermesDebugInfoInsight,
)
from launchpad.size.insights.common.large_audios import LargeAudioFileInsight
from launchpad.size.insights.common.large_images import LargeImageFileInsight
from launchpad.size.insights.common.large_videos import LargeVideoFileInsight
from launchpad.size.insights.insight import InsightsInput
from launchpad.size.models.common import FileAnalysis, FileInfo
from launchpad.size.models.treemap import FILE_TYPE_TO_TREEMAP_TYPE, TreemapElement, TreemapType
from launchpad.size.treemap.treemap_builder import TreemapBuilder
from launchpad.size.utils.apple_bundle_size import calculate_bundle_sizes
from launchpad.utils.apple.code_signature_validator import CodeSignatureValidator
from launchpad.utils.file_utils import calculate_file_hash, get_file_size
from launchpad.utils.logging import get_logger
from launchpad.utils.performance import trace, trace_ctx

from ..models.apple import (
    AppleAnalysisResults,
    AppleAppInfo,
    AppleInsightResults,
    MachOBinaryAnalysis,
    SwiftMetadata,
    SymbolInfo,
)

logger = get_logger(__name__)


class AppleAppAnalyzer:
    """Analyzer for Apple app bundles (.xcarchive directories)."""

    def __init__(
        self,
        working_dir: Path | None = None,
        skip_swift_metadata: bool = False,
        skip_symbols: bool = False,
        skip_component_analysis: bool = False,
        skip_treemap: bool = False,
        skip_image_analysis: bool = False,
        skip_insights: bool = False,
    ) -> None:
        """Initialize the Apple analyzer.

        Args:
            working_dir: Directory for temporary files (None for system temp)
            skip_swift_metadata: Skip Swift metadata extraction for faster analysis
            skip_symbols: Skip symbol extraction for faster analysis
            skip_component_analysis: Skip detailed binary component analysis for faster processing
            skip_treemap: Skip treemap generation for hierarchical size analysis
            skip_image_analysis: Skip image analysis for faster processing
            skip_insights: Skip insights generation for faster analysis
        """
        self.working_dir = working_dir
        self.skip_swift_metadata = skip_swift_metadata
        self.skip_symbols = skip_symbols
        self.skip_component_analysis = skip_component_analysis
        self.skip_treemap = skip_treemap
        self.skip_image_analysis = skip_image_analysis
        self.skip_insights = skip_insights
        self.app_info: AppleAppInfo | None = None

    @trace("apple.preprocess")
    def preprocess(self, artifact: AppleArtifact) -> AppleAppInfo:
        if not isinstance(artifact, ZippedXCArchive):
            raise NotImplementedError(f"Only ZippedXCArchive artifacts are supported, got {type(artifact)}")

        self.app_info = self._extract_app_info(artifact)
        return self.app_info

    @trace("apple.analyze")
    def analyze(self, artifact: AppleArtifact) -> AppleAnalysisResults:
        """Analyze an Apple app bundle.

        Args:
            artifact: AppleArtifact to analyze

        Returns:
            Analysis results including file sizes, binary analysis, and treemap
        """
        if not isinstance(artifact, ZippedXCArchive):
            raise NotImplementedError(f"Only ZippedXCArchive artifacts are supported, got {type(artifact)}")

        if not self.app_info:
            self.app_info = self.preprocess(artifact)

        app_info = self.app_info
        logger.info(f"Analyzing app: {app_info.name} v{app_info.version}")

        file_analysis = self._analyze_files(artifact)
        logger.info(f"Found {file_analysis.file_count} files, total size: {file_analysis.total_size} bytes")

        app_bundle_path = artifact.get_app_bundle_path()
        download_size, install_size = calculate_bundle_sizes(app_bundle_path)
        logger.info(f"Download size: {download_size} bytes, Install size: {install_size} bytes")

        treemap = None
        binary_analysis: List[MachOBinaryAnalysis] = []
        binary_analysis_map: Dict[str, MachOBinaryAnalysis] = {}
        hermes_reports = {}

        if not self.skip_treemap and not self.skip_component_analysis:
            binaries = artifact.get_all_binary_paths()
            logger.info(f"Found {len(binaries)} binaries to analyze")

            for binary_info in binaries:
                logger.info(f"Analyzing binary {binary_info.name} at {binary_info.path}")
                if binary_info.dsym_path:
                    logger.debug(f"Found dSYM file for {binary_info.name} at {binary_info.dsym_path}")
                binary = self._analyze_binary(binary_info.path, binary_info.dsym_path)
                if binary.binary_analysis is not None:
                    binary_analysis.append(binary)
                    binary_analysis_map[str(binary_info.path.relative_to(app_bundle_path))] = binary

            hermes_reports = make_hermes_reports(app_bundle_path)

            compression_ratio = download_size / install_size if install_size > 0 else 1

            treemap_builder = TreemapBuilder(
                app_name=app_info.name,
                platform="ios",
                download_compression_ratio=compression_ratio,
                binary_analysis_map=binary_analysis_map,
                hermes_reports=hermes_reports,
            )
            treemap = treemap_builder.build_file_treemap(file_analysis)

        insights: AppleInsightResults | None = None
        if not self.skip_insights:
            logger.info("Generating insights from analysis results")
            insights_input = InsightsInput(
                app_info=app_info,
                file_analysis=file_analysis,
                binary_analysis=binary_analysis,
                treemap=treemap,
                hermes_reports=hermes_reports,
            )
            insights = AppleInsightResults(
                duplicate_files=self._generate_insight_with_tracing(
                    DuplicateFilesInsight, insights_input, "duplicate_files"
                ),
                large_audio=self._generate_insight_with_tracing(LargeAudioFileInsight, insights_input, "large_audio"),
                large_images=self._generate_insight_with_tracing(LargeImageFileInsight, insights_input, "large_images"),
                large_videos=self._generate_insight_with_tracing(LargeVideoFileInsight, insights_input, "large_videos"),
                strip_binary=self._generate_insight_with_tracing(StripSymbolsInsight, insights_input, "strip_binary"),
                localized_strings=self._generate_insight_with_tracing(
                    LocalizedStringsInsight, insights_input, "localized_strings"
                ),
                hermes_debug_info=self._generate_insight_with_tracing(
                    HermesDebugInfoInsight, insights_input, "hermes_debug_info"
                ),
                small_files=self._generate_insight_with_tracing(SmallFilesInsight, insights_input, "small_files"),
                loose_images=self._generate_insight_with_tracing(LooseImagesInsight, insights_input, "loose_images"),
            )

        results = AppleAnalysisResults(
            app_info=app_info,
            file_analysis=file_analysis,
            binary_analysis=binary_analysis,
            treemap=treemap,
            insights=insights,
            analysis_duration=None,
            use_si_units=True,
            download_size=download_size,
            install_size=install_size,
        )

        return results

    @trace("apple.extract_app_info")
    def _extract_app_info(self, xcarchive: ZippedXCArchive) -> AppleAppInfo:
        """Extract basic app information.

        Returns:
            App information

        Raises:
            RuntimeError: If Info.plist cannot be read
        """
        plist = xcarchive.get_plist()
        provisioning_profile = xcarchive.get_provisioning_profile()
        codesigning_type = None
        profile_name = None
        if provisioning_profile:
            codesigning_type, profile_name = self._get_profile_type(provisioning_profile)

        supported_platforms = plist.get("CFBundleSupportedPlatforms", [])
        is_simulator = "iphonesimulator" in supported_platforms or plist.get("DTPlatformName") == "iphonesimulator"

        is_code_signature_valid = False
        code_signature_errors: List[str] = []
        try:
            validator = CodeSignatureValidator(xcarchive)
            is_code_signature_valid, code_signature_errors = validator.validate()
        except Exception as e:
            logger.warning(f"Failed to validate code signature: {e}")
            is_code_signature_valid = False
            code_signature_errors = [str(e)]

        return AppleAppInfo(
            name=plist.get("CFBundleName", "Unknown"),
            app_id=plist.get("CFBundleIdentifier", "unknown.bundle.id"),
            version=plist.get("CFBundleShortVersionString", "Unknown"),
            build=plist.get("CFBundleVersion", "Unknown"),
            executable=plist.get("CFBundleExecutable", "Unknown"),
            minimum_os_version=plist.get("MinimumOSVersion", "Unknown"),
            supported_platforms=supported_platforms,
            sdk_version=plist.get("DTSDKName"),
            is_simulator=is_simulator,
            codesigning_type=codesigning_type,
            profile_name=profile_name,
            is_code_signature_valid=is_code_signature_valid,
            code_signature_errors=code_signature_errors,
        )

    @trace("apple.detect_file_type")
    def _detect_file_type(self, file_path: Path) -> str:
        """Detect file type using the file command.

        Args:
            file_path: Path to the file to analyze

        Returns:
            File type string from file command output, normalized to common types
        """
        try:
            result = subprocess.run(["file", str(file_path)], capture_output=True, text=True, check=True)
            # Extract just the file type description after the colon
            file_type = result.stdout.split(":", 1)[1].strip().lower()
            logger.debug(f"Detected file type for {file_path}: {file_type}")

            # Normalize common file types
            if "mach-o" in file_type:
                return "macho"
            elif "executable" in file_type:
                return "executable"
            elif "text" in file_type:
                return "text"
            elif "directory" in file_type:
                return "directory"
            elif "symbolic link" in file_type:
                return "symlink"
            elif "hermes javascript bytecode" in file_type:
                return "hermes"
            elif "empty" in file_type:
                return "empty"

            return file_type
        except subprocess.CalledProcessError as e:
            logger.warning(f"Failed to detect file type for {file_path}: {e}")
            return "unknown"
        except Exception as e:
            logger.warning(f"Unexpected error detecting file type for {file_path}: {e}")
            return "unknown"

    def _get_profile_type(self, profile_data: dict[str, Any]) -> Tuple[str, str]:
        """Determine the type of provisioning profile and its name.
        Args:
            profile_data: Dictionary containing the mobileprovision contents
        Returns:
            Tuple of (profile_type, profile_name)
        """
        profile_name = profile_data.get("Name", "Unknown")

        # Check for enterprise profile
        if profile_data.get("ProvisionsAllDevices"):
            return "enterprise", profile_name

        # Check for development/adhoc profile
        provisioned_devices = profile_data.get("ProvisionedDevices", [])
        if provisioned_devices:
            entitlements = profile_data.get("Entitlements", {})
            aps_environment = entitlements.get("aps-environment")

            if aps_environment == "development":
                if entitlements.get("get-task-allow"):
                    return "development", profile_name
                return "unknown", profile_name
            elif aps_environment == "production":
                return "adhoc", profile_name

            # Check certificate type
            developer_certs = profile_data.get("DeveloperCertificates", [])
            if developer_certs:
                # TODO: Parse DER certificate to check if it's a development certificate
                # For now, default to development if we have a certificate
                return "development", profile_name

        # If no devices are provisioned, it's an app store profile
        return "appstore", profile_name

    @trace("apple.analyze_files")
    def _analyze_files(self, xcarchive: ZippedXCArchive) -> FileAnalysis:
        """Analyze all files in the app bundle.

        Args:
            xcarchive: The XCArchive to analyze

        Returns:
            File analysis results
        """
        logger.debug("Analyzing files in app bundle")

        files: List[FileInfo] = []
        app_bundle_path = xcarchive.get_app_bundle_path()

        # Walk through all files in the bundle
        for file_path in app_bundle_path.rglob("*"):
            if not file_path.is_file():
                continue

            relative_path = file_path.relative_to(app_bundle_path)
            file_size = get_file_size(file_path)

            # Get file type from extension first
            file_type = file_path.suffix.lower().lstrip(".")

            # If no extension or unknown type, use file command
            if not file_type or file_type == "unknown":
                file_type = self._detect_file_type(file_path)

            # Calculate hash for duplicate detection
            file_hash = calculate_file_hash(file_path, algorithm="md5")

            # Analyze image if applicable
            # TODO: image analysis
            # image_analysis_result = None
            # if file_type.lower() in {"png", "jpg", "jpeg", "webp"}:
            #     image_analysis_result = self._analyze_image(file_path, file_size)

            children = []
            if file_type == "car":
                children = self._analyze_asset_catalog(xcarchive, relative_path)
                children_size = sum([child.install_size for child in children])
                children.append(
                    TreemapElement(
                        name="Other",
                        install_size=file_size - children_size,
                        download_size=0,
                        element_type=TreemapType.ASSETS,
                        path=str(relative_path) + "/Other",
                        is_directory=False,
                        children=[],
                        details={},
                    )
                )

            file_info = FileInfo(
                full_path=file_path,
                path=str(relative_path),
                size=file_size,
                file_type=file_type or "unknown",
                hash_md5=file_hash,
                treemap_type=FILE_TYPE_TO_TREEMAP_TYPE.get(file_type, TreemapType.FILES),
                children=children,
            )

            files.append(file_info)

        return FileAnalysis(files=files)

    @trace("apple.analyze_asset_catalog")
    def _analyze_asset_catalog(self, xcarchive: ZippedXCArchive, relative_path: Path) -> List[TreemapElement]:
        """Analyze an asset catalog file."""
        catalog_details = xcarchive.get_asset_catalog_details(relative_path)
        return [
            TreemapElement(
                name=element.name,
                install_size=element.size,
                # TODO: This field should be nullable, it doesn’t make sense
                # to talk about download size of individual assets
                # since they are all in one .car file.
                download_size=0,
                element_type=TreemapType.ASSETS,
                path=str(relative_path) + "/" + element.name,
                is_directory=False,
                children=[],
                details={
                    "type": element.type,
                    "vector": element.vector,
                    "filename": element.filename,
                },
            )
            for element in catalog_details
        ]

    def _generate_insight_with_tracing(
        self, insight_class: type, insights_input: InsightsInput, insight_name: str
    ) -> Any:
        with trace_ctx(f"apple.insights.{insight_name}"):
            return insight_class().generate(insights_input)

    @trace("apple.analyze_binary")
    def _analyze_binary(
        self, binary_path: Path, dwarf_binary_path: Path | None = None, skip_swift_metadata: bool = False
    ) -> MachOBinaryAnalysis:
        if not binary_path.exists():
            logger.warning(f"Binary not found: {binary_path}")
            return MachOBinaryAnalysis(
                binary_path=binary_path,
                executable_size=0,
                architectures=[],
                linked_libraries=[],
                sections={},
                swift_metadata=None,
                binary_analysis=None,
                symbol_info=None,
            )

        logger.debug(f"Analyzing binary: {binary_path}")

        fat_binary = lief.MachO.parse(str(binary_path))  # type: ignore

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
        swift_protocol_conformances = []  # parser.parse_swift_protocol_conformances()
        objc_method_names = parser.parse_objc_method_names()

        symbol_info = None

        # Always test symbol removal on the main app binary (not dSYM)
        strippable_symbols_size = self._test_strip_symbols_removal(parser, binary_path)

        if dwarf_binary_path:
            dwarf_fat_binary = lief.MachO.parse(str(dwarf_binary_path))  # type: ignore
            if dwarf_fat_binary:
                dwarf_binary = dwarf_fat_binary.at(0)
                symbol_sizes = MachOSymbolSizes(dwarf_binary).get_symbol_sizes()
                symbol_info = SymbolInfo(
                    swift_type_groups=SwiftSymbolTypeAggregator().aggregate_symbols(symbol_sizes),
                    objc_type_groups=ObjCSymbolTypeAggregator().aggregate_symbols(symbol_sizes),
                    strippable_symbols_size=strippable_symbols_size,
                )
            else:
                logger.warning(f"Failed to parse dwarf binary: {dwarf_binary_path}")
        else:
            if strippable_symbols_size > 0:
                symbol_info = SymbolInfo(
                    swift_type_groups=[],
                    objc_type_groups=[],
                    strippable_symbols_size=strippable_symbols_size,
                )
            logger.info("No dwarf binary path provided, skipping detailed symbol analysis")

        # Extract Swift metadata if enabled
        swift_metadata = None
        if not skip_swift_metadata:
            swift_metadata = SwiftMetadata(
                protocol_conformances=swift_protocol_conformances,
            )

        # Analyze binary components
        binary_analysis = None
        if not self.skip_component_analysis:
            analyzer = MachOSizeAnalyzer(parser, executable_size, str(binary_path))
            binary_analysis = analyzer.analyze()

        return MachOBinaryAnalysis(
            binary_path=binary_path,
            executable_size=executable_size,
            architectures=architectures,
            linked_libraries=linked_libraries,
            sections=sections,
            swift_metadata=swift_metadata,
            binary_analysis=binary_analysis,
            symbol_info=symbol_info,
            objc_method_names=objc_method_names,
        )

    @trace("apple.test_strip_symbols_removal")
    def _test_strip_symbols_removal(self, parser: MachOParser, binary_path: Path) -> int:
        """Test actual symbol removal using LIEF to get real size savings, similar to what strip does."""
        import tempfile

        try:
            with trace_ctx("strip_symbols.get_original_size"):
                original_size = binary_path.stat().st_size

            with trace_ctx("strip_symbols.check_swift_imageinfo"):
                has_swift_imageinfo = parser.has_swift_imageinfo()

            removable_symbols: list[lief.MachO.Symbol] = []
            total_symbols = 0

            with trace_ctx("strip_symbols.analyze_symbols"):
                for symbol in parser.binary.symbols:
                    total_symbols += 1

                    symbol_name = str(symbol.name) if symbol.name else ""

                    # Additional filtering to match what strip would typically target
                    # Only remove symbols that match strip's typical patterns
                    should_remove = (
                        # Debug symbols (strip -S targets)
                        symbol.type == lief.MachO.Symbol.TYPE.ABSOLUTE_SYM
                        or symbol_name.startswith(("__debug", "__zdebug", "__apple_", "l_OBJC_LABEL_", "ltmp"))
                        or "debug" in symbol_name.lower()
                        or
                        # Local symbols (strip -x targets)
                        symbol.category == lief.MachO.Symbol.CATEGORY.LOCAL
                        or
                        # Swift symbols (strip -T targets) - only if __objc_imageinfo has non-zero Swift version
                        (has_swift_imageinfo and symbol_name.startswith(("_$S", "_$s")))
                        or
                        # Compiler-generated symbols
                        symbol_name.startswith(("L", "l", "_OBJC_$_CATEGORY_", "_OBJC_$_PROP_LIST_"))
                        or
                        # Temporary symbols
                        symbol_name.startswith(("tmp", "temp", "unnamed_"))
                        or
                        # Swift compiler symbols (other than the -T targeted ones)
                        symbol_name.startswith(("__swift_FORCE_LOAD", "__swift_"))
                    )

                    if should_remove:
                        removable_symbols.append(symbol)

            logger.debug(
                f"Symbol removal test for {binary_path.name}: {len(removable_symbols)}/{total_symbols} symbols removable"
            )
            if not removable_symbols:
                return 0

            # Create a copy of the binary and remove the symbols to see the new size
            with trace_ctx("strip_symbols.create_binary_copy"):
                binary_copy = lief.MachO.parse(str(binary_path))  # type: ignore
                if not binary_copy or binary_copy.size == 0:
                    logger.warning("Failed to create binary copy for symbol removal testing")
                    return 0

                binary_copy_obj = binary_copy.at(0)

            with trace_ctx("strip_symbols.remove_symbols"):
                removed_count = 0
                for symbol in removable_symbols:
                    if parser.binary.can_remove(symbol):
                        binary_copy_obj.remove(symbol)
                        removed_count += 1

            logger.debug(f"Successfully removed {removed_count} symbols")
            if removed_count == 0:
                return 0

            with trace_ctx("strip_symbols.write_and_measure"):
                with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                    temp_path = Path(temp_file.name)
                    try:
                        binary_copy_obj.write(str(temp_path))
                        modified_size = temp_path.stat().st_size
                        actual_savings = original_size - modified_size

                        logger.debug(f"Symbol removal savings for {binary_path.name}: {actual_savings:,} bytes")
                        return max(0, actual_savings)

                    finally:
                        try:
                            temp_path.unlink()
                        except Exception:
                            pass

        except Exception as e:
            logger.error(f"Error testing symbol removal for {binary_path}: {e}")
            return 0
