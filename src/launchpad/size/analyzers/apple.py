"""Apple app bundle analyzer using LIEF for Mach-O parsing."""

from __future__ import annotations

import gc
import os
import tempfile
import time

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

import lief
import sentry_sdk

from cryptography import x509

from launchpad.artifacts.apple.zipped_xcarchive import BinaryInfo, ZippedXCArchive
from launchpad.artifacts.artifact import AppleArtifact
from launchpad.parsers.apple.dwarf_relocations_parser import DwarfRelocationsParser
from launchpad.parsers.apple.macho_parser import MachOParser
from launchpad.size.constants import APPLE_FILESYSTEM_BLOCK_SIZE
from launchpad.size.hermes.utils import make_hermes_reports
from launchpad.size.insights.apple.image_optimization import ImageOptimizationInsight
from launchpad.size.insights.apple.localized_strings_minify import MinifyLocalizedStringsInsight
from launchpad.size.insights.apple.loose_images import LooseImagesInsight
from launchpad.size.insights.apple.main_binary_export_metadata import MainBinaryExportMetadataInsight
from launchpad.size.insights.apple.small_files import SmallFilesInsight
from launchpad.size.insights.apple.strip_symbols import StripSymbolsInsight
from launchpad.size.insights.apple.unnecessary_files import UnnecessaryFilesInsight
from launchpad.size.insights.common.duplicate_files import DuplicateFilesInsight
from launchpad.size.insights.common.hermes_debug_info import HermesDebugInfoInsight
from launchpad.size.insights.common.large_audios import LargeAudioFileInsight
from launchpad.size.insights.common.large_images import LargeImageFileInsight
from launchpad.size.insights.common.large_videos import LargeVideoFileInsight
from launchpad.size.insights.insight import InsightsInput
from launchpad.size.models.common import APPLE_ANALYSIS_VERSION
from launchpad.size.symbols.macho_symbol_sizes import MachOSymbolSizes
from launchpad.size.treemap.treemap_builder import TreemapBuilder
from launchpad.size.utils.apple_bundle_size import calculate_bundle_sizes
from launchpad.size.utils.file_analysis import analyze_apple_files
from launchpad.utils.apple.apple_strip import AppleStrip
from launchpad.utils.apple.code_signature_validator import CodeSignatureValidator
from launchpad.utils.file_utils import get_file_size, to_nearest_block_size
from launchpad.utils.logging import get_logger

from ..models.apple import (
    AppleAnalysisResults,
    AppleAppInfo,
    AppleInsightResults,
    LoadCommandInfo,
    MachOBinaryAnalysis,
    SectionInfo,
    SegmentInfo,
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

    @sentry_sdk.trace
    def preprocess(self, artifact: AppleArtifact) -> AppleAppInfo:
        if not isinstance(artifact, ZippedXCArchive):
            raise NotImplementedError(f"Only ZippedXCArchive artifacts are supported, got {type(artifact)}")

        self.app_info = self._extract_app_info(artifact)
        return self.app_info

    @sentry_sdk.trace
    def analyze(self, artifact: AppleArtifact) -> AppleAnalysisResults:
        """Analyze an Apple app bundle.

        Args:
            artifact: AppleArtifact to analyze

        Returns:
            Analysis results including file sizes, binary analysis, and treemap
        """
        start_time = time.time()
        if not isinstance(artifact, ZippedXCArchive):
            raise NotImplementedError(f"Only ZippedXCArchive artifacts are supported, got {type(artifact)}")

        if not self.app_info:
            self.app_info = self.preprocess(artifact)

        app_info = self.app_info
        logger.info(
            "size.apple.analyze_app",
            extra={"app_name": app_info.name, "app_version": app_info.version},
        )

        file_analysis = analyze_apple_files(artifact)
        logger.debug(f"Found {len(file_analysis.files)} files, total size: {file_analysis.total_size} bytes")

        app_bundle_path = artifact.get_app_bundle_path()

        bundle_sizes = calculate_bundle_sizes(app_bundle_path, app_info.name)
        total_download_size = bundle_sizes.total_download
        total_install_size = bundle_sizes.total_install
        app_components = bundle_sizes.app_components
        logger.info(
            "size.apple.bundle_sizes",
            extra={
                "download_size": total_download_size,
                "install_size": total_install_size,
                "app_components": [component.model_dump() for component in app_components],
            },
        )

        treemap = None
        binary_analysis: List[MachOBinaryAnalysis] = []
        binary_analysis_map: Dict[str, MachOBinaryAnalysis] = {}
        hermes_reports = {}

        if not self.skip_treemap and not self.skip_component_analysis:
            binaries = artifact.get_all_binary_paths()
            logger.debug(f"Found {len(binaries)} binaries to analyze")

            for binary_info in binaries:
                logger.info(
                    "size.apple.binary_analysis_started",
                    extra={
                        "event": "size.binary_analysis_started",
                        "binary_name": binary_info.name,
                        "binary_path": str(binary_info.path.relative_to(app_bundle_path)),
                        "has_dsym": binary_info.dsym_path is not None,
                    },
                )
                if binary_info.dsym_path:
                    logger.debug(
                        f"Found dSYM file for {binary_info.name} at {binary_info.dsym_path.relative_to(artifact.get_extract_dir())}"
                    )
                binary = self._analyze_binary(binary_info, app_bundle_path)
                if binary is not None:
                    binary_analysis.append(binary)
                    binary_analysis_map[str(binary_info.path.relative_to(app_bundle_path))] = binary

                logger.info(
                    "size.apple.binary_analysis_completed",
                    extra={
                        "event": "size.binary_analysis_completed",
                        "binary_name": binary_info.name,
                        "symbol_count": (len(binary.symbol_info.symbol_sizes) if binary.symbol_info else 0),
                        "swift_types_count": (len(binary.symbol_info.swift_type_groups) if binary.symbol_info else 0),
                        "objc_types_count": (len(binary.symbol_info.objc_type_groups) if binary.symbol_info else 0),
                    },
                )
                gc.collect()

            hermes_reports = make_hermes_reports(app_bundle_path)

            treemap_builder = TreemapBuilder(
                app_name=app_info.name,
                platform="ios",
                binary_analysis_map=binary_analysis_map,
                hermes_reports=hermes_reports,
            )
            treemap = treemap_builder.build_file_treemap(file_analysis)

        insights: AppleInsightResults | None = None
        if not self.skip_insights:
            logger.info("size.apple.generate_insights")
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
                large_images=self._generate_insight_with_tracing(LargeImageFileInsight, insights_input, "large_images"),
                large_audios=self._generate_insight_with_tracing(LargeAudioFileInsight, insights_input, "large_audios"),
                large_videos=self._generate_insight_with_tracing(LargeVideoFileInsight, insights_input, "large_videos"),
                strip_binary=self._generate_insight_with_tracing(StripSymbolsInsight, insights_input, "strip_binary"),
                localized_strings_minify=self._generate_insight_with_tracing(
                    MinifyLocalizedStringsInsight,
                    insights_input,
                    "localized_strings_minify",
                ),
                hermes_debug_info=self._generate_insight_with_tracing(
                    HermesDebugInfoInsight, insights_input, "hermes_debug_info"
                ),
                small_files=self._generate_insight_with_tracing(SmallFilesInsight, insights_input, "small_files"),
                loose_images=self._generate_insight_with_tracing(LooseImagesInsight, insights_input, "loose_images"),
                image_optimization=self._generate_insight_with_tracing(
                    ImageOptimizationInsight, insights_input, "image_optimization"
                ),
                main_binary_exported_symbols=self._generate_insight_with_tracing(
                    MainBinaryExportMetadataInsight,
                    insights_input,
                    "main_binary_exported_symbols",
                ),
                unnecessary_files=self._generate_insight_with_tracing(
                    UnnecessaryFilesInsight, insights_input, "unnecessary_files"
                ),
                # TODO(EME-593): re-enable once we manage to improve accuracy of savings calculation
                # alternate_icons_optimization=self._generate_insight_with_tracing(
                #     AlternateIconsOptimizationInsight, insights_input, "alternate_icons_optimization"
                # ),
                # TODO(EME-427): enable audio/video compression insights once we handle ffmpeg
                # audio_compression=self._generate_insight_with_tracing(
                #     AudioCompressionInsight, insights_input, "audio_compression"
                # ),
                # video_compression=self._generate_insight_with_tracing(
                #     VideoCompressionInsight, insights_input, "video_compression"
                # ),
            )

        analysis_duration = time.time() - start_time
        results = AppleAnalysisResults(
            analysis_version=APPLE_ANALYSIS_VERSION,
            app_info=app_info,
            file_analysis=file_analysis,
            treemap=treemap,
            insights=insights,
            analysis_duration=analysis_duration,
            use_si_units=True,
            download_size=total_download_size,
            install_size=total_install_size,
            app_components=app_components,
        )

        logger.info(
            "size.apple.analyze_app_completed",
            extra={"app_name": app_info.name, "app_version": app_info.version},
        )

        return results

    def parse_plist_date(self, date_value: str | datetime | None) -> str | None:
        if date_value is None:
            return None

        if isinstance(date_value, str):
            try:
                dt = datetime.fromisoformat(date_value)
                return dt.isoformat()
            except (ValueError, AttributeError):
                logger.debug(f"Could not parse date string: {date_value}")
                return date_value

        return date_value.isoformat()

    @sentry_sdk.trace
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
        profile_expiration_date = None
        certificate_expiration_date = None
        if provisioning_profile:
            codesigning_type, profile_name = self._get_profile_type(provisioning_profile)
            expiration_date = provisioning_profile.get("ExpirationDate")
            profile_expiration_date = self.parse_plist_date(expiration_date)
            certificate_expiration_date = self._extract_certificate_expiration_date(provisioning_profile)

        archive_plist = xcarchive.get_archive_plist()
        if archive_plist:
            build_date = self.parse_plist_date(archive_plist.get("CreationDate"))

        supported_platforms = plist.get("CFBundleSupportedPlatforms", [])
        is_simulator = "iphonesimulator" in supported_platforms or plist.get("DTPlatformName") == "iphonesimulator"

        is_code_signature_valid = False
        code_signature_errors: List[str] = []
        try:
            validator = CodeSignatureValidator(xcarchive)
            is_code_signature_valid, code_signature_errors = validator.validate()
        except Exception as e:
            logger.warning("Failed to validate code signature", exc_info=True)
            is_code_signature_valid = False
            code_signature_errors = [str(e)]

        icon_info = xcarchive.get_icon_info()
        primary_icon_name = icon_info.primary_icon_name
        alternate_icon_names = icon_info.alternate_icon_names

        app_name = (
            plist.get("CFBundleName", None)
            or plist.get("CFBundleDisplayName", None)
            or plist.get("Name", None)
            or "Unknown"
        )

        binaries = xcarchive.get_all_binary_paths()
        missing_dsym_binaries = [b.name for b in binaries if b.dsym_path is None]

        return AppleAppInfo(
            name=app_name,
            app_id=plist.get("CFBundleIdentifier", "unknown.bundle.id"),
            version=plist.get("CFBundleShortVersionString", "Unknown"),
            build=plist.get("CFBundleVersion", "Unknown"),
            executable=plist.get("CFBundleExecutable", "Unknown"),
            minimum_os_version=plist.get("MinimumOSVersion", "Unknown"),
            supported_platforms=supported_platforms,
            sdk_version=plist.get("DTSDKName"),
            build_date=build_date,
            is_simulator=is_simulator,
            codesigning_type=codesigning_type,
            profile_name=profile_name,
            profile_expiration_date=profile_expiration_date,
            certificate_expiration_date=certificate_expiration_date,
            is_code_signature_valid=is_code_signature_valid,
            code_signature_errors=code_signature_errors,
            main_binary_uuid=xcarchive.get_main_binary_uuid(),
            primary_icon_name=primary_icon_name,
            alternate_icon_names=alternate_icon_names,
            missing_dsym_binaries=missing_dsym_binaries,
        )

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
                # TODO(EME-428): Parse DER certificate to check if it's a development certificate
                # For now, default to development if we have a certificate
                return "development", profile_name

        # If no devices are provisioned, it's an app store profile
        return "appstore", profile_name

    def _extract_certificate_expiration_date(self, provisioning_profile: dict[str, Any]) -> str | None:
        """Extract the earliest expiration date from developer certificates.

        Args:
            provisioning_profile: Dictionary containing the mobileprovision contents

        Returns:
            ISO format string of the earliest certificate expiration date, or None if no certificates found
        """
        developer_certs = provisioning_profile.get("DeveloperCertificates", [])
        if not developer_certs:
            return None

        earliest_expiration: datetime | None = None

        for cert_data in developer_certs:
            try:
                # Parse DER certificate
                cert = x509.load_der_x509_certificate(cert_data)
                expiration_date = cert.not_valid_after_utc

                # Track the earliest expiration date
                if earliest_expiration is None or expiration_date < earliest_expiration:
                    earliest_expiration = expiration_date

            except Exception:
                logger.exception("Failed to parse certificate")
                continue

        if earliest_expiration:
            return earliest_expiration.isoformat()

        return None

    def _generate_insight_with_tracing(
        self, insight_class: type, insights_input: InsightsInput, insight_name: str
    ) -> Any:
        with sentry_sdk.start_span(op="insight", description=f"apple.insights.{insight_name}"):
            return insight_class().generate(insights_input)

    @sentry_sdk.trace
    def _analyze_binary(
        self,
        binary_info: BinaryInfo,
        app_bundle_path: Path,
        skip_swift_metadata: bool = False,
    ) -> MachOBinaryAnalysis | None:
        binary_path = binary_info.path
        dwarf_binary_path = binary_info.dsym_path
        is_main_binary = binary_info.is_main_binary

        if not binary_path.exists():
            logger.warning(f"Binary not found: {binary_path}")
            return None

        logger.debug(f"Analyzing binary: {binary_path}")

        with open(binary_path, "rb") as f:
            fat_binary = lief.MachO.parse(f)  # type: ignore

        if fat_binary is None or fat_binary.size == 0:
            raise RuntimeError(f"Failed to parse binary with LIEF: {binary_path}")

        binary = fat_binary.at(0)
        executable_size = to_nearest_block_size(get_file_size(binary_path), APPLE_FILESYSTEM_BLOCK_SIZE)

        parser = MachOParser(binary)
        architectures = parser.extract_architectures()
        linked_libraries = parser.extract_linked_libraries()
        swift_protocol_conformances: List[str] = []  # parser.parse_swift_protocol_conformances()
        objc_method_names = parser.parse_objc_method_names()
        segments = self._extract_segments_info(parser.binary)
        load_commands = self._extract_load_commands_info(parser.binary)
        linkedit_info = parser.extract_linkedit_info()

        symbol_info = None
        dwarf_relocations = None

        # Always test symbol removal on the main app binary (not dSYM)
        strippable_symbols_size = self._check_strip_symbols_removal(binary_path, binary)

        if dwarf_binary_path:
            with open(dwarf_binary_path, "rb") as f:
                dwarf_fat_binary = lief.MachO.parse(f)  # type: ignore
            if dwarf_fat_binary:
                dwarf_binary = dwarf_fat_binary.at(0)
                symbol_sizes = MachOSymbolSizes(dwarf_binary).get_symbol_sizes()
                symbol_info = SymbolInfo.from_symbol_sizes(symbol_sizes=symbol_sizes)
            else:
                logger.error(
                    "size.apple.skip_symbol_analysis.dwarf_binary_parse_failed",
                    extra={
                        "binary_name": binary_info.name,
                    },
                )

            if binary_info.relocations_path and os.getenv("LAUNCHPAD_ENV") == "development":
                with sentry_sdk.start_span(op="parse", description="dwarf_relocations.parse"):
                    dwarf_relocations = DwarfRelocationsParser.parse(binary_info.relocations_path)
                if dwarf_relocations:
                    logger.debug(
                        f"Parsed {len(dwarf_relocations.relocations)} DWARF relocations for {binary_info.name}"
                    )
        else:
            logger.info(
                "size.apple.skip_symbol_analysis.no_dwarf_binary",
                extra={
                    "binary_name": binary_info.name,
                },
            )

        swift_metadata = None
        if not skip_swift_metadata:
            swift_metadata = SwiftMetadata(
                protocol_conformances=swift_protocol_conformances,
            )

        return MachOBinaryAnalysis(
            binary_absolute_path=binary_path,
            binary_relative_path=binary_path.relative_to(app_bundle_path),
            executable_size=executable_size,
            architectures=architectures,
            linked_libraries=linked_libraries,
            swift_metadata=swift_metadata,
            symbol_info=symbol_info,
            objc_method_names=objc_method_names,
            is_main_binary=is_main_binary,
            segments=segments,
            load_commands=load_commands,
            header_size=parser.get_header_size(),
            dwarf_relocations=dwarf_relocations,
            strippable_symbols_size=strippable_symbols_size,
            linkedit_info=linkedit_info,
        )

    @sentry_sdk.trace
    def _check_strip_symbols_removal(self, binary_path: Path, binary: lief.MachO.Binary) -> int:
        """Test actual symbol removal using AppleStrip to get real size savings."""
        try:
            with sentry_sdk.start_span(op="measure", description="strip_symbols.get_original_size"):
                original_size = binary_path.stat().st_size

            # Create a temporary file for the stripped output
            with sentry_sdk.start_span(op="measure", description="strip_symbols.create_temp_output"):
                temp_file = tempfile.NamedTemporaryFile(suffix=".stripped", delete=False)
                temp_output_path = Path(temp_file.name)
                temp_file.close()

            actual_savings = 0
            try:
                is_dylib = binary.header.file_type == lief.MachO.Header.FILE_TYPE.DYLIB
                if is_dylib:
                    strip_flags = ["-r", "-S", "-T", "-x"]
                else:
                    strip_flags = ["-S", "-T", "-x"]

                with sentry_sdk.start_span(op="process", description="strip_symbols.strip_binary"):
                    apple_strip = AppleStrip()
                    result = apple_strip.strip(
                        input_file=binary_path,
                        output_file=temp_output_path,
                        flags=strip_flags,
                    )

                if result.returncode != 0:
                    logger.error(f"Strip command failed for {binary_path.name} with return code {result.returncode}")
                    actual_savings = 0
                else:
                    with sentry_sdk.start_span(op="measure", description="strip_symbols.calculate_savings"):
                        stripped_size = temp_output_path.stat().st_size
                        actual_savings = max(0, original_size - stripped_size)

            finally:
                try:
                    temp_output_path.unlink()
                except Exception:
                    pass

            return actual_savings

        except Exception:
            logger.exception(f"Error testing symbol removal for {binary_path}")
            return 0

    def _extract_segments_info(self, binary: lief.MachO.Binary) -> List[SegmentInfo]:
        """Extract segment and section information from LIEF binary into stable dataclasses."""
        segments: List[SegmentInfo] = []

        try:
            for command in binary.commands:
                if isinstance(command, lief.MachO.SegmentCommand):
                    segment_name = self._parse_lief_name(command.name)

                    section_infos: List[SectionInfo] = []
                    for section in command.sections:
                        if section.segment.file_size == 0:
                            logger.warning(
                                "size.apple.skip_segment.zero_file_size",
                                extra={
                                    "segment_name": segment_name,
                                    "section_name": section.name,
                                },
                            )
                            continue

                        section_name = self._parse_lief_name(section.name)
                        is_zerofill = section.type == lief.MachO.Section.TYPE.ZEROFILL
                        section_infos.append(SectionInfo(name=section_name, size=section.size, is_zerofill=is_zerofill))

                    segments.append(
                        SegmentInfo(
                            name=segment_name,
                            sections=section_infos,
                            size=command.file_size,
                        )
                    )
        except Exception:
            logger.exception("Error extracting segments info")

        return segments

    def _parse_lief_name(self, name: str | bytes) -> str:
        if isinstance(name, bytes):
            return name.decode("utf-8", errors="replace")
        return str(name)

    def _extract_load_commands_info(self, binary: lief.MachO.Binary) -> List[LoadCommandInfo]:
        """Extract load command information from LIEF binary into stable dataclasses."""
        load_commands: List[LoadCommandInfo] = []
        for command in binary.commands:
            command_name = str(command.command.name)
            command_size = command.size

            if command_size > 0:
                load_commands.append(LoadCommandInfo(name=command_name, size=command_size))
            else:
                logger.warning(f"Skipping load command {command_name} with size 0")

        return load_commands
