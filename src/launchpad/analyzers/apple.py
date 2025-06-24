"""Apple app bundle analyzer using LIEF for Mach-O parsing."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Tuple

import lief

from ..artifacts.apple.zipped_xcarchive import ZippedXCArchive
from ..artifacts.artifact import AppleArtifact
from ..insights.common import DuplicateFilesInsight
from ..insights.insight import InsightsInput
from ..models.apple import AppleAnalysisResults, AppleAppInfo, AppleInsightResults, MachOBinaryAnalysis, SwiftMetadata
from ..models.common import FileAnalysis, FileInfo
from ..models.treemap import FILE_TYPE_TO_TREEMAP_TYPE, TreemapType
from ..parsers.apple.macho_parser import MachOParser
from ..parsers.apple.range_mapping_builder import RangeMappingBuilder
from ..utils.code_signature_validator import CodeSignatureValidator
from ..utils.file_utils import calculate_file_hash, get_file_size
from ..utils.logging import get_logger
from ..utils.treemap.treemap_builder import TreemapBuilder

logger = get_logger(__name__)


class AppleAppAnalyzer:
    """Analyzer for Apple app bundles (.xcarchive directories)."""

    def __init__(
        self,
        working_dir: Path | None = None,
        skip_swift_metadata: bool = False,
        skip_symbols: bool = False,
        skip_range_mapping: bool = False,
        skip_treemap: bool = False,
        skip_image_analysis: bool = False,
        skip_insights: bool = False,
    ) -> None:
        """Initialize the Apple analyzer.

        Args:
            working_dir: Directory for temporary files (None for system temp)
            skip_swift_metadata: Skip Swift metadata extraction for faster analysis
            skip_symbols: Skip symbol extraction for faster analysis
            skip_range_mapping: Skip range mapping for binary content categorization
            skip_treemap: Skip treemap generation for hierarchical size analysis
            skip_image_analysis: Skip image analysis for faster processing
            skip_insights: Skip insights generation for faster analysis
        """
        self.working_dir = working_dir
        self.skip_swift_metadata = skip_swift_metadata
        self.skip_symbols = skip_symbols
        self.skip_range_mapping = skip_range_mapping
        self.skip_treemap = skip_treemap
        self.skip_image_analysis = skip_image_analysis
        self.skip_insights = skip_insights
        self.app_info: AppleAppInfo | None = None

    def preprocess(self, artifact: AppleArtifact) -> AppleAppInfo:
        if not isinstance(artifact, ZippedXCArchive):
            raise NotImplementedError(f"Only ZippedXCArchive artifacts are supported, got {type(artifact)}")

        self.app_info = self._extract_app_info(artifact)
        return self.app_info

    def analyze(self, artifact: AppleArtifact) -> AppleAnalysisResults:
        """Analyze an Apple app bundle.

        Args:
            artifact: AppleArtifact to analyze

        Returns:
            Analysis results including file sizes, binary analysis, and treemap
        """
        if not isinstance(artifact, ZippedXCArchive):
            raise NotImplementedError(f"Only ZippedXCArchive artifacts are supported, got {type(artifact)}")

        # Extract basic app information
        if not self.app_info:
            self.app_info = self.preprocess(artifact)

        app_info = self.app_info
        logger.info(f"Analyzing app: {app_info.name} v{app_info.version}")

        file_analysis = self._analyze_files(artifact)
        logger.info(f"Found {file_analysis.file_count} files, " f"total size: {file_analysis.total_size} bytes")

        treemap = None
        binary_analysis: List[MachOBinaryAnalysis] = []
        binary_analysis_map: Dict[str, MachOBinaryAnalysis] = {}

        if not self.skip_treemap and not self.skip_range_mapping:
            app_bundle_path = artifact.get_app_bundle_path()

            # First find all binaries
            binaries = self._find_binaries(app_bundle_path, artifact)
            logger.info(f"Found {len(binaries)} binaries to analyze")

            # Then analyze them all
            for binary_path, binary_name in binaries:
                try:
                    logger.info(f"Analyzing binary {binary_name} at {binary_path}")
                    binary = self._analyze_binary(binary_path)
                    if binary.range_map is not None:
                        binary_analysis.append(binary)
                        binary_analysis_map[str(binary_path.relative_to(app_bundle_path))] = binary
                except Exception as e:
                    logger.warning(f"Failed to analyze binary at {binary_path}: {e}")

            treemap_builder = TreemapBuilder(
                app_name=app_info.name,
                platform="ios",
                download_compression_ratio=0.8,  # TODO: implement this
                binary_analysis_map=binary_analysis_map,
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
            )
            insights = AppleInsightResults(
                duplicate_files=DuplicateFilesInsight().generate(insights_input),
            )

        results = AppleAnalysisResults(
            app_info=app_info,
            file_analysis=file_analysis,
            binary_analysis=binary_analysis,
            treemap=treemap,
            insights=insights,
        )

        return results

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
            bundle_id=plist.get("CFBundleIdentifier", "unknown.bundle.id"),
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

            file_info = FileInfo(
                path=str(relative_path),
                size=file_size,
                file_type=file_type or "unknown",
                hash_md5=file_hash,
                treemap_type=FILE_TYPE_TO_TREEMAP_TYPE.get(file_type, TreemapType.FILES),
            )

            files.append(file_info)

        return FileAnalysis(files=files)

    def _find_binaries(self, app_bundle_path: Path, artifact: AppleArtifact) -> List[tuple[Path, str]]:
        """Find all binaries in the app bundle.

        Args:
            app_bundle_path: Path to the app bundle
            artifact: The Apple app artifact being analyzed

        Returns:
            List of tuples containing (binary_path, binary_name, skip_swift_metadata)
        """
        binaries: List[tuple[Path, str]] = []

        # Find main executable
        main_executable = artifact.get_plist().get("CFBundleExecutable")
        if main_executable is None:
            raise RuntimeError("CFBundleExecutable not found in Info.plist")
        main_binary_path = Path(os.path.join(str(app_bundle_path), main_executable))
        binaries.append((main_binary_path, main_executable))  # Don't skip Swift metadata for main binary

        # Find framework binaries
        for framework_path in app_bundle_path.rglob("*.framework"):
            if framework_path.is_dir():
                framework_name = framework_path.stem
                framework_binary_path = framework_path / framework_name
                binaries.append((framework_binary_path, framework_name))  # Skip Swift metadata for frameworks

        # Find app extension binaries
        for extension_path in app_bundle_path.rglob("*.appex"):
            if extension_path.is_dir():
                extension_plist_path = extension_path / "Info.plist"
                if extension_plist_path.exists():
                    try:
                        import plistlib

                        with open(extension_plist_path, "rb") as f:
                            extension_plist = plistlib.load(f)
                        extension_executable = extension_plist.get("CFBundleExecutable")
                        if extension_executable:
                            extension_binary_path = extension_path / extension_executable
                            # Use the full extension name as the key to avoid conflicts
                            extension_name = f"{extension_path.stem}/{extension_executable}"
                            binaries.append(
                                (extension_binary_path, extension_name)
                            )  # Skip Swift metadata for extensions
                    except Exception as e:
                        logger.warning(f"Failed to read extension Info.plist at {extension_path}: {e}")

        return binaries

    def _analyze_binary(self, binary_path: Path, skip_swift_metadata: bool = False) -> MachOBinaryAnalysis:
        """Analyze a binary file using LIEF.

        Args:
            binary_path: Path to the binary file
            skip_swift_metadata: Whether to skip Swift metadata extraction

        Returns:
            Binary analysis results
        """
        if not binary_path.exists():
            logger.warning(f"Binary not found: {binary_path}")
            return MachOBinaryAnalysis(
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
        swift_protocol_conformances = parser.parse_swift_protocol_conformances()

        # Extract Swift metadata if enabled
        swift_metadata = None
        if not skip_swift_metadata:
            swift_metadata = SwiftMetadata(
                protocol_conformances=swift_protocol_conformances,
            )

        # Build range mapping for binary content
        range_map = None
        if not self.skip_range_mapping:
            range_builder = RangeMappingBuilder(parser, executable_size)
            range_map = range_builder.build_range_mapping()

        return MachOBinaryAnalysis(
            executable_size=executable_size,
            architectures=architectures,
            linked_libraries=linked_libraries,
            sections=sections,
            swift_metadata=swift_metadata,
            range_map=range_map,
        )
