import json
import os
import plistlib
import shutil
import subprocess
import tempfile
import uuid

from dataclasses import dataclass
from pathlib import Path
from typing import Any, List

import lief

from launchpad.utils.logging import get_logger

from ..artifact import AppleArtifact
from ..providers.zip_provider import ZipProvider

logger = get_logger(__name__)


@dataclass
class AssetCatalogElement:
    name: str
    imageId: str
    size: int
    type: str
    vector: bool
    filename: str


@dataclass
class BinaryInfo:
    name: str
    path: Path
    dsym_path: Path | None


class ZippedXCArchive(AppleArtifact):
    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self._zip_provider = ZipProvider(path)
        self._extract_dir = self._zip_provider.extract_to_temp_directory()
        self._app_bundle_path: Path | None = None
        self._plist: dict[str, Any] | None = None
        self._provisioning_profile: dict[str, Any] | None = None
        self._dsym_files: dict[str, Path] | None = None

    def get_plist(self) -> dict[str, Any]:
        if self._plist is not None:
            return self._plist

        app_bundle_path = self.get_app_bundle_path()
        plist_path = app_bundle_path / "Info.plist"

        try:
            with open(plist_path, "rb") as f:
                plist_data = plistlib.load(f)

            self._plist = plist_data
            return self._plist
        except Exception as e:
            raise RuntimeError(f"Failed to parse Info.plist: {e}")

    def generate_ipa(self, output_path: Path):
        """Generate an IPA file

        An IPA file is a zip file containing a Payload directory, with the .app bundle inside.

        Args:
            output_path: Path where the IPA file should be saved

        Returns:
            Path to the generated IPA file

        Raises:
            RuntimeError: If IPA generation fails
        """

        logger.info("Generating IPA file from XCArchive")

        # Get the app bundle path
        app_bundle_path = self.get_app_bundle_path()

        # Create a temporary directory for Payload
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir_path = Path(temp_dir)
            payload_dir = temp_dir_path / "Payload"
            payload_dir.mkdir()
            dest_app_path = payload_dir / app_bundle_path.name

            # Copy the .app bundle into Payload (preserve symlinks, permissions, etc.)
            shutil.copytree(app_bundle_path, dest_app_path, symlinks=True)

            # Create the IPA file using zip to preserve symlinks and metadata
            try:
                subprocess.run(
                    [
                        "zip",
                        "-r",
                        "-y",
                        str(output_path),
                        "Payload",
                    ],  # Recursive  # Store symlinks as symlinks
                    cwd=temp_dir_path,
                    check=True,
                )

                logger.info(f"IPA file generated successfully: {output_path}")
                return output_path
            except subprocess.CalledProcessError as e:
                raise RuntimeError(f"Failed to generate IPA file with zip: {e}")
            except FileNotFoundError:
                raise RuntimeError(
                    "zip command not found. This tool is required for IPA generation."
                )

    def get_provisioning_profile(self) -> dict[str, Any] | None:
        if self._provisioning_profile is not None:
            return self._provisioning_profile

        app_bundle_path = self.get_app_bundle_path()
        mobileprovision_path = app_bundle_path / "embedded.mobileprovision"
        try:
            with open(mobileprovision_path, "rb") as f:
                content = f.read()

            content_str = content.decode("utf-8", errors="ignore")
            plist_start = content_str.find("<?xml")
            plist_end = content_str.find("</plist>")
            if plist_start == -1 or plist_end == -1:
                return None

            plist_str = content_str[plist_start : plist_end + 8]
            self._provisioning_profile = plistlib.loads(plist_str.encode("utf-8"))
            return self._provisioning_profile
        except FileNotFoundError:
            logger.debug(f"No embedded.mobileprovision found at {mobileprovision_path}")
            return None

    def get_binary_path(self) -> Path | None:
        app_bundle_path = self.get_app_bundle_path()
        plist = self.get_plist()
        executable_name: str = plist.get("CFBundleExecutable", "")
        if not executable_name:
            return None

        return app_bundle_path / executable_name

    def get_app_bundle_path(self) -> Path:
        """Get the path to the .app bundle."""
        if self._app_bundle_path is not None:
            return self._app_bundle_path

        # Search patterns for different XCArchive formats
        search_patterns = [
            # Format 1: MyApp.xcarchive/Products/**/*.app
            "*.xcarchive/Products/**/*.app",
            # Format 2: Products/Applications/*.app (direct extraction)
            "Products/Applications/*.app",
            # Format 3: Products/**/*.app (more general)
            "Products/**/*.app",
        ]

        for pattern in search_patterns:
            logger.debug(f"Searching for app bundle with pattern: {pattern}")
            for path in self._extract_dir.rglob(pattern):
                if path.is_dir() and "__MACOSX" not in str(path):
                    logger.debug(f"Found Apple app bundle: {path}")
                    self._app_bundle_path = path
                    return path

        raise FileNotFoundError(f"No .app bundle found in {self._extract_dir}")

    def get_all_binary_paths(self) -> List[BinaryInfo]:
        """Find all binaries in the app bundle and their corresponding dSYM files.

        Returns:
            List of BinaryInfo objects
        """

        binaries: List[BinaryInfo] = []
        dsym_files = self._find_dsym_files()

        app_bundle_path = self.get_app_bundle_path()

        # Find main executable
        main_executable = self.get_plist().get("CFBundleExecutable")
        if main_executable is None:
            raise RuntimeError("CFBundleExecutable not found in Info.plist")
        main_binary_path = Path(os.path.join(str(app_bundle_path), main_executable))

        # Find corresponding dSYM for main executable
        main_uuid = self._extract_binary_uuid(main_binary_path)
        main_dsym_path = dsym_files.get(main_uuid) if main_uuid else None

        binaries.append(BinaryInfo(main_executable, main_binary_path, main_dsym_path))

        # Find framework binaries
        for framework_path in app_bundle_path.rglob("*.framework"):
            if framework_path.is_dir():
                framework_name = framework_path.stem
                framework_binary_path = framework_path / framework_name

                # Find corresponding dSYM for framework
                framework_uuid = self._extract_binary_uuid(framework_binary_path)
                framework_dsym_path = (
                    dsym_files.get(framework_uuid) if framework_uuid else None
                )

                binaries.append(
                    BinaryInfo(
                        framework_name, framework_binary_path, framework_dsym_path
                    )
                )

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
                            extension_binary_path = (
                                extension_path / extension_executable
                            )
                            # Use the full extension name as the key to avoid conflicts
                            extension_name = (
                                f"{extension_path.stem}/{extension_executable}"
                            )

                            # Find corresponding dSYM for extension
                            extension_uuid = self._extract_binary_uuid(
                                extension_binary_path
                            )
                            extension_dsym_path = (
                                dsym_files.get(extension_uuid)
                                if extension_uuid
                                else None
                            )

                            binaries.append(
                                BinaryInfo(
                                    extension_name,
                                    extension_binary_path,
                                    extension_dsym_path,
                                )
                            )
                    except Exception as e:
                        logger.warning(
                            f"Failed to read extension Info.plist at {extension_path}: {e}"
                        )

        return binaries

    def get_asset_catalog_details(
        self, relative_path: Path
    ) -> List[AssetCatalogElement]:
        """Get the details of an asset catalog file (Assets.car) by returning the
        parsed JSON from ParsedAssets."""
        try:
            app_bundle_path = self.get_app_bundle_path()
            json_name = relative_path.with_suffix(".json")

            # Handle different XCArchive formats
            xcarchive_dirs = list(self._extract_dir.glob("*.xcarchive"))
            if xcarchive_dirs:
                # Format 1: MyApp.xcarchive/Products/Applications/...
                xcarchive_dir = xcarchive_dirs[0]
                app_bundle_path = app_bundle_path.relative_to(xcarchive_dir)
                file_path = xcarchive_dir / "ParsedAssets" / app_bundle_path / json_name
            else:
                # Format 2: Products/Applications/... (direct extraction)
                file_path = (
                    self._extract_dir / "ParsedAssets" / app_bundle_path / json_name
                )

            if not file_path.exists():
                logger.warning(f"Assets.json not found at {file_path}")
                return []

            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            return [self._parse_asset_element(item) for item in data]
        except Exception as e:
            logger.warning(
                f"Failed to get asset catalog details for {relative_path}: {e}"
            )
            return []

    def _parse_asset_element(self, item: dict[str, Any]) -> AssetCatalogElement:
        """Parse a dictionary item into an AssetCatalogElement."""
        name = item.get("name", "")
        image_id = item.get("imageId", "")
        size = item.get("size", 0)
        asset_type = item.get("type", "")
        is_vector = item.get("vector", False)
        filename = item.get("filename", "")

        return AssetCatalogElement(
            name=name,
            imageId=image_id,
            size=size,
            type=asset_type,
            vector=is_vector,
            filename=filename,
        )

    def _extract_binary_uuid(self, binary_path: Path) -> str | None:
        try:
            fat_binary: lief.MachO.FatBinary | None = lief.MachO.parse(str(binary_path))  # type: ignore
            if fat_binary is None or fat_binary.size == 0:
                logger.debug(f"Failed to parse binary with LIEF: {binary_path}")
                return None

            binary = fat_binary.at(0)

            # Look for UUID load command
            for command in binary.commands:
                if command.command == lief.MachO.LoadCommand.TYPE.UUID:
                    if isinstance(command, lief.MachO.UUIDCommand):
                        uuid_bytes = bytes(command.uuid)
                        uuid_obj = uuid.UUID(bytes=uuid_bytes)
                        return str(uuid_obj).upper()

            logger.debug(f"No UUID command found in binary: {binary_path}")
            return None

        except Exception as e:
            logger.error(f"Failed to extract UUID from binary {binary_path}: {e}")
            return None

    def _find_dsym_files(self) -> dict[str, Path]:
        if self._dsym_files is not None:
            return self._dsym_files

        dsym_files: dict[str, Path] = {}

        dsyms_dir = None
        for path in self._extract_dir.rglob("dSYMs"):
            if path.is_dir():
                dsyms_dir = path
                break

        if dsyms_dir is None:
            logger.debug("No dSYMs directory found in XCArchive")
            self._dsym_files = dsym_files
            return dsym_files

        for dsym_path in dsyms_dir.rglob("DWARF"):
            if dsym_path.is_dir():
                for dwarf_file in dsym_path.iterdir():
                    if dwarf_file.is_file():
                        dsym_uuid = self._extract_binary_uuid(dwarf_file)
                        if dsym_uuid:
                            dsym_files[dsym_uuid] = dwarf_file
                            logger.debug(
                                f"Found dSYM file {dwarf_file} with UUID {dsym_uuid}"
                            )

        self._dsym_files = dsym_files
        return dsym_files
