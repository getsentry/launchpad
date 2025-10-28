import json
import os
import plistlib
import shutil
import subprocess
import tempfile
import uuid

from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, NamedTuple

import lief
import sentry_sdk

from launchpad.parsers.apple.crushed_png import decode_crushed_png
from launchpad.utils.logging import get_logger

from ..artifact import AppleArtifact
from ..providers.zip_provider import ZipProvider

logger = get_logger(__name__)


@dataclass
class AssetCatalogElement:
    name: str
    image_id: str
    size: int
    type: int
    vector: bool
    filename: str
    full_path: Path | None
    idiom: str | None = None
    colorspace: str | None = None


@dataclass
class DsymInfo:
    """Information about a dSYM bundle for a binary."""

    dwarf_file: Path
    dsym_bundle: Path
    relocations_file: Path | None = None


@dataclass
class BinaryInfo:
    name: str
    path: Path
    dsym_path: Path | None
    is_main_binary: bool
    relocations_path: Path | None = None


class AppIconInfo(NamedTuple):
    primary_icon_name: str | None
    primary_icon_files: list[str]
    alternate_icon_names: list[str]


class ZippedXCArchive(AppleArtifact):
    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self._zip_provider = ZipProvider(path)
        self._extract_dir = self._zip_provider.extract_to_temp_directory()
        self._app_bundle_path: Path | None = None
        self._plist: dict[str, Any] | None = None
        self._provisioning_profile: dict[str, Any] | None = None
        self._dsym_info: dict[str, DsymInfo] | None = None

    def get_extract_dir(self) -> Path:
        return self._extract_dir

    @sentry_sdk.trace
    def get_plist(self) -> dict[str, Any]:
        if self._plist is not None:
            return self._plist

        app_bundle_path = self.get_app_bundle_path()
        plist_path = app_bundle_path / "Info.plist"

        try:
            with open(plist_path, "rb") as f:
                plist_data = plistlib.load(f)

            self._plist = plist_data
            return plist_data
        except Exception as e:
            raise RuntimeError("Failed to parse Info.plist") from e

    @sentry_sdk.trace
    def get_app_icon(self) -> bytes | None:
        """Get the primary app icon, decoded from crushed PNG format."""
        icon_info = self.get_icon_info()

        if not icon_info.primary_icon_files:
            logger.warning("No icon files found in CFBundleIconFiles")
            return None

        app_bundle_path = self.get_app_bundle_path()

        for icon_name in icon_info.primary_icon_files:
            # iOS lists base names without extensions or resolution modifiers (@2x, @3x, ~ipad)
            # Search for files matching the base name with any suffix
            # e.g., "AppIcon60x60" matches "AppIcon60x60@2x.png" or "AppIcon60x60.png"
            matching_files = list(app_bundle_path.glob(f"{icon_name}*.png"))

            if not matching_files:
                continue

            # Prioritize: @3x > @2x > no suffix, and iPhone over iPad
            def icon_priority(path: Path) -> tuple[int, int]:
                name = path.stem
                if "@3x" in name:
                    res_priority = 3
                elif "@2x" in name:
                    res_priority = 2
                else:
                    res_priority = 1

                device_priority = 0 if "~ipad" in name else 1

                return (device_priority, res_priority)

            best_icon = max(matching_files, key=icon_priority)
            logger.debug(f"Found app icon: {best_icon.name} (from {len(matching_files)} candidates)")

            if not best_icon.exists():
                logger.warning(f"Icon file {best_icon} does not exist")
                continue

            icon_data = best_icon.read_bytes()
            decoded_icon = decode_crushed_png(icon_data)

            if decoded_icon is None:
                logger.warning(f"Failed to decode icon: {best_icon.name}")
                continue

            return decoded_icon

        logger.warning(f"No icon files found for CFBundleIconFiles: {icon_info.primary_icon_files}")
        return None

    @sentry_sdk.trace
    def get_icon_info(self) -> AppIconInfo:
        """Extract icon information from Info.plist."""
        plist = self.get_plist()
        bundle_icons = plist.get("CFBundleIcons", {})

        primary_icon_name: str | None = None
        primary_icon_files: list[str] = []
        alternate_icon_names: list[str] = []

        primary_icon = bundle_icons.get("CFBundlePrimaryIcon", {})
        if isinstance(primary_icon, dict):
            primary_icon_name = primary_icon.get("CFBundleIconName")

        # CFBundleIconFiles lists the base names of icon files (without extensions or resolution modifiers)
        icon_files = primary_icon.get("CFBundleIconFiles", [])
        if isinstance(icon_files, list):
            primary_icon_files = icon_files

        alternate_icons = bundle_icons.get("CFBundleAlternateIcons", {})
        if isinstance(alternate_icons, dict):
            for icon_key, icon_data in alternate_icons.items():
                if isinstance(icon_data, dict):
                    icon_name = icon_data.get("CFBundleIconName")
                    if icon_name:
                        alternate_icon_names.append(icon_name)

        return AppIconInfo(primary_icon_name, primary_icon_files, alternate_icon_names)

    @sentry_sdk.trace
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
                raise RuntimeError("Failed to generate IPA file with zip") from e
            except FileNotFoundError:
                raise RuntimeError("zip command not found. This tool is required for IPA generation.")

    @sentry_sdk.trace
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

    @sentry_sdk.trace
    def get_binary_path(self) -> Path | None:
        app_bundle_path = self.get_app_bundle_path()
        plist = self.get_plist()
        executable_name: str = plist.get("CFBundleExecutable", "")
        if not executable_name:
            return None

        return app_bundle_path / executable_name

    @sentry_sdk.trace
    def get_app_bundle_path(self) -> Path:
        """Get the path to the .app bundle."""
        if self._app_bundle_path is not None:
            return self._app_bundle_path

        for path in self._extract_dir.rglob("*.xcarchive/Products/**/*.app"):
            if path.is_dir() and "__MACOSX" not in str(path):
                logger.debug(f"Found Apple app bundle: {path}")
                return path

        raise FileNotFoundError(f"No .app bundle found in {self._extract_dir}")

    @sentry_sdk.trace
    def get_main_binary_uuid(self) -> str | None:
        main_binary_path = self._get_main_binary_path()
        return self._extract_binary_uuid(main_binary_path)

    @sentry_sdk.trace
    def get_all_binary_paths(self) -> List[BinaryInfo]:
        """Find all binaries in the app bundle and their corresponding dSYM files.

        Returns:
            List of BinaryInfo objects
        """

        binaries: List[BinaryInfo] = []
        dsym_info = self._find_dsym_files()

        app_bundle_path = self.get_app_bundle_path()

        # Find main executable
        main_executable = self.get_plist().get("CFBundleExecutable")
        if main_executable is None:
            raise RuntimeError("CFBundleExecutable not found in Info.plist")
        main_binary_path = self._get_main_binary_path()

        # Find corresponding dSYM for main executable
        main_uuid = self._extract_binary_uuid(main_binary_path)
        main_dsym_info = dsym_info.get(main_uuid) if main_uuid else None

        binaries.append(
            BinaryInfo(
                main_executable,
                main_binary_path,
                main_dsym_info.dwarf_file if main_dsym_info else None,
                is_main_binary=True,
                relocations_path=main_dsym_info.relocations_file if main_dsym_info else None,
            )
        )

        # Find framework binaries
        for framework_path in app_bundle_path.rglob("*.framework"):
            if framework_path.is_dir():
                framework_name = framework_path.stem
                framework_binary_path = framework_path / framework_name

                # Find corresponding dSYM for framework
                framework_uuid = self._extract_binary_uuid(framework_binary_path)
                framework_dsym_info = dsym_info.get(framework_uuid) if framework_uuid else None

                binaries.append(
                    BinaryInfo(
                        framework_name,
                        framework_binary_path,
                        framework_dsym_info.dwarf_file if framework_dsym_info else None,
                        is_main_binary=False,
                        relocations_path=framework_dsym_info.relocations_file if framework_dsym_info else None,
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
                            extension_binary_path = extension_path / extension_executable
                            # Use the full extension name as the key to avoid conflicts
                            extension_name = f"{extension_path.stem}/{extension_executable}"

                            # Find corresponding dSYM for extension
                            extension_uuid = self._extract_binary_uuid(extension_binary_path)
                            extension_dsym_info = dsym_info.get(extension_uuid) if extension_uuid else None

                            binaries.append(
                                BinaryInfo(
                                    extension_name,
                                    extension_binary_path,
                                    extension_dsym_info.dwarf_file if extension_dsym_info else None,
                                    is_main_binary=True,  # App extension main executables are main binaries
                                    relocations_path=extension_dsym_info.relocations_file
                                    if extension_dsym_info
                                    else None,
                                )
                            )
                    except Exception:
                        logger.exception(f"Failed to read extension Info.plist at {extension_path}")

        # Find Watch app binaries
        for watch_path in app_bundle_path.rglob("Watch/*.app"):
            if watch_path.is_dir():
                watch_plist_path = watch_path / "Info.plist"
                if watch_plist_path.exists():
                    try:
                        import plistlib

                        with open(watch_plist_path, "rb") as f:
                            watch_plist = plistlib.load(f)
                        watch_executable = watch_plist.get("CFBundleExecutable")
                        if watch_executable:
                            watch_binary_path = watch_path / watch_executable
                            watch_name = f"Watch/{watch_path.stem}/{watch_executable}"

                            watch_uuid = self._extract_binary_uuid(watch_binary_path)
                            watch_dsym_info = dsym_info.get(watch_uuid) if watch_uuid else None

                            binaries.append(
                                BinaryInfo(
                                    watch_name,
                                    watch_binary_path,
                                    watch_dsym_info.dwarf_file if watch_dsym_info else None,
                                    is_main_binary=True,  # Watch app main executables are main binaries
                                    relocations_path=watch_dsym_info.relocations_file if watch_dsym_info else None,
                                )
                            )
                    except Exception:
                        logger.exception(f"Failed to read Watch app Info.plist at {watch_path}")

        return binaries

    @sentry_sdk.trace
    def get_asset_catalog_details(self, relative_path: Path) -> List[AssetCatalogElement]:
        """Get the details of an asset catalog file (Assets.car) by returning the
        parsed JSON from ParsedAssets."""
        try:
            app_bundle_path = self.get_app_bundle_path()
            json_name = relative_path.with_suffix(".json")
            xcarchive_dir = list(self._extract_dir.glob("*.xcarchive"))[0]
            app_bundle_path = app_bundle_path.relative_to(xcarchive_dir)

            parent_path = xcarchive_dir / "ParsedAssets" / app_bundle_path / relative_path.parent
            file_path = parent_path / json_name.name

            if not file_path.exists():
                logger.warning(
                    "size.apple.assets_json_not_found",
                    extra={"file_path": file_path.relative_to(self._extract_dir)},
                )
                return []

            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            return [self._parse_asset_element(item, parent_path) for item in data]
        except Exception:
            logger.exception(f"Failed to get asset catalog details for {relative_path}")
            return []

    def _get_main_binary_path(self) -> Path:
        app_bundle_path = self.get_app_bundle_path()
        main_executable = self.get_plist().get("CFBundleExecutable")
        if main_executable is None:
            raise RuntimeError("CFBundleExecutable not found in Info.plist")
        return Path(os.path.join(str(app_bundle_path), main_executable))

    def _parse_asset_element(self, item: dict[str, Any], parent_path: Path) -> AssetCatalogElement:
        """Parse a dictionary item into an AssetCatalogElement."""
        name = item.get("name", "")
        image_id = item.get("imageId", "")
        size = item.get("size", 0)
        asset_type = item.get("type", 0)
        is_vector = item.get("vector", False)
        filename = item.get("filename", "")
        idiom = item.get("idiom")
        colorspace = item.get("colorspace")

        file_extension = Path(filename).suffix.lower()
        if filename and file_extension in {".png", ".jpg", ".jpeg", ".heic", ".heif"}:
            potential_path = parent_path / f"{image_id}{file_extension}"
            if potential_path.exists():
                full_path = potential_path
            else:
                full_path = None
        else:
            full_path = None

        return AssetCatalogElement(
            name=name,
            image_id=image_id,
            size=size,
            type=asset_type,
            vector=is_vector,
            filename=filename,
            full_path=full_path,
            idiom=idiom,
            colorspace=colorspace,
        )

    def _extract_binary_uuid(self, binary_path: Path) -> str | None:
        try:
            with open(binary_path, "rb") as f:
                fat_binary: lief.MachO.FatBinary | None = lief.MachO.parse(f)  # type: ignore
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

        except Exception:
            logger.exception(f"Failed to extract UUID from binary {binary_path}")
            return None

    @sentry_sdk.trace
    def _find_dsym_files(self) -> dict[str, DsymInfo]:
        """Find all dSYM bundles and map them by binary UUID.

        Returns:
            Dictionary mapping UUID to DsymInfo containing dwarf file, bundle, and relocations
        """
        if self._dsym_info is not None:
            return self._dsym_info

        dsym_info: dict[str, DsymInfo] = {}

        dsyms_dir = None
        for path in self._extract_dir.rglob("dSYMs"):
            if path.is_dir():
                dsyms_dir = path
                break

        if dsyms_dir is None:
            logger.debug("No dSYMs directory found in XCArchive")
            self._dsym_info = dsym_info
            return dsym_info

        for dwarf_dir in dsyms_dir.rglob("DWARF"):
            if dwarf_dir.is_dir():
                # Find the dSYM bundle root by walking up until we find a .dSYM directory
                dsym_bundle = self._find_dsym_bundle_root(dwarf_dir)
                if not dsym_bundle:
                    continue

                for dwarf_file in dwarf_dir.iterdir():
                    if dwarf_file.is_file():
                        binary_uuid = self._extract_binary_uuid(dwarf_file)
                        if binary_uuid:
                            binary_name = dwarf_file.name

                            # Find relocations file
                            relocations_file = self._find_relocations_file_in_bundle(dsym_bundle, binary_name)

                            dsym_info[binary_uuid] = DsymInfo(
                                dwarf_file=dwarf_file,
                                dsym_bundle=dsym_bundle,
                                relocations_file=relocations_file,
                            )
                            logger.debug(f"Found dSYM file {dwarf_file} with UUID {binary_uuid}")

        self._dsym_info = dsym_info
        return dsym_info

    def _find_dsym_bundle_root(self, dwarf_dir: Path) -> Path | None:
        current = dwarf_dir
        while current != current.parent:
            if current.suffix == ".dSYM":
                return current
            current = current.parent

        logger.warning(f"Could not find .dSYM bundle for DWARF directory: {dwarf_dir}")
        return None

    def _find_relocations_file_in_bundle(self, dsym_bundle: Path, binary_name: str) -> Path | None:
        # Standard location: dSYM/Contents/Resources/Relocations/<arch>/<binary>.yml
        relocations_dir = dsym_bundle / "Contents" / "Resources" / "Relocations"

        if not relocations_dir.exists():
            return None

        # Search for the binary's relocations file in any architecture subdirectory
        for extension in ("yml", "yaml"):
            for relocations_file in relocations_dir.rglob(f"{binary_name}.{extension}"):
                logger.debug(f"Found relocations file: {relocations_file}")
                return relocations_file

        return None
