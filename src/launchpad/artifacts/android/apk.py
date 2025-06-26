"""Android APK model and utilities."""

from __future__ import annotations

from pathlib import Path

from launchpad.utils.logging import get_logger

from ..artifact import AndroidArtifact
from ..providers.zip_provider import ZipProvider
from .manifest.axml import AxmlUtils
from .manifest.manifest import AndroidManifest
from .resources.binary import BinaryResourceTable

logger = get_logger(__name__)


class APK(AndroidArtifact):
    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self._path = path
        self._zip_provider = ZipProvider(path)
        self._extract_dir = self._zip_provider.extract_to_temp_directory()
        self._manifest: AndroidManifest | None = None
        self._resource_table: BinaryResourceTable | None = None

    def get_manifest(self) -> AndroidManifest:
        if self._manifest is not None:
            return self._manifest

        manifest_files = list(self._extract_dir.rglob("AndroidManifest.xml"))
        if len(manifest_files) > 1:
            raise ValueError("Multiple AndroidManifest.xml files found in APK")

        manifest_file = manifest_files[0] if manifest_files else None
        if not manifest_file:
            raise ValueError("Could not find manifest in APK")

        with open(manifest_file, "rb") as f:
            manifest_buffer = f.read()
        binary_res_tables = self.get_resource_tables()

        self._manifest = AxmlUtils.binary_xml_to_android_manifest(manifest_buffer, binary_res_tables)
        return self._manifest

    def get_resource_tables(self) -> list[BinaryResourceTable]:  # type: ignore[override]
        if self._resource_table is not None:
            return [self._resource_table]

        arsc_files = list(self._extract_dir.rglob("resources.arsc"))
        if len(arsc_files) > 1:
            raise ValueError("Multiple resources.arsc files found in APK")

        arsc_file = arsc_files[0] if arsc_files else None
        if not arsc_file:
            logger.warning("No resources.arsc file found in APK")
            return []

        with open(arsc_file, "rb") as f:
            arsc_buffer = f.read()

        self._resource_table = BinaryResourceTable(arsc_buffer)
        return [self._resource_table]

    def get_extract_path(self) -> Path:
        return self._extract_dir
