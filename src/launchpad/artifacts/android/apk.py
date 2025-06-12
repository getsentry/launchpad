"""Android APK model and utilities."""

from __future__ import annotations

import logging
from typing import Optional

from ..artifact import AndroidArtifact
from ..providers.zip_provider import ZipProvider
from .manifest.axml import AxmlUtils
from .manifest.manifest import AndroidManifest
from .resources.binary import BinaryResourceTable

logger = logging.getLogger(__name__)


class APK(AndroidArtifact):
    """Represents an Android APK file that can be analyzed."""

    def __init__(self, content: bytes) -> None:
        """Initialize APK with raw bytes content.

        Args:
            content: Raw bytes of the APK file
        """
        super().__init__(content)
        self._zip_provider = ZipProvider(content)
        self._manifest: Optional[AndroidManifest] = None
        self._resource_table: Optional[BinaryResourceTable] = None

    def get_manifest(self) -> AndroidManifest:
        """Get the Android manifest information.

        Returns:
            Dictionary containing manifest information

        Raises:
            ValueError: If manifest cannot be found or parsed
        """
        if self._manifest is not None:
            return self._manifest

        zip_file = self._zip_provider.get_zip()
        manifest_files = [f for f in zip_file.namelist() if f.endswith("AndroidManifest.xml")]
        if len(manifest_files) > 1:
            raise ValueError("Multiple AndroidManifest.xml files found in APK")

        manifest_file = manifest_files[0] if manifest_files else None
        if not manifest_file:
            raise ValueError("Could not find manifest in APK")

        manifest_buffer = zip_file.read(manifest_file)
        binary_res_tables = self.get_resource_tables()

        self._manifest = AxmlUtils.binary_xml_to_android_manifest(manifest_buffer, binary_res_tables)
        return self._manifest

    def get_resource_tables(self) -> list[BinaryResourceTable]:
        """Get the resource tables from the artifact.

        Returns:
            List of resource table dictionaries

        Raises:
            ValueError: If resource tables cannot be found or parsed
        """
        if self._resource_table is not None:
            return [self._resource_table]

        zip_file = self._zip_provider.get_zip()
        arsc_files = [f for f in zip_file.namelist() if f.endswith("resources.arsc")]
        if len(arsc_files) > 1:
            raise ValueError("Multiple resources.arsc files found in APK")

        arsc_file = arsc_files[0] if arsc_files else None
        if not arsc_file:
            logger.warning("No resources.arsc file found in APK")
            return []

        arsc_buffer = zip_file.read(arsc_file)
        self._resource_table = BinaryResourceTable(arsc_buffer)
        return [self._resource_table]
