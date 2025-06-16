"""Android APK model and utilities."""

from __future__ import annotations

from launchpad.utils.android.bundletool import Bundletool, DeviceSpec
from launchpad.utils.file_utils import cleanup_directory, create_temp_directory
from launchpad.utils.logging import get_logger

from ..artifact import AndroidArtifact
from ..providers.zip_provider import ZipProvider
from .apk import APK
from .manifest.manifest import AndroidManifest
from .manifest.proto_xml import ProtoXmlUtils
from .resources.proto import ProtobufResourceTable

logger = get_logger(__name__)


class AAB(AndroidArtifact):
    """Represents an Android AAB file that can be analyzed."""

    def __init__(self, content: bytes) -> None:
        """Initialize APK with raw bytes content.

        Args:
            content: Raw bytes of the AAB file
        """
        super().__init__(content)
        self._path = create_temp_directory("aab-") / "bundle.aab"
        self._path.write_bytes(content)
        self._zip_provider = ZipProvider(content)
        self._manifest: AndroidManifest | None = None
        self._resource_table: ProtobufResourceTable | None = None
        self._primary_apks: list[APK] | None = None

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
        manifest_files = [f for f in zip_file.namelist() if f.endswith("base/manifest/AndroidManifest.xml")]
        if len(manifest_files) > 1:
            raise ValueError("Multiple AndroidManifest.xml files found in AAB")

        manifest_file = manifest_files[0] if manifest_files else None
        if not manifest_file:
            raise ValueError("Could not find manifest in APK")

        manifest_buffer = zip_file.read(manifest_file)
        proto_res_tables = self.get_resource_tables()

        self._manifest = ProtoXmlUtils.proto_xml_to_android_manifest(manifest_buffer, proto_res_tables)
        return self._manifest

    def get_resource_tables(self) -> list[ProtobufResourceTable]:  # type: ignore[override]
        """Get the resource tables from the artifact.

        Returns:
            List of resource table dictionaries

        Raises:
            ValueError: If resource tables cannot be found or parsed
        """
        if self._resource_table is not None:
            return [self._resource_table]

        zip_file = self._zip_provider.get_zip()
        arsc_files = [f for f in zip_file.namelist() if f.endswith("base/resources.pb")]
        if len(arsc_files) > 1:
            raise ValueError("Multiple resources.arsc files found in APK")

        arsc_file = arsc_files[0] if arsc_files else None
        if not arsc_file:
            raise ValueError("Could not find resources.pb in APK")

        arsc_buffer = zip_file.read(arsc_file)
        self._resource_table = ProtobufResourceTable(arsc_buffer)
        return [self._resource_table]

    def get_primary_apks(self, device_spec: DeviceSpec = DeviceSpec()) -> list[APK]:
        """Split the AAB into APKS.

        Args:
            device_spec: Device specification for APK splitting
        """
        if self._primary_apks is not None:
            return self._primary_apks

        apks_dir = create_temp_directory("apks-")
        try:
            bundletool = Bundletool()
            bundletool.build_apks(bundle_path=self._path, output_dir=apks_dir, device_spec=device_spec)

            apks = []
            for apk_path in apks_dir.glob("*.apk"):
                with open(apk_path, "rb") as apk_file:
                    apks.append(APK(apk_file.read()))

            self._primary_apks = apks
            return apks
        finally:
            cleanup_directory(apks_dir)
