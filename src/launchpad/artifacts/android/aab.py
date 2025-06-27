"""Android APK model and utilities."""

from __future__ import annotations

from pathlib import Path

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
    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self._path = path
        self._zip_provider = ZipProvider(path)
        self._extract_dir = self._zip_provider.extract_to_temp_directory()
        self._manifest: AndroidManifest | None = None
        self._resource_table: ProtobufResourceTable | None = None
        self._primary_apks: list[APK] | None = None

    def get_manifest(self) -> AndroidManifest:
        if self._manifest is not None:
            return self._manifest

        manifest_files = list(self._extract_dir.rglob("base/manifest/AndroidManifest.xml"))
        if len(manifest_files) > 1:
            raise ValueError("Multiple AndroidManifest.xml files found in AAB")

        manifest_file = manifest_files[0] if manifest_files else None
        if not manifest_file:
            raise ValueError("Could not find manifest in AAB")

        with open(manifest_file, "rb") as f:
            manifest_buffer = f.read()
        proto_res_tables = self.get_resource_tables()

        self._manifest = ProtoXmlUtils.proto_xml_to_android_manifest(manifest_buffer, proto_res_tables)
        return self._manifest

    def get_resource_tables(self) -> list[ProtobufResourceTable]:  # type: ignore[override]
        if self._resource_table is not None:
            return [self._resource_table]

        arsc_files = list(self._extract_dir.rglob("base/resources.pb"))
        if len(arsc_files) > 1:
            raise ValueError("Multiple resources.pb files found in AAB")

        arsc_file = arsc_files[0] if arsc_files else None
        if not arsc_file:
            raise ValueError("Could not find resources.pb in AAB")

        with open(arsc_file, "rb") as f:
            arsc_buffer = f.read()
        self._resource_table = ProtobufResourceTable(arsc_buffer)
        return [self._resource_table]

    def get_primary_apks(self, device_spec: DeviceSpec = DeviceSpec()) -> list[APK]:
        if self._primary_apks is not None:
            return self._primary_apks

        apks_dir = create_temp_directory("apks-")
        try:
            bundletool = Bundletool()
            bundletool.build_apks(bundle_path=self._path, output_dir=apks_dir, device_spec=device_spec)

            apks = []
            for apk_path in apks_dir.glob("*.apk"):
                apks.append(APK(apk_path))

            self._primary_apks = apks
            return apks
        finally:
            cleanup_directory(apks_dir)
