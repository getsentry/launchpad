"""Android APK model and utilities."""

from __future__ import annotations

import tempfile

from pathlib import Path

from launchpad.parsers.android.dex.dex_mapping import DexMapping
from launchpad.utils.android.bundletool import Bundletool, DeviceSpec
from launchpad.utils.logging import get_logger

from ..artifact import ZippedAndroidArtifact
from .apk import APK
from .manifest.manifest import AndroidManifest
from .manifest.proto_xml import ProtoXmlUtils
from .resources.proto import ProtobufResourceTable

logger = get_logger(__name__)


class AAB(ZippedAndroidArtifact):
    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self._path = path
        self._manifest: AndroidManifest | None = None
        self._resource_table: ProtobufResourceTable | None = None
        self._primary_apks: list[APK] | None = None
        self._dex_mapping: DexMapping | None = None
        self._universal_apk: APK | None = None
        self._temp_apk_files: list[Path] = []

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup of temporary APK files and ZIP extraction."""
        # Clean up temporary APK files
        for temp_file in self._temp_apk_files:
            if temp_file.exists():
                temp_file.unlink()
        self._temp_apk_files.clear()

        # Call parent cleanup for ZIP extraction
        return super().__exit__(exc_type, exc_val, exc_tb)

    def get_manifest(self) -> AndroidManifest:
        if self._manifest is not None:
            return self._manifest

        extract_dir = self._ensure_extracted()
        manifest_files = list(extract_dir.rglob("base/manifest/AndroidManifest.xml"))
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

        extract_dir = self._ensure_extracted()
        arsc_files = list(extract_dir.rglob("base/resources.pb"))
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

        # Create APKs with their own managed temporary files
        with tempfile.TemporaryDirectory(prefix="bundletool-apks-") as bundletool_temp:
            apks_dir = Path(bundletool_temp)
            bundletool = Bundletool()
            bundletool.build_apks(bundle_path=self._path, output_dir=apks_dir, device_spec=device_spec)

            apks = []
            for apk_path in apks_dir.glob("*.apk"):
                # Copy each APK to its own managed temporary file
                with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as temp_apk:
                    temp_apk_path = Path(temp_apk.name)
                    temp_apk.write(apk_path.read_bytes())
                    self._temp_apk_files.append(temp_apk_path)
                    apks.append(APK(temp_apk_path, self.get_dex_mapping()))

            self._primary_apks = apks
            return apks

    def get_universal_apk(self, device_spec: DeviceSpec = DeviceSpec()) -> APK:
        if self._universal_apk is not None:
            return self._universal_apk

        # Create universal APK with its own managed temporary file
        with tempfile.TemporaryDirectory(prefix="bundletool-universal-") as bundletool_temp:
            apk_dir = Path(bundletool_temp)
            bundletool = Bundletool()
            bundletool.build_apks(
                bundle_path=self._path,
                output_dir=apk_dir,
                device_spec=device_spec,
                universal_apk=True,
            )

            apk_files = list(apk_dir.glob("*.apk"))
            if len(apk_files) != 1:
                raise ValueError("Expected 1 APK, got %d" % len(apk_files))

            # Copy the APK to its own managed temporary file
            with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as temp_apk:
                temp_apk_path = Path(temp_apk.name)
                temp_apk.write(apk_files[0].read_bytes())
                self._temp_apk_files.append(temp_apk_path)
                apk = APK(temp_apk_path, self.get_dex_mapping())

            self._universal_apk = apk
            return apk

    def get_dex_mapping(self) -> DexMapping | None:
        if self._dex_mapping is not None:
            return self._dex_mapping

        extract_dir = self._ensure_extracted()
        dex_mapping_files = list(extract_dir.rglob("proguard.map"))
        if len(dex_mapping_files) > 1:
            raise ValueError("Multiple proguard.map files found in AAB")

        if len(dex_mapping_files) == 0:
            return None

        dex_mapping_file = dex_mapping_files[0]
        with open(dex_mapping_file, "rb") as f:
            dex_mapping_buffer = f.read()
        return DexMapping(dex_mapping_buffer)
