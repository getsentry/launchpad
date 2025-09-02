from pathlib import Path

from ..artifact import ZippedAndroidArtifact
from .apk import APK
from .manifest.manifest import AndroidManifest


class ZippedAPK(ZippedAndroidArtifact):
    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self._primary_apk: APK | None = None

    def get_manifest(self) -> AndroidManifest:
        return self.get_primary_apk().get_manifest()

    def get_primary_apk(self) -> APK:
        if self._primary_apk is not None:
            return self._primary_apk

        extract_dir = self._ensure_extracted()
        for path in extract_dir.rglob("*.apk"):
            if path.is_file():
                self._primary_apk = APK(path)
                return self._primary_apk

        raise FileNotFoundError(f"No primary APK found in {extract_dir}")
