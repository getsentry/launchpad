from pathlib import Path

from ..artifact import ZippedAndroidArtifact
from .aab import AAB
from .apk import APK
from .manifest.manifest import AndroidManifest


class ZippedAAB(ZippedAndroidArtifact):
    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self._aab: AAB | None = None

    def get_manifest(self) -> AndroidManifest:
        return self.get_aab().get_manifest()

    def get_aab(self) -> AAB:
        if self._aab is not None:
            return self._aab

        extract_dir = self._ensure_extracted()
        for path in extract_dir.rglob("*.aab"):
            if path.is_file():
                self._aab = AAB(path)
                return self._aab

        raise FileNotFoundError(f"No AAB found in {extract_dir}")

    def get_primary_apks(self) -> list[APK]:
        return self.get_aab().get_primary_apks()
