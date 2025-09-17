import shutil
import tempfile

from pathlib import Path
from typing import Callable

from ..artifact import AndroidArtifact
from ..providers.zip_provider import ZipProvider
from .apk import APK
from .manifest.manifest import AndroidManifest


class ZippedAPK(AndroidArtifact):
    def __init__(self, path: Path, cleanup: None | Callable[[], None] = None) -> None:
        super().__init__(path, cleanup=cleanup)
        self._zip_provider = ZipProvider(path)
        self._extract_dir = self._zip_provider.extract_to_temp_directory()
        self._primary_apk: APK | None = None

    def get_manifest(self) -> AndroidManifest:
        return self.get_primary_apk().get_manifest()

    def get_primary_apk(self) -> APK:
        if self._primary_apk is not None:
            return self._primary_apk

        for path in self._extract_dir.rglob("*.apk"):
            if path.is_file():
                tmp_dir = Path(tempfile.mkdtemp())
                new_path = tmp_dir / path.name
                shutil.copyfile(path, new_path)
                self._primary_apk = APK(new_path, None, cleanup=lambda: shutil.rmtree(tmp_dir))
                return self._primary_apk

        raise FileNotFoundError(f"No primary APK found in {self._extract_dir}")
