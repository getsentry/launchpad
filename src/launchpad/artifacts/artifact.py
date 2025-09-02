from pathlib import Path
from typing import Any

from .android.manifest.manifest import AndroidManifest
from .android.resources.resource_table import ResourceTable


class Artifact:
    """Base class for all artifacts that can be analyzed."""

    def __init__(self, path: Path) -> None:
        self.path = path


class ZippedArtifact(Artifact):
    """Base class for artifacts that are ZIP files requiring extraction."""

    def __init__(self, path: Path) -> None:
        super().__init__(path)
        # Import here to avoid circular imports
        from .providers.zip_provider import ZipProvider

        self._zip_provider = ZipProvider(path)
        self._extract_dir: Path | None = None

    def _ensure_extracted(self) -> Path:
        """Ensure the archive is extracted and return the extraction directory."""
        if self._extract_dir is None:
            self._extract_dir = self._zip_provider.extract_to_temp_directory()
        return self._extract_dir

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with automatic cleanup."""
        self._zip_provider.cleanup()
        self._extract_dir = None
        return False  # Don't suppress exceptions


class AndroidArtifact(Artifact):
    """Protocol defining the interface for Android artifacts."""

    def get_manifest(self) -> AndroidManifest:
        """Get the Android manifest information."""
        raise NotImplementedError("Not implemented")

    def get_resource_tables(self) -> list[ResourceTable]:
        """Get the resource tables from the artifact."""
        raise NotImplementedError("Not implemented")


class ZippedAndroidArtifact(ZippedArtifact, AndroidArtifact):
    """Base class for Android artifacts that are ZIP files."""

    pass


class AppleArtifact(Artifact):
    """Protocol defining the interface for Apple artifacts."""

    def get_plist(self) -> dict[str, Any]:
        """Get the plist from the artifact."""
        raise NotImplementedError("Not implemented")

    def generate_ipa(self, output_path: Path):
        raise NotImplementedError("Not implemented")


class ZippedAppleArtifact(ZippedArtifact, AppleArtifact):
    """Base class for Apple artifacts that are ZIP files."""

    pass
