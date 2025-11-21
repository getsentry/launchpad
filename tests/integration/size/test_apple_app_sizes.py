from pathlib import Path
from typing import Callable, cast

import pytest

from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive
from launchpad.artifacts.artifact import AppleArtifact
from launchpad.artifacts.artifact_factory import ArtifactFactory
from launchpad.size.analyzers.apple import AppleAppAnalyzer
from launchpad.size.models.common import ComponentType


@pytest.fixture
def create_watch_app() -> Callable[[ZippedXCArchive, str, dict[str, int]], Path]:
    def _create_watch_app(artifact: ZippedXCArchive, name: str, files: dict[str, int]) -> Path:
        """Create a watch app with specified files and sizes."""
        app_bundle_path = artifact.get_app_bundle_path()

        # Create Watch directory if it doesn't exist
        watch_dir = app_bundle_path / "Watch"
        watch_dir.mkdir(exist_ok=True)

        # Create the watch app bundle
        watch_app_dir = watch_dir / f"{name}.app"
        watch_app_dir.mkdir(exist_ok=True)

        # Create files with specified sizes
        for filename, size in files.items():
            file_path = watch_app_dir / filename
            # Fill with dummy data to reach the target size
            file_path.write_bytes(b"x" * size)

        return watch_app_dir

    return _create_watch_app


class TestAppleAppSizes:
    """Test Apple app sizes functionality."""

    def test_apple_app_sizes(self, hackernews_xcarchive: Path) -> None:
        """Test that treemap structure matches reference report."""

        analyzer = AppleAppAnalyzer(skip_treemap=False)
        artifact = ArtifactFactory.from_path(hackernews_xcarchive)

        results = analyzer.analyze(cast(AppleArtifact, artifact))

        assert results.install_size == 9728000
        assert results.download_size == 6502319

        app_components = results.app_components
        assert len(app_components) == 1
        main_app = app_components[0]
        assert main_app.component_type == ComponentType.MAIN_ARTIFACT
        assert main_app.name == "HackerNews"
        assert main_app.path == "."
        assert main_app.download_size == 6502319
        assert main_app.install_size == 9728000

    def test_apple_app_sizes_with_watch_app(self, hackernews_xcarchive: Path, create_watch_app: Callable) -> None:
        """Test that watch app sizes are properly separated from main app."""

        artifact = cast(ZippedXCArchive, ArtifactFactory.from_path(hackernews_xcarchive))

        create_watch_app(
            artifact,
            "TestWatch",
            {
                "Info.plist": 4 * 1024,  # 4KB -> rounds to 16KB
                "TestWatch": 60 * 1024,  # 60KB -> rounds to 64KB
                "image.png": 15 * 1024,  # 15KB -> rounds to 16KB
            },
        )

        analyzer = AppleAppAnalyzer(skip_treemap=False)
        results = analyzer.analyze(artifact)

        assert results.install_size == 9818112
        assert results.download_size == 6503823

        app_components = results.app_components
        assert len(app_components) == 2

        main_app = app_components[0]
        assert main_app.component_type == ComponentType.MAIN_ARTIFACT
        assert main_app.name == "HackerNews"
        assert main_app.path == "."
        assert main_app.install_size == 9728000
        # Download size increased slightly by ZIP metadata overhead for watch app files
        assert main_app.download_size == 6503337

        watch_app = app_components[1]
        assert watch_app.component_type == ComponentType.WATCH_ARTIFACT
        assert watch_app.name == "TestWatch"
        assert watch_app.path == "Watch/TestWatch.app"
        # Watch app install size breakdown:
        # - TestWatch.app contents: 86016 bytes
        # - Watch/ directory overhead: 4096 bytes / 1 watch app = 4096 bytes per app
        assert watch_app.install_size == 90112
        assert watch_app.download_size == 486

        assert main_app.install_size + watch_app.install_size == results.install_size
        assert main_app.download_size + watch_app.download_size == results.download_size
