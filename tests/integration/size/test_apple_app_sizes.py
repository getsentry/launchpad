import plistlib

from pathlib import Path
from typing import Callable, cast

import pytest

from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive
from launchpad.artifacts.artifact import AppleArtifact
from launchpad.artifacts.artifact_factory import ArtifactFactory
from launchpad.size.analyzers.apple import AppleAppAnalyzer
from launchpad.size.models.common import ComponentType


@pytest.fixture
def create_watch_app() -> Callable[[ZippedXCArchive, str, str, dict[str, int]], Path]:
    def _create_watch_app(artifact: ZippedXCArchive, name: str, app_id: str, files: dict[str, int]) -> Path:
        """Create a watch app with specified files and sizes."""
        app_bundle_path = artifact.get_app_bundle_path()

        # Create Watch directory if it doesn't exist
        watch_dir = app_bundle_path / "Watch"
        watch_dir.mkdir(exist_ok=True)

        # Create the watch app bundle
        watch_app_dir = watch_dir / f"{name}.app"
        watch_app_dir.mkdir(exist_ok=True)

        # Create Info.plist with app ID
        plist_data = {"CFBundleIdentifier": app_id}
        plist_path = watch_app_dir / "Info.plist"
        with open(plist_path, "wb") as f:
            plistlib.dump(plist_data, f)

        # Create files with specified sizes
        for filename, size in files.items():
            if filename != "Info.plist":  # Already created above
                file_path = watch_app_dir / filename
                file_path.write_bytes(b"x" * size)

        return watch_app_dir

    return _create_watch_app


@pytest.fixture
def create_app_clip() -> Callable[[ZippedXCArchive, str, str, dict[str, int]], Path]:
    def _create_app_clip(artifact: ZippedXCArchive, name: str, app_id: str, files: dict[str, int]) -> Path:
        """Create an App Clip with specified files and sizes."""
        app_bundle_path = artifact.get_app_bundle_path()

        app_clips_dir = app_bundle_path / "AppClips"
        app_clips_dir.mkdir(exist_ok=True)

        app_clip_dir = app_clips_dir / f"{name}.app"
        app_clip_dir.mkdir(exist_ok=True)

        plist_data = {"CFBundleIdentifier": app_id}
        plist_path = app_clip_dir / "Info.plist"
        with open(plist_path, "wb") as f:
            plistlib.dump(plist_data, f)

        for filename, size in files.items():
            if filename != "Info.plist":
                file_path = app_clip_dir / filename
                file_path.write_bytes(b"x" * size)

        return app_clip_dir

    return _create_app_clip


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
        assert main_app.app_id == "com.emergetools.hackernews"
        assert main_app.name == "HackerNews"
        assert main_app.path == "."
        assert main_app.download_size == 6502319
        assert main_app.install_size == 9728000

    def test_apple_app_sizes_with_watch_app(self, hackernews_xcarchive: Path, create_watch_app: Callable) -> None:
        """Test that watch app sizes are properly separated from main app."""

        artifact = cast(ZippedXCArchive, ArtifactFactory.from_path(hackernews_xcarchive))

        # Note: Info.plist is created separately with plistlib to include the app_id
        create_watch_app(
            artifact,
            "TestWatch",
            "com.test.watch.app",
            {
                "TestWatch": 60 * 1024,  # 60KB -> rounds to 64KB
                "image.png": 15 * 1024,  # 15KB -> rounds to 16KB
            },
        )

        analyzer = AppleAppAnalyzer(skip_treemap=False)
        results = analyzer.analyze(artifact)

        assert results.install_size == 9818112
        assert results.download_size == 6503930

        app_components = results.app_components
        assert len(app_components) == 2

        main_app = app_components[0]
        assert main_app.component_type == ComponentType.MAIN_ARTIFACT
        assert main_app.app_id == "com.emergetools.hackernews"
        assert main_app.name == "HackerNews"
        assert main_app.path == "."
        assert main_app.install_size == 9728000
        assert main_app.download_size == 6503337

        watch_app = app_components[1]
        assert watch_app.component_type == ComponentType.WATCH_ARTIFACT
        assert watch_app.app_id == "com.test.watch.app"
        assert watch_app.name == "TestWatch"
        assert watch_app.path == "Watch/TestWatch.app"
        assert watch_app.install_size == 90112
        assert watch_app.download_size == 593

        assert main_app.install_size + watch_app.install_size == results.install_size
        assert main_app.download_size + watch_app.download_size == results.download_size

    def test_apple_app_sizes_with_app_clip(self, hackernews_xcarchive: Path, create_app_clip: Callable) -> None:
        """Test that App Clip sizes are properly separated from main app."""

        artifact = cast(ZippedXCArchive, ArtifactFactory.from_path(hackernews_xcarchive))

        create_app_clip(
            artifact,
            "TestAppClip",
            "com.test.app.clip",
            {
                "TestAppClip": 50 * 1024,  # 50KB -> rounds to 56KB
                "image.png": 15 * 1024,  # 15KB -> rounds to 16KB
            },
        )

        analyzer = AppleAppAnalyzer(skip_treemap=False)
        results = analyzer.analyze(artifact)

        app_components = results.app_components
        assert len(app_components) == 2

        main_app = app_components[0]
        assert main_app.component_type == ComponentType.MAIN_ARTIFACT
        assert main_app.app_id == "com.emergetools.hackernews"
        assert main_app.name == "HackerNews"
        assert main_app.path == "."

        app_clip = app_components[1]
        assert app_clip.component_type == ComponentType.APP_CLIP_ARTIFACT
        assert app_clip.app_id == "com.test.app.clip"
        assert app_clip.name == "TestAppClip"
        assert app_clip.path == "AppClips/TestAppClip.app"
        assert app_clip.install_size > 0
        assert app_clip.download_size > 0

        assert main_app.install_size + app_clip.install_size == results.install_size
        assert main_app.download_size + app_clip.download_size == results.download_size
