import functools
import multiprocessing as mp
import plistlib
import signal
import time

from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Callable, cast
from unittest.mock import patch

import pytest

from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive
from launchpad.artifacts.artifact import AppleArtifact
from launchpad.artifacts.artifact_factory import ArtifactFactory
from launchpad.size.analyzers import apple
from launchpad.size.analyzers.apple import AppleAppAnalyzer, _force_kill_pool
from launchpad.size.models.common import ComponentType


def _sigterm_ignoring_busy_loop(*_args: object) -> None:
    """Models a worker wedged in a native call: SIGTERM is ignored, spins forever."""
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    while True:
        pass


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

    def test_generate_insight_logs_timing(self) -> None:
        """Each insight logs its wall-clock duration so slow phases are visible."""

        class _DummyInsight:
            def generate(self, _input: object) -> str:
                return "ok"

        analyzer = AppleAppAnalyzer()
        with patch("launchpad.size.analyzers.apple.logger") as mock_logger:
            result = analyzer._generate_insight_with_tracing(_DummyInsight, cast(object, None), "dummy")

        assert result == "ok"
        mock_logger.info.assert_called_once()
        args, kwargs = mock_logger.info.call_args
        assert args[0] == "size.apple.insight_completed"
        assert kwargs["extra"]["insight"] == "dummy"
        assert "elapsed_s" in kwargs["extra"]

    def test_binary_worker_count(self) -> None:
        analyzer = AppleAppAnalyzer()
        assert analyzer._binary_analysis_worker_count(1) == 1
        assert analyzer._binary_analysis_worker_count(0) == 1
        assert analyzer._binary_analysis_worker_count(100) == 4
        assert analyzer._binary_analysis_worker_count(2) == 2

    def test_binary_worker_count_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        analyzer = AppleAppAnalyzer()
        monkeypatch.setenv("LAUNCHPAD_BINARY_ANALYSIS_WORKERS", "3")
        assert analyzer._binary_analysis_worker_count(100) == 3
        assert analyzer._binary_analysis_worker_count(2) == 2  # capped at num binaries
        monkeypatch.setenv("LAUNCHPAD_BINARY_ANALYSIS_WORKERS", "1")
        assert analyzer._binary_analysis_worker_count(100) == 1

    def test_parallel_binary_analysis_matches_serial(
        self, hackernews_xcarchive: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Toggling the worker count must not change analysis output."""
        monkeypatch.setenv("LAUNCHPAD_BINARY_ANALYSIS_WORKERS", "1")
        serial = AppleAppAnalyzer(skip_treemap=False).analyze(
            cast(AppleArtifact, ArtifactFactory.from_path(hackernews_xcarchive))
        )

        monkeypatch.setenv("LAUNCHPAD_BINARY_ANALYSIS_WORKERS", "4")
        parallel = AppleAppAnalyzer(skip_treemap=False).analyze(
            cast(AppleArtifact, ArtifactFactory.from_path(hackernews_xcarchive))
        )

        assert serial.install_size == parallel.install_size
        assert serial.download_size == parallel.download_size
        assert serial.treemap is not None and parallel.treemap is not None
        assert serial.treemap.model_dump_json() == parallel.treemap.model_dump_json()

    def test_force_kill_pool_kills_sigterm_ignoring_worker(self) -> None:
        """Cleanup must SIGKILL workers that ignore SIGTERM (e.g. wedged in LIEF)."""
        ctx = mp.get_context("fork")
        executor = ProcessPoolExecutor(max_workers=2, mp_context=ctx)
        try:
            executor.submit(_sigterm_ignoring_busy_loop)
            executor.submit(_sigterm_ignoring_busy_loop)

            deadline = time.monotonic() + 10
            while len(getattr(executor, "_processes", {})) < 2 and time.monotonic() < deadline:
                time.sleep(0.05)
            procs = list(executor._processes.values())
            assert len(procs) == 2 and all(p.is_alive() for p in procs)

            _force_kill_pool(executor)

            deadline = time.monotonic() + 15
            for p in procs:
                while p.is_alive() and time.monotonic() < deadline:
                    p.join(timeout=0.2)
                assert not p.is_alive()
                assert p.exitcode == -signal.SIGKILL
        finally:
            for p in list((getattr(executor, "_processes", None) or {}).values()):
                if p.is_alive():
                    p.kill()
            executor.shutdown(wait=False, cancel_futures=True)

    def test_parallel_binary_analysis_under_forkserver(
        self, hackernews_xcarchive: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Prod uses the forkserver start method, which pickles the analyzer and binaries;
        the fork default in tests would mask a pickling regression, so exercise it here."""
        ctx = mp.get_context("forkserver")
        monkeypatch.setattr(apple, "ProcessPoolExecutor", functools.partial(ProcessPoolExecutor, mp_context=ctx))
        monkeypatch.setenv("LAUNCHPAD_BINARY_ANALYSIS_WORKERS", "2")

        results = AppleAppAnalyzer(skip_treemap=False).analyze(
            cast(AppleArtifact, ArtifactFactory.from_path(hackernews_xcarchive))
        )

        assert results.treemap is not None
        assert results.install_size > 0

    def test_binary_completed_log_includes_elapsed(self) -> None:
        """Per-binary duration must survive parallelization via an elapsed_s log field."""
        from unittest.mock import Mock, patch

        binary_info = Mock()
        binary_info.name = "Foo"
        binary = Mock(symbol_info=None)

        with patch.object(apple.logger, "info") as info:
            AppleAppAnalyzer()._log_binary_completed(binary_info, binary, 1.23456)

        assert info.call_args.kwargs["extra"]["elapsed_s"] == 1.235

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
