import functools
import json
import logging
import multiprocessing as mp
import os
import plistlib
import threading
import time

from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any, Callable, cast
from unittest.mock import patch

import pytest
import sentry_sdk
import sentry_sdk.transport

from sentry_sdk.envelope import Envelope

from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive
from launchpad.artifacts.artifact import AppleArtifact
from launchpad.artifacts.artifact_factory import ArtifactFactory
from launchpad.size.analyzers import apple
from launchpad.size.analyzers.apple import AppleAppAnalyzer
from launchpad.size.models.common import ComponentType
from launchpad.tracing import current_request_id, request_context


class _CapturingTransport(sentry_sdk.transport.Transport):
    def __init__(self) -> None:
        super().__init__()
        self.transactions: list[dict[str, Any]] = []

    def capture_envelope(self, envelope: Envelope) -> None:
        for item in envelope.items:
            if item.headers.get("type") == "transaction":
                self.transactions.append(json.loads(item.get_bytes()))


def _log_forever(i: int) -> None:
    log = logging.getLogger("launchpad.size.analyzers.apple")
    while True:
        log.info("tick %d", i)


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
        assert analyzer._binary_analysis_worker_count(0) == 0
        assert analyzer._binary_analysis_worker_count(100) == 4
        assert analyzer._binary_analysis_worker_count(2) == 2

    def test_binary_worker_count_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        analyzer = AppleAppAnalyzer()
        monkeypatch.setenv("LAUNCHPAD_BINARY_ANALYSIS_WORKERS", "3")
        assert analyzer._binary_analysis_worker_count(100) == 3
        assert analyzer._binary_analysis_worker_count(2) == 2  # capped at num binaries
        monkeypatch.setenv("LAUNCHPAD_BINARY_ANALYSIS_WORKERS", "1")
        assert analyzer._binary_analysis_worker_count(100) == 1
        monkeypatch.setenv("LAUNCHPAD_BINARY_ANALYSIS_WORKERS", "0")
        assert analyzer._binary_analysis_worker_count(100) == 0

    def test_parallel_binary_analysis_matches_in_process(
        self, hackernews_xcarchive: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("LAUNCHPAD_BINARY_ANALYSIS_WORKERS", "0")
        in_process = AppleAppAnalyzer(skip_treemap=False).analyze(
            cast(AppleArtifact, ArtifactFactory.from_path(hackernews_xcarchive))
        )

        monkeypatch.setenv("LAUNCHPAD_BINARY_ANALYSIS_WORKERS", "4")
        parallel = AppleAppAnalyzer(skip_treemap=False).analyze(
            cast(AppleArtifact, ArtifactFactory.from_path(hackernews_xcarchive))
        )

        assert in_process.install_size == parallel.install_size
        assert in_process.download_size == parallel.download_size
        assert in_process.treemap is not None and parallel.treemap is not None
        assert in_process.treemap.model_dump_json() == parallel.treemap.model_dump_json()

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

    def test_worker_logs_relay_to_parent_with_request_id(
        self, hackernews_xcarchive: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Per-binary logs are emitted inside pool workers, which have no logging config of
        their own; they must reach the parent's handlers stamped with the parent's request id."""
        ctx = mp.get_context("forkserver")
        monkeypatch.setattr(apple, "ProcessPoolExecutor", functools.partial(ProcessPoolExecutor, mp_context=ctx))
        monkeypatch.setenv("LAUNCHPAD_BINARY_ANALYSIS_WORKERS", "2")
        caplog.set_level(logging.INFO)

        with request_context():
            request_id = current_request_id()
            AppleAppAnalyzer(skip_treemap=False).analyze(
                cast(AppleArtifact, ArtifactFactory.from_path(hackernews_xcarchive))
            )

        completed = [r for r in caplog.records if r.getMessage() == "size.apple.binary_analysis_completed"]
        assert completed
        assert all(r.process != os.getpid() for r in completed)
        assert all(getattr(r, "request_id", None) == request_id for r in completed)
        assert all(isinstance(getattr(r, "elapsed_s", None), float) for r in completed)

    def test_parallel_binary_spans_reattach_to_parent_transaction(
        self, hackernews_xcarchive: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Workers can't report spans, so the parent rebuilds one per binary from worker
        timestamps; they must land on the task transaction and reflect real concurrency."""
        ctx = mp.get_context("forkserver")
        monkeypatch.setattr(apple, "ProcessPoolExecutor", functools.partial(ProcessPoolExecutor, mp_context=ctx))
        monkeypatch.setenv("LAUNCHPAD_BINARY_ANALYSIS_WORKERS", "2")
        transport = _CapturingTransport()
        sentry_sdk.init(dsn="https://key@example.invalid/1", transport=transport, traces_sample_rate=1.0)
        try:
            with sentry_sdk.start_transaction(name="test"):
                artifact = cast(AppleArtifact, ArtifactFactory.from_path(hackernews_xcarchive))
                binary_count = len(artifact.get_all_binary_paths())
                AppleAppAnalyzer(skip_treemap=False).analyze(artifact)
            sentry_sdk.flush()
        finally:
            sentry_sdk.get_global_scope().set_client(None)

        spans = [
            s
            for t in transport.transactions
            for s in t["spans"]
            if s["op"] == "function" and s["description"].endswith("AppleAppAnalyzer._analyze_binary")
        ]
        assert len(spans) == binary_count
        assert {s["data"]["binary_name"] for s in spans} == {b.name for b in artifact.get_all_binary_paths()}
        assert all(s["timestamp"] > s["start_timestamp"] for s in spans)
        assert any(
            a is not b and a["start_timestamp"] < b["start_timestamp"] < a["timestamp"] for a in spans for b in spans
        )

    def test_worker_log_relay_exits_cleanly_after_killing_workers(self, caplog: pytest.LogCaptureFixture) -> None:
        """Simulates the deadline path: workers SIGKILLed mid-log must not leave the parent
        blocked on the shared log queue or with a feeder thread that would hang interpreter exit."""
        caplog.set_level(logging.INFO)
        ctx = mp.get_context("forkserver")
        started = time.monotonic()
        with apple._WorkerLogRelay() as relay:
            executor = ProcessPoolExecutor(
                max_workers=2,
                mp_context=ctx,
                initializer=apple._binary_worker_init,
                initargs=(relay.queue, relay.level),
            )
            for i in range(2):
                executor.submit(_log_forever, i)
            deadline = time.monotonic() + 10
            while not any(r.getMessage().startswith("tick") for r in caplog.records) and time.monotonic() < deadline:
                time.sleep(0.05)
            assert any(r.getMessage().startswith("tick") for r in caplog.records)
            executor.kill_workers()

        assert time.monotonic() - started < 15
        assert not relay._thread.is_alive()
        assert not any(t.name == "QueueFeederThread" for t in threading.enumerate())

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
