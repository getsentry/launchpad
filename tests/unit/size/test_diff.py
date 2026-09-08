from pathlib import Path

from launchpad.size.diff import compute_diff
from launchpad.size.models.android import AndroidAnalysisResults, AndroidAppInfo
from launchpad.size.models.common import FileAnalysis, FileInfo
from launchpad.size.models.diff import ChangeKind
from launchpad.size.models.treemap import TreemapType


def _file(path: str, size: int, hash: str, treemap_type: TreemapType = TreemapType.RESOURCES) -> FileInfo:
    return FileInfo(
        full_path=Path(path),
        path=path,
        size=size,
        file_type=path.split(".")[-1],
        treemap_type=treemap_type,
        hash=hash,
        is_dir=False,
    )


def _results(files: list[FileInfo], version: str, build: str) -> AndroidAnalysisResults:
    file_analysis = FileAnalysis(items=files)
    total = file_analysis.total_size
    return AndroidAnalysisResults(
        analysis_version="1.0.0",
        file_analysis=file_analysis,
        treemap=None,
        download_size=total,
        install_size=total,
        app_info=AndroidAppInfo(name="MyApp", version=version, build=build, app_id="com.example.myapp"),
        insights=None,
    )


class TestComputeDiff:
    def test_added_removed_modified_and_unchanged(self):
        base = _results(
            [
                _file("assets/logo.png", 1000, "a", TreemapType.ASSETS),
                _file("lib/removed.so", 500, "b", TreemapType.NATIVE_LIBRARIES),
                _file("res/stable.xml", 300, "c"),
            ],
            version="1.0.0",
            build="100",
        )
        head = _results(
            [
                _file("assets/logo.png", 2000, "a2", TreemapType.ASSETS),  # modified (grew)
                _file("res/stable.xml", 300, "c"),  # unchanged
                _file("lib/added.so", 800, "d", TreemapType.NATIVE_LIBRARIES),  # added
            ],
            version="1.1.0",
            build="101",
        )

        diff = compute_diff(base, head)

        assert diff.app_name == "MyApp"
        assert diff.base_label == "1.0.0 (100)"
        assert diff.head_label == "1.1.0 (101)"

        # base total = 1800, head total = 3100
        assert diff.install_size_diff == 1300
        assert diff.download_size_diff == 1300

        by_path = {c.path: c for c in diff.file_changes}
        assert by_path["assets/logo.png"].kind == ChangeKind.MODIFIED
        assert by_path["assets/logo.png"].size_diff == 1000
        assert by_path["lib/added.so"].kind == ChangeKind.ADDED
        assert by_path["lib/added.so"].size_diff == 800
        assert by_path["lib/removed.so"].kind == ChangeKind.REMOVED
        assert by_path["lib/removed.so"].size_diff == -500
        assert "res/stable.xml" not in by_path  # unchanged files are omitted

        # Sorted by absolute size delta, largest first
        assert [c.size_diff for c in diff.file_changes] == [1000, 800, -500]

    def test_category_diffs(self):
        base = _results([_file("assets/a.png", 1000, "a", TreemapType.ASSETS)], "1.0.0", "1")
        head = _results(
            [
                _file("assets/a.png", 1500, "a2", TreemapType.ASSETS),
                _file("lib/new.so", 400, "n", TreemapType.NATIVE_LIBRARIES),
            ],
            "1.0.1",
            "2",
        )

        diff = compute_diff(base, head)
        by_cat = {c.category: c.size_diff for c in diff.category_diffs}
        assert by_cat[TreemapType.ASSETS.value] == 500
        assert by_cat[TreemapType.NATIVE_LIBRARIES.value] == 400

    def test_identical_builds_have_no_changes(self):
        files = [_file("assets/a.png", 1000, "a", TreemapType.ASSETS)]
        diff = compute_diff(_results(files, "1.0.0", "1"), _results(files, "1.0.0", "1"))

        assert diff.file_changes == []
        assert diff.category_diffs == []
        assert diff.install_size_diff == 0

    def test_to_dict_includes_computed_deltas(self):
        base = _results([_file("a.txt", 100, "a")], "1.0.0", "1")
        head = _results([_file("a.txt", 250, "b")], "1.0.1", "2")

        data = compute_diff(base, head).to_dict()
        assert data["install_size_diff"] == 150
        assert data["download_size_diff"] == 150
        assert data["file_changes"][0]["size_diff"] == 150
        assert data["file_changes"][0]["kind"] == "modified"
