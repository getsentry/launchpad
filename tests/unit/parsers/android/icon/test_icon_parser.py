import tempfile

from pathlib import Path

from launchpad.parsers.android.icon.icon_parser import IconParser


class TestIconParserFindFile:
    def test_find_file_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            extract_dir = Path(tmpdir)
            parser = IconParser(extract_dir)

            assert parser._find_file("../../etc/passwd") is None
            assert parser._find_file("/etc/passwd") is None
