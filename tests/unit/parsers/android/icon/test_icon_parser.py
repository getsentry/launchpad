import tempfile

from pathlib import Path

import pytest

from launchpad.artifacts.providers.zip_provider import UnsafePathError
from launchpad.parsers.android.icon.icon_parser import IconParser


class TestIconParserFindFile:
    def test_find_file_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            extract_dir = Path(tmpdir)
            parser = IconParser(extract_dir)

            with pytest.raises(UnsafePathError):
                parser._find_file("../../etc/passwd")

            with pytest.raises(UnsafePathError):
                parser._find_file("/etc/passwd")
