import json

from io import BytesIO, TextIOWrapper
from pathlib import Path

from launchpad.size.runner import do_size, write_results_as_json


class TestSizeRunner:
    def test_apple(self) -> None:
        output_file = TextIOWrapper(BytesIO())
        path = Path("tests/_fixtures/ios/HackerNews.xcarchive.zip")
        results = do_size(path)
        write_results_as_json(results, output_file)

        output_file.seek(0)
        size = json.load(output_file)
        assert size["app_info"]["name"] == "HackerNews"

    def test_android(self) -> None:
        output_file = TextIOWrapper(BytesIO())
        path = Path("tests/_fixtures/android/hn.aab")
        results = do_size(path)
        write_results_as_json(results, output_file)

        output_file.seek(0)
        size = json.load(output_file)
        assert size["app_info"]["name"] == "Hacker News"
