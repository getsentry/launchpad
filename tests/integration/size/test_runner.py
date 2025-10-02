import json

from io import BytesIO, TextIOWrapper
from pathlib import Path

from launchpad.size.runner import do_size, write_results_as_json


class TestSizeRunner:
    def test_apple(self, hackernews_xcarchive: Path) -> None:
        output_file = TextIOWrapper(BytesIO())
        results = do_size(hackernews_xcarchive)
        write_results_as_json(results, output_file)

        output_file.seek(0)
        size = json.load(output_file)
        assert size["app_info"]["name"] == "HackerNews"
        assert size["install_size"] > size["download_size"]

    def test_android(self, hn_aab: Path) -> None:
        output_file = TextIOWrapper(BytesIO())
        results = do_size(hn_aab)
        write_results_as_json(results, output_file)

        output_file.seek(0)
        size = json.load(output_file)
        assert size["app_info"]["name"] == "Hacker News"
        assert size["install_size"] > size["download_size"]
