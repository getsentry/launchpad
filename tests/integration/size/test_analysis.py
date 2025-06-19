import json
from io import BytesIO, TextIOWrapper
from pathlib import Path

from launchpad.size import do_size_analysis


class TestSizeAnalysis:

    def test_apple(self) -> None:
        output_file = TextIOWrapper(BytesIO())
        with open(Path("tests/_fixtures/ios/HackerNews.xcarchive.zip"), "rb") as input_file:
            do_size_analysis(input_file, output_file)

        output_file.seek(0)
        size = json.load(output_file)
        assert size["app_info"]["name"] == "HackerNews"

    def test_android(self) -> None:
        output_file = TextIOWrapper(BytesIO())
        with open(Path("tests/_fixtures/android/hn.aab"), "rb") as input_file:
            do_size_analysis(input_file, output_file)

        output_file.seek(0)
        size = json.load(output_file)
        assert size["app_info"]["name"] == "Hacker News"
