import tempfile
import zipfile

from pathlib import Path

from launchpad.utils.metadata_extractor import (
    ToolingMetadata,
    _parse_metadata_content,
    extract_metadata_from_zip,
)


class TestParseMetadataContent:
    def test_parse_all_fields(self):
        content = """sentry-cli-version: 2.58.2
sentry-fastlane-plugin: 1.2.3
sentry-gradle-plugin: 4.12.0"""
        metadata = _parse_metadata_content(content)
        assert metadata.cli_version == "2.58.2"
        assert metadata.fastlane_plugin_version == "1.2.3"
        assert metadata.gradle_plugin_version == "4.12.0"

    def test_parse_empty_content(self):
        content = ""
        metadata = _parse_metadata_content(content)
        assert metadata.cli_version is None
        assert metadata.fastlane_plugin_version is None
        assert metadata.gradle_plugin_version is None


class TestExtractMetadataFromZip:
    def test_extract_from_zip_root(self):
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
            try:
                with zipfile.ZipFile(tf.name, "w") as zf:
                    zf.writestr(
                        ".sentry-cli-metadata.txt",
                        "sentry-cli-version: 2.58.2\nsentry-fastlane-plugin: 1.2.3\nsentry-gradle-plugin: 4.12.0",
                    )
                    zf.writestr("some-file.txt", "content")

                metadata = extract_metadata_from_zip(Path(tf.name))
                assert metadata.cli_version == "2.58.2"
                assert metadata.fastlane_plugin_version == "1.2.3"
                assert metadata.gradle_plugin_version == "4.12.0"
            finally:
                Path(tf.name).unlink()

    def test_extract_when_missing(self):
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
            try:
                with zipfile.ZipFile(tf.name, "w") as zf:
                    zf.writestr("some-file.txt", "content")
                    zf.writestr("other-file.txt", "content")

                metadata = extract_metadata_from_zip(Path(tf.name))
                assert metadata.cli_version is None
                assert metadata.fastlane_plugin_version is None
                assert metadata.gradle_plugin_version is None
            finally:
                Path(tf.name).unlink()


class TestToolingMetadata:
    def test_create_with_defaults(self):
        metadata = ToolingMetadata()
        assert metadata.cli_version is None
        assert metadata.fastlane_plugin_version is None
        assert metadata.gradle_plugin_version is None
