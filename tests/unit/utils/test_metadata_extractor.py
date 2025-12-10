"""Tests for metadata extraction from .sentry-cli-metadata.txt files."""

import tempfile
import zipfile

from pathlib import Path

from launchpad.utils.metadata_extractor import (
    ToolingMetadata,
    _parse_metadata_content,
    extract_metadata_from_zip,
)


class TestParseMetadataContent:
    """Tests for parsing .sentry-cli-metadata.txt content."""

    def test_parse_all_fields(self):
        content = """sentry-cli-version: 2.58.2
fastlane-plugin: 1.2.3
gradle-plugin: 4.12.0"""
        metadata = _parse_metadata_content(content)
        assert metadata.cli_version == "2.58.2"
        assert metadata.fastlane_plugin_version == "1.2.3"
        assert metadata.gradle_plugin_version == "4.12.0"

    def test_parse_partial_fields(self):
        content = """sentry-cli-version: 2.58.2
fastlane-plugin: 1.2.3"""
        metadata = _parse_metadata_content(content)
        assert metadata.cli_version == "2.58.2"
        assert metadata.fastlane_plugin_version == "1.2.3"
        assert metadata.gradle_plugin_version is None

    def test_parse_only_cli_version(self):
        content = "sentry-cli-version: 2.58.2"
        metadata = _parse_metadata_content(content)
        assert metadata.cli_version == "2.58.2"
        assert metadata.fastlane_plugin_version is None
        assert metadata.gradle_plugin_version is None

    def test_parse_empty_content(self):
        content = ""
        metadata = _parse_metadata_content(content)
        assert metadata.cli_version is None
        assert metadata.fastlane_plugin_version is None
        assert metadata.gradle_plugin_version is None

    def test_parse_with_extra_whitespace(self):
        content = """  sentry-cli-version:  2.58.2
  fastlane-plugin:  1.2.3
  gradle-plugin:  4.12.0  """
        metadata = _parse_metadata_content(content)
        assert metadata.cli_version == "2.58.2"
        assert metadata.fastlane_plugin_version == "1.2.3"
        assert metadata.gradle_plugin_version == "4.12.0"

    def test_parse_with_extra_lines(self):
        content = """
sentry-cli-version: 2.58.2

fastlane-plugin: 1.2.3

gradle-plugin: 4.12.0
"""
        metadata = _parse_metadata_content(content)
        assert metadata.cli_version == "2.58.2"
        assert metadata.fastlane_plugin_version == "1.2.3"
        assert metadata.gradle_plugin_version == "4.12.0"

    def test_parse_with_unknown_fields(self):
        content = """sentry-cli-version: 2.58.2
unknown-field: some-value
fastlane-plugin: 1.2.3"""
        metadata = _parse_metadata_content(content)
        assert metadata.cli_version == "2.58.2"
        assert metadata.fastlane_plugin_version == "1.2.3"
        assert metadata.gradle_plugin_version is None


class TestExtractMetadataFromZip:
    """Tests for extracting metadata from zip files."""

    def test_extract_from_zip_root(self):
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
            try:
                with zipfile.ZipFile(tf.name, "w") as zf:
                    zf.writestr(
                        ".sentry-cli-metadata.txt",
                        "sentry-cli-version: 2.58.2\nfastlane-plugin: 1.2.3\ngradle-plugin: 4.12.0",
                    )
                    zf.writestr("some-file.txt", "content")

                metadata = extract_metadata_from_zip(Path(tf.name))
                assert metadata.cli_version == "2.58.2"
                assert metadata.fastlane_plugin_version == "1.2.3"
                assert metadata.gradle_plugin_version == "4.12.0"
            finally:
                Path(tf.name).unlink()

    def test_extract_from_nested_path(self):
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
            try:
                with zipfile.ZipFile(tf.name, "w") as zf:
                    zf.writestr(
                        "some/nested/path/.sentry-cli-metadata.txt",
                        "sentry-cli-version: 3.0.0",
                    )
                    zf.writestr("other-file.txt", "content")

                metadata = extract_metadata_from_zip(Path(tf.name))
                assert metadata.cli_version == "3.0.0"
                assert metadata.fastlane_plugin_version is None
                assert metadata.gradle_plugin_version is None
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

    def test_extract_multiple_metadata_files(self):
        # Should use the first one found
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
            try:
                with zipfile.ZipFile(tf.name, "w") as zf:
                    zf.writestr(
                        "first/.sentry-cli-metadata.txt",
                        "sentry-cli-version: 1.0.0",
                    )
                    zf.writestr(
                        "second/.sentry-cli-metadata.txt",
                        "sentry-cli-version: 2.0.0",
                    )

                metadata = extract_metadata_from_zip(Path(tf.name))
                # Should get one of them (order not guaranteed in zip namelist)
                assert metadata.cli_version in ["1.0.0", "2.0.0"]
            finally:
                Path(tf.name).unlink()

    def test_extract_from_invalid_zip(self):
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
            try:
                tf.write(b"not a valid zip file")
                tf.flush()

                metadata = extract_metadata_from_zip(Path(tf.name))
                # Should return empty metadata on error
                assert metadata.cli_version is None
                assert metadata.fastlane_plugin_version is None
                assert metadata.gradle_plugin_version is None
            finally:
                Path(tf.name).unlink()


class TestToolingMetadata:
    """Tests for ToolingMetadata container class."""

    def test_create_with_all_fields(self):
        metadata = ToolingMetadata(
            cli_version="2.58.2",
            fastlane_plugin_version="1.2.3",
            gradle_plugin_version="4.12.0",
        )
        assert metadata.cli_version == "2.58.2"
        assert metadata.fastlane_plugin_version == "1.2.3"
        assert metadata.gradle_plugin_version == "4.12.0"

    def test_create_with_defaults(self):
        metadata = ToolingMetadata()
        assert metadata.cli_version is None
        assert metadata.fastlane_plugin_version is None
        assert metadata.gradle_plugin_version is None

    def test_repr(self):
        metadata = ToolingMetadata(cli_version="2.58.2")
        repr_str = repr(metadata)
        assert "ToolingMetadata" in repr_str
        assert "cli_version=2.58.2" in repr_str
        assert "fastlane_plugin_version" in repr_str
