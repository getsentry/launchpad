import plistlib
import tempfile

from pathlib import Path

from launchpad.size.insights.apple.localized_strings_minify import (
    MinifyLocalizedStringsInsight,
    MinifyLocalizedStringsProcessor,
)
from launchpad.size.insights.insight import InsightsInput
from launchpad.size.models.apple import AppleAppInfo
from launchpad.size.models.common import FileAnalysis, FileInfo
from launchpad.size.models.treemap import TreemapType


class TestMinifyLocalizedStringsProcessor:
    """Test the parse_strings_file method for parsing .strings files."""

    def test_parse_simple_strings(self):
        """Test parsing simple key-value pairs."""
        processor = MinifyLocalizedStringsProcessor()

        content = """
"hello" = "Hello";
"goodbye" = "Goodbye";
"welcome" = "Welcome";
"""

        result = processor.parse_strings_file(content)
        assert result is not None
        assert result == {
            "hello": "Hello",
            "goodbye": "Goodbye",
            "welcome": "Welcome",
        }

    def test_parse_with_comments(self):
        """Test that comments are stripped during parsing."""
        processor = MinifyLocalizedStringsProcessor()

        content_with_comments = """
/* This is a block comment */
"hello" = "Hello";

// This is a line comment
"goodbye" = "Goodbye";

/* Multi-line
   block comment */
"welcome" = "Welcome";
"""

        result = processor.parse_strings_file(content_with_comments)
        assert result is not None
        assert result == {
            "hello": "Hello",
            "goodbye": "Goodbye",
            "welcome": "Welcome",
        }

    def test_parse_with_varied_whitespace(self):
        """Test parsing with different whitespace patterns."""
        processor = MinifyLocalizedStringsProcessor()

        content_with_spaces = """
"key1" = "value1";
"key2"  =  "value2";
"key3"   =   "value3";
"""

        result = processor.parse_strings_file(content_with_spaces)
        assert result is not None
        assert result == {
            "key1": "value1",
            "key2": "value2",
            "key3": "value3",
        }

    def test_parse_tamil_unicode_content(self):
        """Test parsing Tamil Unicode content."""
        processor = MinifyLocalizedStringsProcessor()

        tamil_content = """
/* Tamil strings */
"DeviceLogin.LogInPrompt" = "%@ என்பதற்குச் சென்று மேலே தெரியும் குறியீட்டை உள்ளிடவும்.";
"ErrorRecovery.Alert.OK" = "சரி";
"LoginButton.LogIn" = "உள்நுழைவு";
"""

        result = processor.parse_strings_file(tamil_content)
        assert result is not None
        assert result == {
            "DeviceLogin.LogInPrompt": "%@ என்பதற்குச் சென்று மேலே தெரியும் குறியீட்டை உள்ளிடவும்.",
            "ErrorRecovery.Alert.OK": "சரி",
            "LoginButton.LogIn": "உள்நுழைவு",
        }

    def test_parse_empty_content(self):
        """Test that empty content returns None."""
        processor = MinifyLocalizedStringsProcessor()
        assert processor.parse_strings_file("") is None

    def test_parse_only_comments(self):
        """Test that content with only comments returns None."""
        processor = MinifyLocalizedStringsProcessor()

        only_comments = "/* Just a comment */\n// Another comment"
        assert processor.parse_strings_file(only_comments) is None

    def test_parse_malformed_strings_without_quotes(self):
        """Test that malformed strings without quotes are ignored."""
        processor = MinifyLocalizedStringsProcessor()

        malformed = "hello = world;\nkey = value;"
        result = processor.parse_strings_file(malformed)
        assert result is None  # Should return None for invalid content

    def test_parse_mixed_valid_and_invalid_entries(self):
        """Test that valid entries are parsed while invalid entries are ignored."""
        processor = MinifyLocalizedStringsProcessor()

        mixed = """
        "valid" = "entry";
        invalid = entry;
        "another_valid" = "entry2";
        """
        result = processor.parse_strings_file(mixed)
        assert result is not None
        assert result == {
            "valid": "entry",
            "another_valid": "entry2",
        }

    def test_parse_equals_in_string_values(self):
        """Test parsing strings with equals signs in values."""
        processor = MinifyLocalizedStringsProcessor()

        content_with_equals_in_values = """
/* Math equations */
"math.simple" = "2 + 2 = 4";
"math.complex" = "x = y + z";

// Format descriptions
"format.description" = "Use format: key = value";
"assignment.example" = "Set variable: foo = bar";
"""

        result = processor.parse_strings_file(content_with_equals_in_values)
        assert result is not None
        assert result == {
            "math.simple": "2 + 2 = 4",
            "math.complex": "x = y + z",
            "format.description": "Use format: key = value",
            "assignment.example": "Set variable: foo = bar",
        }

    def test_parse_escaped_quotes_in_string_values(self):
        """Test parsing strings with escaped quotes."""
        processor = MinifyLocalizedStringsProcessor()

        content_with_escaped_quotes = """
"PROLOGUE" = "<p>Drag &amp; drop files on this window or use the \\"Upload Files&hellip;\\" button to upload new files.</p>";
"EPILOGUE" = "";
"FOOTER_FORMAT" = "%@ %@";
"QUOTED_TEXT" = "She said \\"Hello\\" and left";
"BACKSLASH_TEST" = "Path: C:\\\\Users\\\\file.txt";
"""

        result = processor.parse_strings_file(content_with_escaped_quotes)
        assert result is not None
        assert (
            result["PROLOGUE"]
            == '<p>Drag &amp; drop files on this window or use the "Upload Files&hellip;" button to upload new files.</p>'
        )
        assert result["EPILOGUE"] == ""
        assert result["FOOTER_FORMAT"] == "%@ %@"
        assert result["QUOTED_TEXT"] == 'She said "Hello" and left'
        assert result["BACKSLASH_TEST"] == "Path: C:\\Users\\file.txt"


class TestMinifyLocalizedStringsInsight:
    """Test the MinifyLocalizedStringsInsight functionality."""

    def _create_test_app_info(self) -> AppleAppInfo:
        """Create a test AppleAppInfo with all required fields."""
        return AppleAppInfo(
            name="TestApp",
            version="1.0",
            build="1",
            app_id="com.test.app",
            executable="TestApp",
            minimum_os_version="15.0",
            sdk_version="15.0",
            is_simulator=False,
            codesigning_type="development",
            profile_name="TestProfile",
            is_code_signature_valid=True,
        )

    def test_no_localized_strings_files(self):
        """Test that insight returns None when no localized strings files are found."""
        insight = MinifyLocalizedStringsInsight()

        input_data = InsightsInput(
            app_info=self._create_test_app_info(),
            file_analysis=FileAnalysis(
                files=[
                    FileInfo(
                        full_path=Path("/test/regular_file.txt"),
                        path="regular_file.txt",
                        size=1000,
                        file_type="txt",
                        hash="abcd1234",
                        treemap_type=TreemapType.FILES,
                        is_dir=False,
                        children=[],
                    )
                ],
                directories=[],
            ),
            binary_analysis=[],
            treemap=None,
            hermes_reports={},
        )

        result = insight.generate(input_data)
        assert result is None

    def test_localized_strings_with_comments_above_threshold(self):
        """Test that insight returns results when strings files have comments above threshold."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create a strings file with lots of comments to ensure meaningful block savings
            strings_file = temp_path / "en.lproj" / "Localizable.strings"
            strings_file.parent.mkdir(parents=True)

            # Generate content that will cross filesystem block boundaries
            strings_content = ""
            # Add substantial comments and whitespace to ensure block-level savings
            for i in range(50):
                strings_content += f"""
/* This is a very long comment for key{i} that takes up quite a bit of space
   and continues on multiple lines to ensure we have substantial content
   that will result in meaningful filesystem block savings when removed */
"key{i}"    =    "Value {i} with some content";

// Another comment for variety
/* More comment content to pad the file size significantly */
"""

            strings_file.write_text(strings_content)

            insight = MinifyLocalizedStringsInsight()

            input_data = InsightsInput(
                app_info=self._create_test_app_info(),
                file_analysis=FileAnalysis(
                    files=[
                        FileInfo(
                            full_path=strings_file,
                            path="en.lproj/Localizable.strings",
                            size=len(strings_content.encode("utf-8")),
                            file_type="strings",
                            hash="abcd1234",
                            treemap_type=TreemapType.FILES,
                            is_dir=False,
                            children=[],
                        )
                    ],
                    directories=[],
                ),
                binary_analysis=[],
                treemap=None,
                hermes_reports={},
            )

            result = insight.generate(input_data)
            assert result is not None
            assert len(result.files) == 1
            assert result.files[0].file_path == "en.lproj/Localizable.strings"
            assert result.files[0].total_savings == 16384

    def test_localized_strings_with_whitespace_only(self):
        """Test that insight can find savings from whitespace normalization even without comments."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            strings_file = temp_path / "en.lproj" / "Localizable.strings"
            strings_file.parent.mkdir(parents=True)

            strings_content = ""
            for i in range(100):
                strings_content += f'"key{i}"          =          "Value {i} with substantial content to ensure we have enough data";\n'

            strings_file.write_text(strings_content)

            input_data = InsightsInput(
                app_info=self._create_test_app_info(),
                file_analysis=FileAnalysis(
                    files=[
                        FileInfo(
                            full_path=strings_file,
                            path="en.lproj/Localizable.strings",
                            size=len(strings_content.encode("utf-8")),
                            file_type="strings",
                            hash="abcd1234",
                            treemap_type=TreemapType.FILES,
                            is_dir=False,
                            children=[],
                        )
                    ],
                    directories=[],
                ),
                binary_analysis=[],
                treemap=None,
                hermes_reports={},
            )

            result = MinifyLocalizedStringsInsight().generate(input_data)
            assert result is not None
            assert len(result.files) == 1
            assert result.files[0].total_savings == 4096

    def test_localized_strings_no_savings_small_file(self):
        """Test that insight returns None when file is too small to have meaningful savings."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            strings_file = temp_path / "en.lproj" / "Localizable.strings"
            strings_file.parent.mkdir(parents=True)
            strings_content = '"hello"="Hello";\n"goodbye"="Goodbye";\n'  # Already optimized, very small
            strings_file.write_text(strings_content)

            input_data = InsightsInput(
                app_info=self._create_test_app_info(),
                file_analysis=FileAnalysis(
                    files=[
                        FileInfo(
                            full_path=strings_file,
                            path="en.lproj/Localizable.strings",
                            size=len(strings_content.encode("utf-8")),
                            file_type="strings",
                            hash="abcd1234",
                            treemap_type=TreemapType.FILES,
                            is_dir=False,
                            children=[],
                        )
                    ],
                    directories=[],
                ),
                binary_analysis=[],
                treemap=None,
                hermes_reports={},
            )

            result = MinifyLocalizedStringsInsight().generate(input_data)
            assert result is None  # Too small to have meaningful block-aligned savings

    def test_multiple_localized_strings_files(self):
        """Test that insight works with multiple localized strings files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            for lang in ["en", "es", "fr"]:
                strings_file = temp_path / f"{lang}.lproj" / "Localizable.strings"
                strings_file.parent.mkdir(parents=True)

                strings_content = ""
                for i in range(30):
                    strings_content += f"""
/* Comment for {lang} key{i} with substantial content that will be stripped */
"key{i}"      =      "Hello in {lang} - Value {i} with enough content";

// Line comment for variety
"""
                strings_file.write_text(strings_content)

            files: list[FileInfo] = []
            for lang in ["en", "es", "fr"]:
                strings_file = temp_path / f"{lang}.lproj" / "Localizable.strings"
                content_size = len(strings_file.read_text().encode("utf-8"))
                files.append(
                    FileInfo(
                        full_path=strings_file,
                        path=f"{lang}.lproj/Localizable.strings",
                        size=content_size,
                        file_type="strings",
                        hash=f"hash_{lang}",
                        treemap_type=TreemapType.FILES,
                        is_dir=False,
                        children=[],
                    )
                )

            input_data = InsightsInput(
                app_info=self._create_test_app_info(),
                file_analysis=FileAnalysis(
                    files=files,
                    directories=[],
                ),
                binary_analysis=[],
                treemap=None,
                hermes_reports={},
            )

            result = MinifyLocalizedStringsInsight().generate(input_data)
            assert result is not None
            assert len(result.files) == 3
            assert result.files[0].total_savings == 4096
            assert result.files[1].total_savings == 4096
            assert result.files[2].total_savings == 4096

    def test_binary_plist_strings_file(self):
        """Test that small binary plist files don't generate insights due to low savings."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            strings_file = temp_path / "en.lproj" / "BinaryPlist.strings"
            strings_file.parent.mkdir(parents=True)

            plist_dict = {
                "key1": "Value 1",
                "key2": "Value 2",
                "key3": "Value 3",
            }
            binary_plist = plistlib.dumps(plist_dict, fmt=plistlib.FMT_BINARY)
            strings_file.write_bytes(binary_plist)

            input_data = InsightsInput(
                app_info=self._create_test_app_info(),
                file_analysis=FileAnalysis(
                    files=[
                        FileInfo(
                            full_path=strings_file,
                            path="en.lproj/BinaryPlist.strings",
                            size=len(binary_plist),
                            file_type="strings",
                            hash="binary_hash",
                            treemap_type=TreemapType.FILES,
                            is_dir=False,
                            children=[],
                        )
                    ],
                    directories=[],
                ),
                binary_analysis=[],
                treemap=None,
                hermes_reports={},
            )

            result = MinifyLocalizedStringsInsight().generate(input_data)
            assert result is None

    def test_binary_plist_already_optimal(self):
        """Test that binary plist files are already optimal and produce no savings."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            strings_file = temp_path / "en.lproj" / "BinaryPlist.strings"
            strings_file.parent.mkdir(parents=True)

            plist_dict = {}
            for i in range(100):
                plist_dict[f"localization_key_{i}"] = f"Localized string value for item number {i}"

            binary_plist = plistlib.dumps(plist_dict, fmt=plistlib.FMT_BINARY)
            strings_file.write_bytes(binary_plist)

            input_data = InsightsInput(
                app_info=self._create_test_app_info(),
                file_analysis=FileAnalysis(
                    files=[
                        FileInfo(
                            full_path=strings_file,
                            path="en.lproj/BinaryPlist.strings",
                            size=len(binary_plist),
                            file_type="strings",
                            hash="binary_hash",
                            treemap_type=TreemapType.FILES,
                            is_dir=False,
                            children=[],
                        )
                    ],
                    directories=[],
                ),
                binary_analysis=[],
                treemap=None,
                hermes_reports={},
            )

            result = MinifyLocalizedStringsInsight().generate(input_data)
            assert result is None, "Should not generate insight for binary plist (already optimal)"

    def test_xml_plist_strings_file_with_formatting(self):
        """Test that insight handles XML plist-format .strings files with extra formatting."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            strings_file = temp_path / "en.lproj" / "WidgetIntents.strings"
            strings_file.parent.mkdir(parents=True)

            plist_dict = {
                "2GqvPe": "Go to Copied Link",
                "PzSrmZ-2GqvPe": "Just to confirm, you wanted 'Go to Copied Link'?",
                "PzSrmZ-eHmH1H": "Just to confirm, you wanted 'Clear Private Tabs'?",
                "PzSrmZ-scEmjs": "Just to confirm, you wanted 'New Private Search'?",
                "ctDNmu": "Quick access to various Firefox actions",
                "eHmH1H": "Clear Private Tabs",
                "eV8mOT": "Quick Action Type",
                "fi3W24-2GqvPe": "There are ${count} options matching 'Go to Copied Link'.",
            }

            for i in range(50):
                plist_dict[f"extra_key_{i}"] = f"Extra value with substantial content for key {i}"

            plist_xml = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>2GqvPe</key>
\t<string>Go to Copied Link</string>
\t<key>PzSrmZ-2GqvPe</key>
\t<string>Just to confirm, you wanted 'Go to Copied Link'?</string>
\t<key>PzSrmZ-eHmH1H</key>
\t<string>Just to confirm, you wanted 'Clear Private Tabs'?</string>
\t<key>PzSrmZ-scEmjs</key>
\t<string>Just to confirm, you wanted 'New Private Search'?</string>
\t<key>ctDNmu</key>
\t<string>Quick access to various Firefox actions</string>
\t<key>eHmH1H</key>
\t<string>Clear Private Tabs</string>
\t<key>eV8mOT</key>
\t<string>Quick Action Type</string>
\t<key>fi3W24-2GqvPe</key>
\t<string>There are ${count} options matching 'Go to Copied Link'.</string>
"""
            for i in range(50):
                plist_xml += f"\t<key>extra_key_{i}</key>\n"
                plist_xml += f"\t<string>Extra value with substantial content for key {i}</string>\n"

            plist_xml += "</dict>\n</plist>\n"
            strings_file.write_text(plist_xml)

            input_data = InsightsInput(
                app_info=self._create_test_app_info(),
                file_analysis=FileAnalysis(
                    files=[
                        FileInfo(
                            full_path=strings_file,
                            path="en.lproj/WidgetIntents.strings",
                            size=len(plist_xml.encode("utf-8")),
                            file_type="strings",
                            hash="plist_hash",
                            treemap_type=TreemapType.FILES,
                            is_dir=False,
                            children=[],
                        )
                    ],
                    directories=[],
                ),
                binary_analysis=[],
                treemap=None,
                hermes_reports={},
            )

            result = MinifyLocalizedStringsInsight().generate(input_data)
            assert len(result.files) == 1
            assert result.files[0].file_path == "en.lproj/WidgetIntents.strings"
            assert result.files[0].total_savings == 4096

    def test_xml_plist_strings_file_already_compact(self):
        """Test that insight handles compact XML plist files with minimal savings."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            strings_file = temp_path / "en.lproj" / "Compact.strings"
            strings_file.parent.mkdir(parents=True)

            plist_dict = {
                "key1": "value1",
                "key2": "value2",
            }

            plist_xml = plistlib.dumps(plist_dict, fmt=plistlib.FMT_XML)
            strings_file.write_bytes(plist_xml)

            input_data = InsightsInput(
                app_info=self._create_test_app_info(),
                file_analysis=FileAnalysis(
                    files=[
                        FileInfo(
                            full_path=strings_file,
                            path="en.lproj/Compact.strings",
                            size=len(plist_xml),
                            file_type="strings",
                            hash="compact_hash",
                            treemap_type=TreemapType.FILES,
                            is_dir=False,
                            children=[],
                        )
                    ],
                    directories=[],
                ),
                binary_analysis=[],
                treemap=None,
                hermes_reports={},
            )

            result = MinifyLocalizedStringsInsight().generate(input_data)
            assert result is None

    def test_xml_plist_with_xml_comments(self):
        """Test that insight strips XML comments from XML plist files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            strings_file = temp_path / "en.lproj" / "CommentedPlist.strings"
            strings_file.parent.mkdir(parents=True)

            plist_xml = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- This is a lengthy comment about the plist file that provides documentation
     and context for developers. It spans multiple lines to add substantial size.
     More text here to ensure we have enough content to cross block boundaries. -->
<plist version="1.0">
<dict>
"""
            for i in range(100):
                plist_xml += f"\t<!-- This is a detailed comment for key{i} that explains what this key is used for.\n"
                plist_xml += "\t     It provides context and documentation for developers working with this file.\n"
                plist_xml += "\t     Additional information and explanatory text to increase the comment size. -->\n"
                plist_xml += f"\t<key>extra_key_{i}</key>\n"
                plist_xml += f"\t<string>Extra value with substantial content for key {i}</string>\n\n"

            plist_xml += "</dict>\n</plist>\n"
            strings_file.write_text(plist_xml)

            input_data = InsightsInput(
                app_info=self._create_test_app_info(),
                file_analysis=FileAnalysis(
                    files=[
                        FileInfo(
                            full_path=strings_file,
                            path="en.lproj/CommentedPlist.strings",
                            size=len(plist_xml.encode("utf-8")),
                            file_type="strings",
                            hash="commented_hash",
                            treemap_type=TreemapType.FILES,
                            is_dir=False,
                            children=[],
                        )
                    ],
                    directories=[],
                ),
                binary_analysis=[],
                treemap=None,
                hermes_reports={},
            )

            result = MinifyLocalizedStringsInsight().generate(input_data)
            assert result is not None
            assert len(result.files) == 1
            assert result.files[0].file_path == "en.lproj/CommentedPlist.strings"
            assert result.files[0].total_savings == 28672

    def test_invalid_xml_plist(self):
        """Test that insight gracefully handles malformed XML plist files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            strings_file = temp_path / "en.lproj" / "Invalid.strings"
            strings_file.parent.mkdir(parents=True)

            # Malformed XML plist - starts with XML header but has invalid structure
            invalid_plist_xml = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>unclosed_key
    <string>value without closing tag
    <dict>
        <key>nested</key>
    </broken>
</plist>"""
            strings_file.write_text(invalid_plist_xml)

            input_data = InsightsInput(
                app_info=self._create_test_app_info(),
                file_analysis=FileAnalysis(
                    files=[
                        FileInfo(
                            full_path=strings_file,
                            path="en.lproj/Invalid.strings",
                            size=len(invalid_plist_xml.encode("utf-8")),
                            file_type="strings",
                            hash="invalid_hash",
                            treemap_type=TreemapType.FILES,
                            is_dir=False,
                            children=[],
                        )
                    ],
                    directories=[],
                ),
                binary_analysis=[],
                treemap=None,
                hermes_reports={},
            )

            result = MinifyLocalizedStringsInsight().generate(input_data)
            assert result is None, "Should return None for malformed XML plist (no savings possible)"
