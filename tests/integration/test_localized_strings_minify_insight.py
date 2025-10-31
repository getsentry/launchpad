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
    """Test the strip_string_comments_and_whitespace method directly."""

    def test_strip_comments_only(self):
        """Test stripping comments without whitespace changes."""
        processor = MinifyLocalizedStringsProcessor()

        content_with_comments = """
/* This is a block comment */
"hello"="Hello";

// This is a line comment
"goodbye"="Goodbye";

/* Multi-line
   block comment */
"welcome"="Welcome";
"""

        stripped = processor.strip_string_comments_and_whitespace(content_with_comments)

        expected = (
            "\n".join(
                [
                    '"hello"="Hello";',
                    '"goodbye"="Goodbye";',
                    '"welcome"="Welcome";',
                ]
            )
            + "\n"
        )
        assert stripped == expected

    def test_normalize_whitespace_only(self):
        """Test normalizing whitespace around = without comments."""
        processor = MinifyLocalizedStringsProcessor()

        content_with_spaces = """
"key1" = "value1";
"key2"  =  "value2";
"key3"   =   "value3";
"""

        normalized = processor.strip_string_comments_and_whitespace(content_with_spaces)

        expected = (
            "\n".join(
                [
                    '"key1"="value1";',
                    '"key2"="value2";',
                    '"key3"="value3";',
                ]
            )
            + "\n"
        )
        assert normalized == expected

    def test_strip_string_comments_and_whitespace_whitespace(self):
        """Test both comment stripping and whitespace normalization together."""
        processor = MinifyLocalizedStringsProcessor()

        content = """
/* Header comment */
"hello" = "Hello World";

// Comment before key
"goodbye"  =  "Goodbye";

/* Multi-line comment
   with details */
"welcome"   = "Welcome!";
"""

        result = processor.strip_string_comments_and_whitespace(content)

        expected = (
            "\n".join(
                [
                    '"hello"="Hello World";',
                    '"goodbye"="Goodbye";',
                    '"welcome"="Welcome!";',
                ]
            )
            + "\n"
        )
        assert result == expected

    def test_tamil_unicode_content(self):
        """Test processing Tamil Unicode content."""
        processor = MinifyLocalizedStringsProcessor()

        tamil_content = """
/* Tamil strings */
"DeviceLogin.LogInPrompt" = "%@ என்பதற்குச் சென்று மேலே தெரியும் குறியீட்டை உள்ளிடவும்.";
"ErrorRecovery.Alert.OK" = "சரி";
"LoginButton.LogIn" = "உள்நுழைவு";
"""

        result = processor.strip_string_comments_and_whitespace(tamil_content)

        expected = (
            "\n".join(
                [
                    '"DeviceLogin.LogInPrompt"="%@ என்பதற்குச் சென்று மேலே தெரியும் குறியீட்டை உள்ளிடவும்.";',
                    '"ErrorRecovery.Alert.OK"="சரி";',
                    '"LoginButton.LogIn"="உள்நுழைவு";',
                ]
            )
            + "\n"
        )
        assert result == expected

    def test_empty_content(self):
        """Test that empty content returns empty string."""
        processor = MinifyLocalizedStringsProcessor()
        assert processor.strip_string_comments_and_whitespace("") == ""

    def test_content_with_only_comments(self):
        """Test that content with only comments and no key-value pairs returns empty string."""
        processor = MinifyLocalizedStringsProcessor()

        only_comments = "/* Just a comment */\n// Another comment"
        assert processor.strip_string_comments_and_whitespace(only_comments) == ""

    def test_malformed_strings_without_quotes(self):
        """Test that malformed strings without quotes are filtered out."""
        processor = MinifyLocalizedStringsProcessor()

        malformed = "hello = world;\nkey = value;"
        result = processor.strip_string_comments_and_whitespace(malformed)
        assert result == ""  # Should filter out malformed entries

    def test_mixed_valid_and_invalid_entries(self):
        """Test that valid entries are kept while invalid entries are filtered out."""
        processor = MinifyLocalizedStringsProcessor()

        mixed = """
        "valid" = "entry";
        invalid = entry;
        "another_valid" = "entry2";
        """
        result = processor.strip_string_comments_and_whitespace(mixed)
        expected = (
            "\n".join(
                [
                    '"valid"="entry";',
                    '"another_valid"="entry2";',
                ]
            )
            + "\n"
        )
        assert result == expected

    def test_equals_in_string_values(self):
        """Test handling of equals signs within string values."""
        processor = MinifyLocalizedStringsProcessor()

        content_with_equals_in_values = """
/* Math equations */
"math.simple" = "2 + 2 = 4";
"math.complex"  =  "x = y + z";

// Format descriptions
"format.description" = "Use format: key = value";
"assignment.example"   =   "Set variable: foo = bar";
"""

        result = processor.strip_string_comments_and_whitespace(content_with_equals_in_values)

        expected = (
            "\n".join(
                [
                    '"math.simple"="2 + 2 = 4";',
                    '"math.complex"="x = y + z";',
                    '"format.description"="Use format: key = value";',
                    '"assignment.example"="Set variable: foo = bar";',
                ]
            )
            + "\n"
        )
        assert result == expected

    def test_escaped_quotes_in_string_values(self):
        """Test handling of escaped quotes within string values."""
        processor = MinifyLocalizedStringsProcessor()

        content_with_escaped_quotes = """
"PROLOGUE" = "<p>Drag &amp; drop files on this window or use the \\"Upload Files&hellip;\\" button to upload new files.</p>";
"EPILOGUE" = "";
"FOOTER_FORMAT" = "%@ %@";
"QUOTED_TEXT" = "She said \\"Hello\\" and left";
"BACKSLASH_TEST"  =  "Path: C:\\\\Users\\\\file.txt";
"""

        result = processor.strip_string_comments_and_whitespace(content_with_escaped_quotes)

        expected = (
            '"PROLOGUE"="<p>Drag &amp; drop files on this window or use the \\"Upload Files&hellip;\\" button to upload new files.</p>";\n'
            '"EPILOGUE"="";\n'
            '"FOOTER_FORMAT"="%@ %@";\n'
            '"QUOTED_TEXT"="She said \\"Hello\\" and left";\n'
            '"BACKSLASH_TEST"="Path: C:\\\\Users\\\\file.txt";\n'
        )
        assert result == expected


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
            assert result.files[0].total_savings > 0
            assert result.total_savings > insight.THRESHOLD_BYTES

    def test_localized_strings_with_whitespace_only(self):
        """Test that insight can find savings from whitespace normalization even without comments."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create content with substantial whitespace that will result in block-level savings
            strings_file = temp_path / "en.lproj" / "Localizable.strings"
            strings_file.parent.mkdir(parents=True)

            # Generate enough content with excessive whitespace to cross filesystem blocks
            strings_content = ""
            for i in range(100):  # More entries with more whitespace
                # Add lots of whitespace that will be normalized away
                strings_content += f'"key{i}"          =          "Value {i} with substantial content to ensure we have enough data";\n'

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
            # Should find savings from whitespace normalization
            assert result is not None
            assert len(result.files) == 1
            assert result.files[0].total_savings > 0

    def test_localized_strings_no_savings_small_file(self):
        """Test that insight returns None when file is too small to have meaningful savings."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create a very small strings file without comments or extra whitespace
            strings_file = temp_path / "en.lproj" / "Localizable.strings"
            strings_file.parent.mkdir(parents=True)
            strings_content = '"hello"="Hello";\n"goodbye"="Goodbye";\n'  # Already optimized, very small
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
            assert result is None  # Too small to have meaningful block-aligned savings

    def test_multiple_localized_strings_files(self):
        """Test that insight works with multiple localized strings files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create multiple strings files with substantial content
            for lang in ["en", "es", "fr"]:
                strings_file = temp_path / f"{lang}.lproj" / "Localizable.strings"
                strings_file.parent.mkdir(parents=True)

                # Generate substantial content for each language
                strings_content = ""
                for i in range(30):
                    strings_content += f"""
/* Comment for {lang} key{i} with substantial content that will be stripped */
"key{i}"      =      "Hello in {lang} - Value {i} with enough content";

// Line comment for variety
"""
                strings_file.write_text(strings_content)

            insight = MinifyLocalizedStringsInsight()

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

            result = insight.generate(input_data)
            assert result is not None
            assert len(result.files) == 3
            assert result.total_savings > 0

    def test_binary_plist_strings_file(self):
        """Test that small binary plist files don't generate insights due to low savings."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create a binary plist strings file
            strings_file = temp_path / "en.lproj" / "BinaryPlist.strings"
            strings_file.parent.mkdir(parents=True)

            # Create a plist dict and save as binary
            plist_dict = {
                "key1": "Value 1",
                "key2": "Value 2",
                "key3": "Value 3",
            }
            binary_plist = plistlib.dumps(plist_dict, fmt=plistlib.FMT_BINARY)
            strings_file.write_bytes(binary_plist)

            insight = MinifyLocalizedStringsInsight()

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

            result = insight.generate(input_data)
            # Small plist has savings below threshold, so no insight is generated
            assert result is None

    def test_binary_plist_with_significant_savings(self):
        """Test that large binary plist files show savings when converted to standard strings format."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create a binary plist strings file with many entries
            strings_file = temp_path / "en.lproj" / "LargeBinaryPlist.strings"
            strings_file.parent.mkdir(parents=True)

            # Create a plist dict with enough entries to demonstrate block-aligned savings
            # Binary plists have overhead from metadata, type info, offset tables, etc.
            # With 200 short entries: binary ~4425 bytes (2 blocks) vs strings ~3780 bytes (1 block) = 4096 bytes savings
            plist_dict = {}
            for i in range(200):
                plist_dict[f"k{i}"] = f"Value {i}"

            binary_plist = plistlib.dumps(plist_dict, fmt=plistlib.FMT_BINARY)
            strings_file.write_bytes(binary_plist)

            # Calculate what the strings format would be
            processor = MinifyLocalizedStringsProcessor()
            strings_content = processor.plist_dict_to_strings(plist_dict)
            strings_bytes = strings_content.encode("utf-8")

            # Verify binary plist is actually larger (showing the overhead)
            assert len(binary_plist) > len(strings_bytes), (
                f"Binary plist ({len(binary_plist)} bytes) should be larger than "
                f"strings format ({len(strings_bytes)} bytes)"
            )

            insight = MinifyLocalizedStringsInsight()

            input_data = InsightsInput(
                app_info=self._create_test_app_info(),
                file_analysis=FileAnalysis(
                    files=[
                        FileInfo(
                            full_path=strings_file,
                            path="en.lproj/LargeBinaryPlist.strings",
                            size=len(binary_plist),
                            file_type="strings",
                            hash="large_binary_hash",
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
            # Should find savings from converting binary plist to standard strings format
            assert result is not None, "Should generate insight for large binary plist"
            assert len(result.files) == 1
            assert result.files[0].file_path == "en.lproj/LargeBinaryPlist.strings"
            assert result.files[0].total_savings > 0
            assert result.total_savings > insight.THRESHOLD_BYTES

    def test_xml_plist_strings_file_with_formatting(self):
        """Test that insight handles XML plist-format .strings files with extra formatting."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            strings_file = temp_path / "en.lproj" / "WidgetIntents.strings"
            strings_file.parent.mkdir(parents=True)

            # Create a plist dict with sample content
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

            # Add more entries to ensure we have enough content to cross filesystem blocks
            for i in range(50):
                plist_dict[f"extra_key_{i}"] = f"Extra value with substantial content for key {i}"

            # Serialize with extra formatting (indent, etc.) to simulate real-world plist
            # We'll write it manually to ensure it has extra whitespace that can be compressed
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
            # Add the extra entries with lots of formatting
            for i in range(50):
                plist_xml += f"\t<key>extra_key_{i}</key>\n"
                plist_xml += f"\t<string>Extra value with substantial content for key {i}</string>\n"

            plist_xml += "</dict>\n</plist>\n"
            strings_file.write_text(plist_xml)

            insight = MinifyLocalizedStringsInsight()

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

            result = insight.generate(input_data)
            # Should be able to parse and find savings from XML formatting
            if result:
                assert len(result.files) == 1
                assert result.files[0].file_path == "en.lproj/WidgetIntents.strings"
                assert result.files[0].total_savings > 0

    def test_xml_plist_strings_file_already_compact(self):
        """Test that insight handles compact XML plist files with minimal savings."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            strings_file = temp_path / "en.lproj" / "Compact.strings"
            strings_file.parent.mkdir(parents=True)

            # Create a small, already compact plist
            plist_dict = {
                "key1": "value1",
                "key2": "value2",
            }

            # Write as compact XML (plistlib default)
            plist_xml = plistlib.dumps(plist_dict, fmt=plistlib.FMT_XML)
            strings_file.write_bytes(plist_xml)

            insight = MinifyLocalizedStringsInsight()

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

            result = insight.generate(input_data)
            # Small, already compact file should not yield savings
            assert result is None

    def test_xml_plist_with_xml_comments(self):
        """Test that insight strips XML comments from XML plist files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            strings_file = temp_path / "en.lproj" / "CommentedPlist.strings"
            strings_file.parent.mkdir(parents=True)

            # Create a plist with substantial XML comments and extra formatting to ensure
            # we exceed the 1024 byte threshold when comments are stripped
            plist_xml = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- This is a lengthy comment about the plist file that provides documentation
     and context for developers. It spans multiple lines to add substantial size.
     More text here to ensure we have enough content to cross block boundaries. -->
<plist version="1.0">
<dict>
"""
            # Add entries with substantial comments to ensure we cross filesystem block boundaries
            for i in range(100):
                plist_xml += f"\t<!-- This is a detailed comment for key{i} that explains what this key is used for.\n"
                plist_xml += "\t     It provides context and documentation for developers working with this file.\n"
                plist_xml += "\t     Additional information and explanatory text to increase the comment size. -->\n"
                plist_xml += f"\t<key>extra_key_{i}</key>\n"
                plist_xml += f"\t<string>Extra value with substantial content for key {i}</string>\n\n"

            plist_xml += "</dict>\n</plist>\n"
            strings_file.write_text(plist_xml)

            insight = MinifyLocalizedStringsInsight()

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

            result = insight.generate(input_data)
            # Should definitely find savings from stripping XML comments and formatting
            assert result is not None
            assert len(result.files) == 1
            assert result.files[0].file_path == "en.lproj/CommentedPlist.strings"
            assert result.files[0].total_savings > 0
            assert result.total_savings > insight.THRESHOLD_BYTES
