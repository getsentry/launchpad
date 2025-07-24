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


class TestLocalizedStringsProcessor:
    """Test the LocalizedStringsProcessor class directly."""

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

        stripped = processor.strip_comments_and_normalize(content_with_comments)

        # Should only contain the key-value pairs
        assert '"hello"="Hello"' in stripped
        assert '"goodbye"="Goodbye"' in stripped
        assert '"welcome"="Welcome"' in stripped

        # Should not contain comments
        assert "/* This is a block comment */" not in stripped
        assert "// This is a line comment" not in stripped
        assert "/* Multi-line" not in stripped

    def test_normalize_whitespace_only(self):
        """Test normalizing whitespace around = without comments."""
        processor = MinifyLocalizedStringsProcessor()

        content_with_spaces = """
"key1" = "value1";
"key2"  =  "value2";
"key3"   =   "value3";
"""

        normalized = processor.strip_comments_and_normalize(content_with_spaces)

        # Should normalize all spacing around =
        assert '"key1"="value1"' in normalized
        assert '"key2"="value2"' in normalized
        assert '"key3"="value3"' in normalized

        # Should not contain spaces around =
        assert '" = "' not in normalized
        assert '"  =  "' not in normalized

    def test_strip_comments_and_normalize_whitespace(self):
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

        result = processor.strip_comments_and_normalize(content)

        # Should strip comments AND normalize whitespace
        assert '"hello"="Hello World"' in result
        assert '"goodbye"="Goodbye"' in result
        assert '"welcome"="Welcome!"' in result

        # Should not contain comments or extra spaces
        assert "/* Header comment */" not in result
        assert "// Comment before key" not in result
        assert '" = "' not in result

    def test_tamil_unicode_content(self):
        """Test processing Tamil Unicode content."""
        processor = MinifyLocalizedStringsProcessor()

        tamil_content = """
/* Tamil strings */
"DeviceLogin.LogInPrompt" = "%@ என்பதற்குச் சென்று மேலே தெரியும் குறியீட்டை உள்ளிடவும்.";
"ErrorRecovery.Alert.OK" = "சரி";
"LoginButton.LogIn" = "உள்நுழைவு";
"""

        result = processor.strip_comments_and_normalize(tamil_content)

        # Should preserve Tamil characters exactly
        assert "என்பதற்குச் சென்று" in result
        assert "சரி" in result
        assert "உள்நுழைவு" in result

        # Should normalize whitespace
        assert '"DeviceLogin.LogInPrompt"=' in result
        assert '"ErrorRecovery.Alert.OK"=' in result

        # Should remove comments
        assert "/* Tamil strings */" not in result

    def test_edge_cases(self):
        """Test edge cases and malformed input."""
        processor = MinifyLocalizedStringsProcessor()

        # Empty content
        assert processor.strip_comments_and_normalize("") == ""

        # Only comments
        only_comments = "/* Just a comment */\n// Another comment"
        assert processor.strip_comments_and_normalize(only_comments) == ""

        # Malformed strings (no quotes) - should be filtered out
        malformed = "hello = world;\nkey = value;"
        result = processor.strip_comments_and_normalize(malformed)
        assert result == ""  # Should filter out malformed entries

        # Mixed valid and invalid
        mixed = """
        "valid" = "entry";
        invalid = entry;
        "another_valid" = "entry2";
        """
        result = processor.strip_comments_and_normalize(mixed)
        assert '"valid"="entry"' in result
        assert '"another_valid"="entry2"' in result
        assert "invalid = entry" not in result

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

        result = processor.strip_comments_and_normalize(content_with_equals_in_values)

        # Should preserve equals signs in the values while normalizing whitespace around assignment
        assert '"math.simple"="2 + 2 = 4"' in result
        assert '"math.complex"="x = y + z"' in result
        assert '"format.description"="Use format: key = value"' in result
        assert '"assignment.example"="Set variable: foo = bar"' in result

        # Should remove comments
        assert "/* Math equations */" not in result
        assert "// Format descriptions" not in result

        # Should not have extra spaces around the main assignment =
        assert '" = "2 + 2 = 4"' not in result  # No spaces around main assignment
        assert '"math.simple" = ' not in result  # No spaces around main assignment


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
