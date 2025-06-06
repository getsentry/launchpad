"""Unit tests for data models."""


import pytest

from app_size_analyzer.models.results import (
    AnalysisResults,
    AppInfo,
    BinaryAnalysis,
    DuplicateFileGroup,
    FileAnalysis,
    FileInfo,
)


class TestFileInfo:
    """Test cases for FileInfo model."""

    def test_valid_file_info(self) -> None:
        """Test creating valid FileInfo instance."""
        file_info = FileInfo(path="test/file.txt", size=1024, file_type="txt", hash_md5="abcd1234")

        assert file_info.path == "test/file.txt"
        assert file_info.size == 1024
        assert file_info.file_type == "txt"
        assert file_info.hash_md5 == "abcd1234"

    def test_negative_size_validation(self) -> None:
        """Test that negative file size is rejected."""
        with pytest.raises(ValueError):
            FileInfo(path="test/file.txt", size=-1, file_type="txt")


class TestAppInfo:
    """Test cases for AppInfo model."""

    def test_valid_app_info(self) -> None:
        """Test creating valid AppInfo instance."""
        app_info = AppInfo(
            name="Test App",
            bundle_id="com.test.app",
            version="1.0.0",
            build="100",
            executable="TestApp",
            minimum_os_version="14.0",
            supported_platforms=["iPhoneOS"],
        )

        assert app_info.name == "Test App"
        assert app_info.bundle_id == "com.test.app"
        assert app_info.version == "1.0.0"


class TestDuplicateFileGroup:
    """Test cases for DuplicateFileGroup model."""

    def test_duplicate_count_property(self) -> None:
        """Test duplicate_count property calculation."""
        file1 = FileInfo(path="file1.txt", size=100, file_type="txt")
        file2 = FileInfo(path="file2.txt", size=100, file_type="txt")
        file3 = FileInfo(path="file3.txt", size=100, file_type="txt")

        group = DuplicateFileGroup(files=[file1, file2, file3], potential_savings=200)

        assert group.duplicate_count == 2  # 3 files - 1 original

    def test_minimum_files_validation(self) -> None:
        """Test that at least 2 files are required."""
        file1 = FileInfo(path="file1.txt", size=100, file_type="txt")

        with pytest.raises(ValueError):
            DuplicateFileGroup(files=[file1], potential_savings=0)  # Only 1 file


class TestFileAnalysis:
    """Test cases for FileAnalysis model."""

    def test_total_duplicate_savings_property(self) -> None:
        """Test total_duplicate_savings property calculation."""
        file1 = FileInfo(path="file1.txt", size=100, file_type="txt")
        file2 = FileInfo(path="file2.txt", size=100, file_type="txt")

        group1 = DuplicateFileGroup(files=[file1, file2], potential_savings=100)
        group2 = DuplicateFileGroup(files=[file1, file2], potential_savings=200)

        analysis = FileAnalysis(total_size=1000, file_count=10, duplicate_files=[group1, group2])

        assert analysis.total_duplicate_savings == 300

    def test_file_type_sizes_property(self) -> None:
        """Test file_type_sizes property calculation."""
        txt_file1 = FileInfo(path="file1.txt", size=100, file_type="txt")
        txt_file2 = FileInfo(path="file2.txt", size=200, file_type="txt")
        jpg_file = FileInfo(path="image.jpg", size=500, file_type="jpg")

        analysis = FileAnalysis(
            total_size=800,
            file_count=3,
            files_by_type={"txt": [txt_file1, txt_file2], "jpg": [jpg_file]},
        )

        type_sizes = analysis.file_type_sizes
        assert type_sizes["txt"] == 300  # 100 + 200
        assert type_sizes["jpg"] == 500


class TestAnalysisResults:
    """Test cases for AnalysisResults model."""

    def test_total_size_property(self) -> None:
        """Test total_size property returns file analysis total."""
        app_info = AppInfo(
            name="Test",
            bundle_id="com.test",
            version="1.0",
            build="1",
            executable="test",
            minimum_os_version="14.0",
        )

        file_analysis = FileAnalysis(total_size=2048, file_count=5)

        binary_analysis = BinaryAnalysis(executable_size=1024, architectures=["arm64"])

        results = AnalysisResults(
            app_info=app_info, file_analysis=file_analysis, binary_analysis=binary_analysis
        )

        assert results.total_size == 2048

    def test_to_dict_serialization(self) -> None:
        """Test to_dict method creates serializable dictionary."""
        app_info = AppInfo(
            name="Test",
            bundle_id="com.test",
            version="1.0",
            build="1",
            executable="test",
            minimum_os_version="14.0",
        )

        file_analysis = FileAnalysis(total_size=1024, file_count=1)

        binary_analysis = BinaryAnalysis(executable_size=512, architectures=["arm64"])

        results = AnalysisResults(
            app_info=app_info, file_analysis=file_analysis, binary_analysis=binary_analysis
        )

        data = results.to_dict()

        assert isinstance(data, dict)
        assert "app_info" in data
        assert "file_analysis" in data
        assert "binary_analysis" in data
        assert "generated_at" in data
        assert isinstance(data["generated_at"], str)  # Should be ISO format string
