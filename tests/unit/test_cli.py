from click.testing import CliRunner

from launchpad import __version__
from launchpad.cli import cli


class TestCLI:
    """Test cases for the CLI interface."""

    def test_version_flag(self) -> None:
        """Test --version flag displays correct version."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])

        assert result.exit_code == 0
        assert __version__ in result.output

    def test_help_output(self) -> None:
        """Test help output is displayed when no command given."""
        runner = CliRunner()
        result = runner.invoke(cli, [])

        assert result.exit_code == 0
        assert "Launchpad" in result.output
        assert "apple-app" in result.output

    def test_analyze_help(self) -> None:
        """Test analyze command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["apple-app", "--help"])

        assert result.exit_code == 0
        assert "Analyze an Apple app bundle" in result.output
        assert "INPUT_PATH" in result.output

    def test_analyze_missing_input(self) -> None:
        """Test analyze command fails with missing input."""
        runner = CliRunner()
        result = runner.invoke(cli, ["analyze"])

        assert result.exit_code != 0
        assert "Missing argument" in result.output or "Error" in result.output

    def test_analyze_nonexistent_file(self) -> None:
        """Test analyze command fails with nonexistent file."""
        runner = CliRunner()
        result = runner.invoke(cli, ["analyze", "/nonexistent/file.app"])

        assert result.exit_code != 0
