import platform
import subprocess

from pathlib import Path
from typing import List


class AppleStrip:
    """
    A wrapper for the strip tool that works on both macOS and Linux.

    On macOS, uses the system strip tool.
    On Linux, uses the bundled Apple strip tool from scripts/strip/dist/.
    """

    def __init__(self) -> None:
        self._strip_path = self._get_strip_path()

    def strip(
        self, input_file: str | Path, output_file: str | Path | None = None, flags: List[str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        input_path = Path(input_file)
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")

        cmd = [self._strip_path]

        if flags:
            cmd.extend(flags)

        if output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            cmd.extend(["-o", str(output_path)])

        cmd.append(str(input_path))

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )
        return result

    def _get_strip_path(self) -> str:
        # TODO(EME-434): eventually remove this and wire this up to our deps tool
        system = platform.system()

        if system == "Darwin":
            return "strip"
        elif system == "Linux":
            # Find project root and locate the bundled strip tool
            project_root = self._find_project_root()
            strip_path = project_root / "scripts" / "strip" / "dist" / "strip"

            if not strip_path.exists():
                raise FileNotFoundError(
                    f"Strip tool not found at {strip_path}. Make sure the bundled strip tool is built and available."
                )

            return str(strip_path)
        else:
            raise RuntimeError(f"Unsupported platform: {system}")

    def _find_project_root(self) -> Path:
        """
        Find the project root by looking for marker files.
        """
        current_path = Path(__file__).resolve()

        # Look for common project marker files/directories
        markers = ["pyproject.toml", ".git", "Makefile", "requirements.txt"]

        for parent in [current_path] + list(current_path.parents):
            for marker in markers:
                if (parent / marker).exists():
                    return parent

        raise RuntimeError(
            "Could not find project root. Please ensure you're running from within "
            "the project directory or that project marker files exist."
        )
