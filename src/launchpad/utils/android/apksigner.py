import shutil
import subprocess

from pathlib import Path

from ..logging import get_logger

logger = get_logger(__name__)


class ApksignerError(Exception):
    """Raised when apksigner command fails."""

    def __init__(self, message: str, returncode: int, stdout: str, stderr: str) -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class Apksigner:
    """Wrapper around Android's apksigner CLI utility."""

    def __init__(self, apksigner_path: str | Path | None = None) -> None:
        """Initialize apksigner wrapper.

        Args:
            apksigner_path: Optional path to apksigner executable file. If not provided,
                will attempt to find apksigner in PATH.

        Raises:
            FileNotFoundError: If apksigner cannot be found at specified path or in PATH
        """
        if apksigner_path is None:
            apksigner_path = shutil.which("apksigner")
            if apksigner_path is None:
                raise FileNotFoundError("apksigner not found in PATH.")

        self.apksigner_path = Path(apksigner_path)
        if not self.apksigner_path.exists():
            raise FileNotFoundError(f"apksigner not found at {apksigner_path}")

    def get_certs(self, apk_path: Path) -> str:
        """Get certificates for an APK.

        Args:
            apk_path: Path to the APK file

        Returns:
            String containing certificate information
        """
        cmd = [str(self.apksigner_path), "verify", "--print-certs", str(apk_path)]

        logger.debug("Running apksigner command: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            raise ApksignerError(f"Failed to run apksigner command: {e}", -1, "", str(e)) from e

        return result.stdout
