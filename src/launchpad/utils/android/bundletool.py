"""Android bundletool wrapper utilities."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Sequence

from pydantic import BaseModel, Field

from ..file_utils import create_temp_directory
from ..logging import get_logger

logger = get_logger(__name__)


class BundletoolError(Exception):
    """Raised when bundletool command fails."""

    def __init__(self, message: str, returncode: int, stdout: str, stderr: str) -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class Bundletool:
    """Wrapper around Android's bundletool CLI utility."""

    def __init__(self, bundletool_path: str | Path | None = None) -> None:
        """Initialize bundletool wrapper.

        Args:
            bundletool_path: Optional path to bundletool executable file. If not provided,
                will attempt to find bundletool in PATH.

        Raises:
            FileNotFoundError: If bundletool cannot be found at specified path or in PATH
        """
        if bundletool_path is None:
            try:
                result = subprocess.run(
                    ["which", "bundletool"],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                bundletool_path = result.stdout.strip()
            except subprocess.CalledProcessError as e:
                raise FileNotFoundError("bundletool not found in PATH. Install with `brew install bundletool`") from e

        self.bundletool_path = Path(bundletool_path)
        if not self.bundletool_path.exists():
            raise FileNotFoundError(f"bundletool not found at {bundletool_path}")

    def _run_command(self, command: list[str], **kwargs: Any) -> tuple[int, str, str]:
        """Run a bundletool command.

        Args:
            command: List of command arguments to pass to bundletool
            **kwargs: Additional arguments to pass to subprocess.run

        Returns:
            Tuple of (returncode, stdout, stderr)

        Raises:
            BundletoolError: If command fails
        """
        cmd = [str(self.bundletool_path)] + command
        logger.debug("Running bundletool command: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                **kwargs,
            )
        except subprocess.SubprocessError as e:
            raise BundletoolError(
                f"Failed to run bundletool command: {e}",
                -1,
                "",
                str(e),
            ) from e

        if result.returncode != 0:
            raise BundletoolError(
                f"bundletool command failed with return code {result.returncode}",
                result.returncode,
                result.stdout,
                result.stderr,
            )

        return result.returncode, result.stdout, result.stderr

    def build_apks(
        self,
        bundle_path: str | Path,
        output_dir: str | Path,
        device_spec: DeviceSpec,
    ) -> None:
        """Build APKs from an Android App Bundle.

        Args:
            bundle_path: Path to input AAB file
            output_dir: Directory to output APKS files
            device_spec: Device specification for APK splitting configuration.

        Raises:
            BundletoolError: If build command fails
        """
        temp_apks_path = create_temp_directory("apks-") / "apks.apks"
        build_apks_command = ["build-apks", f"--bundle={bundle_path}", f"--output={temp_apks_path}"]

        # Create a temporary file for the device spec JSON
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as temp_file:
            json.dump(device_spec.model_dump(by_alias=True), temp_file)
            temp_device_spec_path = temp_file.name

        try:
            self._run_command(build_apks_command)

            # Extract APKs for the specified device
            extract_command = [
                "extract-apks",
                f"--apks={temp_apks_path}",
                f"--output-dir={output_dir}",
                f"--device-spec={temp_device_spec_path}",
            ]
            self._run_command(extract_command)
        finally:
            # Clean up the temporary file
            Path(temp_device_spec_path).unlink(missing_ok=True)


class DeviceSpec(BaseModel):
    """Device specification for APK splitting configuration.

    Matches the proto definition from bundletool's device_targeting_config.proto.
    See https://github.com/google/bundletool/blob/master/src/main/proto/devices.proto,
    https://github.com/google/bundletool/blob/master/src/main/proto/device_targeting_config.proto

    # Intentionally skipping:
    # deviceTier
    # glExtensions
    # textureCompressionFormats
    # hasGlEs3
    # deviceFeature
    # minScreenWidthDp
    # maxScreenWidthDp
    # minScreenHeightDp
    # maxScreenHeightDp
    """

    # Required fields
    sdk_version: int = Field(
        default=35,
        alias="sdkVersion",
        description="Minimum SDK version required",
        ge=1,  # SDK versions start at 1
    )

    # Optional fields
    supported_abis: Sequence[str] | None = Field(
        default=["arm64-v8a"],
        alias="supportedAbis",
        description="List of supported ABIs (e.g. ['arm64-v8a', 'armeabi-v7a'])",
    )
    supported_locales: Sequence[str] | None = Field(
        default=["en"],
        alias="supportedLocales",
        description="List of supported locales (e.g. ['en', 'fr'])",
    )
    screen_density: int | None = Field(
        default=420,
        alias="screenDensity",
        description="Screen density in dpi",
        ge=1,  # Must be positive
    )
