"""Android bundletool wrapper utilities."""

from __future__ import annotations

import json
import secrets
import shutil
import string
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

    def __str__(self):
        return f"{super().__str__()}\n\nstdout:\n{self.stdout}\n\nstderr:\n{self.stderr}"


class Bundletool:
    """Wrapper around Android's bundletool CLI utility."""

    bundletool_path: str

    def __init__(self) -> None:
        """Initialize bundletool wrapper.

        Raises:
            AssertionError: If bundletool cannot be found on PATH
        """
        bundletool_path = shutil.which("bundletool")
        assert bundletool_path is not None
        self.bundletool_path = bundletool_path

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

    def _generate_keystore(self, keystore_path: Path) -> tuple[str, str]:
        """Generate a random keystore for signing APKs.

        Args:
            keystore_path: Path where the keystore file should be created

        Returns:
            Tuple of (keystore_password, key_alias)

        Raises:
            BundletoolError: If keystore generation fails
        """
        # Generate random password and alias
        password = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
        key_alias = "".join(secrets.choice(string.ascii_lowercase) for _ in range(8))

        # Keytool command to generate keystore
        keytool_cmd = [
            "keytool",
            "-genkeypair",
            "-v",
            "-keystore",
            str(keystore_path),
            "-alias",
            key_alias,
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            "10000",
            "-storepass",
            password,
            "-keypass",
            password,
            "-dname",
            "CN=Launchpad, OU=Development, O=Sentry, L=San Francisco, S=CA, C=US",
        ]

        logger.debug("Generating keystore at %s", keystore_path)

        try:
            subprocess.run(
                keytool_cmd,
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            raise BundletoolError(
                f"Failed to generate keystore: {e}",
                e.returncode,
                e.stdout,
                e.stderr,
            ) from e

        return password, key_alias

    def build_apks(
        self,
        bundle_path: str | Path,
        output_dir: str | Path,
        device_spec: DeviceSpec,
        sign_apks: bool = True,
    ) -> None:
        """Build APKs from an Android App Bundle.

        Args:
            bundle_path: Path to input AAB file
            output_dir: Directory to output APKS files
            device_spec: Device specification for APK splitting configuration.
            sign_apks: Whether to sign the generated APKs with a random keystore.
                      Defaults to True to ensure .SF and .MF files are present.

        Raises:
            BundletoolError: If build command fails
        """
        temp_apks_path = create_temp_directory("apks-") / "apks.apks"
        build_apks_command = ["build-apks", f"--bundle={bundle_path}", f"--output={temp_apks_path}"]

        # Generate keystore and sign APKs if requested
        if sign_apks:
            keystore_path = create_temp_directory("keystore-") / "signing.keystore"
            keystore_password, key_alias = self._generate_keystore(keystore_path)

            # Add signing arguments to build command
            build_apks_command.extend(
                [
                    f"--ks={keystore_path}",
                    f"--ks-key-alias={key_alias}",
                    f"--ks-pass=pass:{keystore_password}",
                ]
            )

            logger.debug("APKs will be signed with generated keystore")

        # Create a temporary file for the device spec JSON
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as temp_file:
            json.dump(device_spec.model_dump(by_alias=True), temp_file)
            temp_file.flush()  # Ensure data is written to disk

            self._run_command(build_apks_command)

            # Extract APKs for the specified device
            extract_command = [
                "extract-apks",
                f"--apks={temp_apks_path}",
                f"--output-dir={output_dir}",
                f"--device-spec={temp_file.name}",
            ]
            self._run_command(extract_command)


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
