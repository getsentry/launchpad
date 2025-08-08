import logging

from io import BytesIO
from pathlib import Path
from zipfile import BadZipFile, ZipFile

from .android.aab import AAB
from .android.apk import APK
from .android.zipped_aab import ZippedAAB
from .android.zipped_apk import ZippedAPK
from .apple.zipped_xcarchive import ZippedXCArchive
from .artifact import Artifact

logger = logging.getLogger(__name__)

# DEBUG: Remove this line when debugging is complete
DEBUG_FACTORY = True  # Force enable for debugging


class ArtifactFactory:
    """Factory for creating artifacts from paths."""

    @staticmethod
    def from_path(path: Path) -> Artifact:
        """Create appropriate Artifact from file path.

        Args:
            path: Path to the artifact file

        Returns:
            Appropriate Artifact instance

        Raises:
            FileNotFoundError: If path does not exist
            ValueError: If file is not a valid artifact
        """
        if not path.is_file():
            raise FileNotFoundError(f"Path is not a file: {path}")

        content = path.read_bytes()

        # DEBUG: Remove this function call when debugging is complete
        if DEBUG_FACTORY:
            _debug_artifact_analysis(path, content)

        # Check if it's a zip file by looking at magic bytes
        if content.startswith(b"PK\x03\x04"):
            try:
                with ZipFile(BytesIO(content)) as zip_file:
                    # Check if zip contains a Info.plist in the root of the .xcarchive folder (ZippedXCArchive)
                    plist_files = [f for f in zip_file.namelist() if f.endswith(".xcarchive/Info.plist")]
                    if plist_files:
                        return ZippedXCArchive(path)

                    apk_files = [f for f in zip_file.namelist() if f.endswith(".apk")]
                    if len(apk_files) == 1:
                        return ZippedAPK(path)

                    aab_files = [f for f in zip_file.namelist() if f.endswith(".aab")]
                    if len(aab_files) == 1:
                        return ZippedAAB(path)

                    # Check if zip contains base/manifest/AndroidManifest.xml (AAB)
                    manifest_files = [f for f in zip_file.namelist() if f.endswith("base/manifest/AndroidManifest.xml")]
                    if manifest_files:
                        return AAB(path)

                    # Check if zip contains AndroidManifest.xml (APK)
                    manifest_files = [f for f in zip_file.namelist() if f.endswith("AndroidManifest.xml")]
                    if manifest_files:
                        return APK(path)

            except BadZipFile as e:
                logger.error(f"ZIP file is corrupted: {e}")
                raise ValueError(f"Corrupted ZIP file: {e}")
            except Exception as e:
                logger.error(f"Unexpected error reading ZIP: {e}")
                raise ValueError(f"Error reading ZIP file: {e}")

        # Check if it's a direct APK or AAB by looking for AndroidManifest.xml in specific locations
        try:
            with ZipFile(BytesIO(content)) as zip_file:
                if any(f.endswith("base/manifest/AndroidManifest.xml") for f in zip_file.namelist()):
                    return AAB(path)

                if any(f.endswith("AndroidManifest.xml") for f in zip_file.namelist()):
                    return APK(path)
        except Exception:
            pass

        raise ValueError("Input is not a supported artifact")


# DEBUG: Remove this entire function when debugging is complete
def _debug_artifact_analysis(path: Path, content: bytes) -> None:
    """Comprehensive debug analysis of artifact file."""
    logger.info(f"[DEBUG_FACTORY] ===== ARTIFACT FACTORY ANALYSIS FOR {path} =====")
    logger.info(f"[DEBUG_FACTORY] File size: {len(content)} bytes ({len(content) / 1024 / 1024:.2f} MB)")
    logger.info(f"[DEBUG_FACTORY] First 50 bytes: {content[:50]}")
    logger.info(f"[DEBUG_FACTORY] First 50 bytes hex: {content[:50].hex()}")

    if len(content) > 100:
        logger.info(f"[DEBUG_FACTORY] Last 50 bytes: {content[-50:]}")
        logger.info(f"[DEBUG_FACTORY] Last 50 bytes hex: {content[-50:].hex()}")

    # Check ZIP magic bytes
    if content.startswith(b"PK\x03\x04"):
        logger.info("[DEBUG_FACTORY] ✓ File has ZIP magic bytes")

        try:
            with ZipFile(BytesIO(content)) as zip_file:
                all_files = zip_file.namelist()
                logger.info(f"[DEBUG_FACTORY] ✓ ZIP file opened successfully - {len(all_files)} files total")

                # Show first 20 files
                logger.info(f"[DEBUG_FACTORY] First 20 files: {all_files[:20]}")

                # Comprehensive pattern analysis
                plist_files = [f for f in all_files if f.endswith(".xcarchive/Info.plist")]
                apk_files = [f for f in all_files if f.endswith(".apk")]
                aab_files = [f for f in all_files if f.endswith(".aab")]
                aab_manifests = [f for f in all_files if f.endswith("base/manifest/AndroidManifest.xml")]
                apk_manifests = [f for f in all_files if f.endswith("AndroidManifest.xml")]
                xcarchive_files = [f for f in all_files if ".xcarchive" in f]
                ios_files = [
                    f
                    for f in all_files
                    if any(ext in f.lower() for ext in [".app/", ".framework/", ".dylib", ".bundle/", "info.plist"])
                ]

                logger.info("[DEBUG_FACTORY] PATTERN ANALYSIS:")
                logger.info(f"[DEBUG_FACTORY]   📱 iOS .xcarchive/Info.plist files: {len(plist_files)} → {plist_files}")
                logger.info(
                    f"[DEBUG_FACTORY]   📱 Any .xcarchive files: {len(xcarchive_files)} → {xcarchive_files[:10]}"
                )
                logger.info(
                    f"[DEBUG_FACTORY]   📱 iOS-like files (.app/.framework/etc): {len(ios_files)} → {ios_files[:10]}"
                )
                logger.info(f"[DEBUG_FACTORY]   🤖 Android .apk files: {len(apk_files)} → {apk_files}")
                logger.info(f"[DEBUG_FACTORY]   🤖 Android .aab files: {len(aab_files)} → {aab_files}")
                logger.info(
                    f"[DEBUG_FACTORY]   🤖 AAB manifests (base/manifest/): {len(aab_manifests)} → {aab_manifests}"
                )
                logger.info(
                    f"[DEBUG_FACTORY]   🤖 APK manifests (AndroidManifest.xml): {len(apk_manifests)} → {apk_manifests}"
                )

                # Detection logic simulation
                logger.info("[DEBUG_FACTORY] DETECTION LOGIC:")
                if plist_files:
                    logger.info(f"[DEBUG_FACTORY]   ✅ WOULD DETECT as ZippedXCArchive due to: {plist_files}")
                elif len(apk_files) == 1:
                    logger.info(f"[DEBUG_FACTORY]   ✅ WOULD DETECT as ZippedAPK due to single APK: {apk_files[0]}")
                elif len(aab_files) == 1:
                    logger.info(f"[DEBUG_FACTORY]   ✅ WOULD DETECT as ZippedAAB due to single AAB: {aab_files[0]}")
                elif aab_manifests:
                    logger.info(f"[DEBUG_FACTORY]   ✅ WOULD DETECT as AAB due to AAB manifests: {aab_manifests}")
                elif apk_manifests:
                    logger.info(f"[DEBUG_FACTORY]   ✅ WOULD DETECT as APK due to APK manifests: {apk_manifests}")
                else:
                    logger.info("[DEBUG_FACTORY]   ❌ NO DETECTION PATTERN MATCHED")
                    logger.info(
                        "[DEBUG_FACTORY]   💡 This explains why 'Input is not a supported artifact' error occurs"
                    )

        except BadZipFile as e:
            logger.error(f"[DEBUG_FACTORY] ❌ ZIP file is corrupted or truncated: {e}")
            logger.info("[DEBUG_FACTORY] Attempting partial ZIP analysis...")

            # Check for ZIP signatures
            eocd_sig = b"PK\x05\x06"  # End of Central Directory
            cd_sig = b"PK\x01\x02"  # Central Directory
            lf_sig = b"PK\x03\x04"  # Local File Header

            eocd_pos = content.rfind(eocd_sig)
            cd_pos = content.find(cd_sig)
            lf_count = content.count(lf_sig)

            logger.info("[DEBUG_FACTORY] ZIP structure analysis:")
            logger.info(f"[DEBUG_FACTORY]   - Local File Headers (PK\\x03\\x04): {lf_count} found")
            logger.info(
                f"[DEBUG_FACTORY]   - Central Directory (PK\\x01\\x02): {'Found' if cd_pos >= 0 else 'NOT FOUND'} at pos {cd_pos}"
            )
            logger.info(
                f"[DEBUG_FACTORY]   - End of Central Directory (PK\\x05\\x06): {'Found' if eocd_pos >= 0 else 'NOT FOUND'} at pos {eocd_pos}"
            )

            if eocd_pos < 0:
                logger.error("[DEBUG_FACTORY] ❌ Missing End of Central Directory - file severely truncated!")
            if cd_pos < 0:
                logger.error("[DEBUG_FACTORY] ❌ Missing Central Directory - file may be incomplete!")

        except Exception as e:
            logger.error(f"[DEBUG_FACTORY] ❌ Unexpected ZIP error: {e}", exc_info=True)
    else:
        logger.info("[DEBUG_FACTORY] ❌ File does NOT have ZIP magic bytes")
        if len(content) >= 4:
            logger.info(f"[DEBUG_FACTORY] First 4 bytes: {content[:4]} (hex: {content[:4].hex()})")
        else:
            logger.info(f"[DEBUG_FACTORY] File too small: only {len(content)} bytes")

    logger.info(f"[DEBUG_FACTORY] ===== END ANALYSIS FOR {path} =====")
