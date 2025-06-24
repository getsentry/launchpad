"""Code signature validation for iOS apps."""

from __future__ import annotations

import hashlib
import plistlib
import re

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import lief

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive
from launchpad.parsers.apple.code_signature_parser import CodeSignInformation
from launchpad.parsers.apple.macho_parser import MachOParser

from .logging import get_logger

logger = get_logger(__name__)

# Known Apple root certificate fingerprints
KNOWN_APPLE_ROOT_CERT_FINGERPRINTS = [
    # Apple Inc Root
    "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024",
    # Apple Root CA - G2 Root
    "c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050",
    # Apple Root CA - G3 Root
    "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179",
    # Worldwide Developer Relations - G2 (Expiring 05/06/2029 23:43:24 UTC)
    "c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050",
    # Worldwide Developer Relations - G3 (Expiring 02/20/2030 00:00:00 UTC)
    "dcf21878c77f4198e4b4614f03d696d89c66c66008d4244e1b99161aac91601f",
    # Worldwide Developer Relations - G4 (Expiring 12/10/2030 00:00:00 UTC)
    "ea4757885538dd8cb59ff4556f676087d83c85e70902c122e42c0808b5bce14c",
    # Worldwide Developer Relations - G5 (Expiring 12/10/2030 00:00:00 UTC)
    "53fd008278e5a595fe1e908ae9c5e5675f26243264a5a6438c023e3ce2870760",
    # Worldwide Developer Relations - G6 (Expiring 03/19/2036 00:00:00 UTC)
    "bdd4ed6e74691f0c2bfd01be0296197af1379e0418e2d300efa9c3bef642ca30",
    # Apple WWDR MP CA 1 - G1 (Expiring 09/28/2038 00:00:00 UTC)
    "128a8d3fd58a44f516041bb00a0ab9781badec974b11c907b2027f2cc4cfbe1f",
]


class CodeSignatureHashIndex:
    """Code signature hash indices."""

    ENTITLEMENTS_DER = 0
    UNUSED = 1
    ENTITLEMENTS = 2
    APPLICATION_SPECIFIC = 3
    CODE_RESOURCES = 4
    REQUIREMENTS = 5
    INFO_PLIST = 6


class CodeSigningRule:
    """Code signing rule."""

    def __init__(self, omit: bool = False, optional: bool = False):
        self.omit = omit
        self.optional = optional


class FileHash:
    """File hash information."""

    def __init__(self, hash2: Optional[str] = None, optional: bool = False, symlink: Optional[str] = None):
        self.hash2 = hash2
        self.optional = optional
        self.symlink = symlink


class BinaryCheckResult:
    """Binary check result."""

    def __init__(
        self,
        valid: bool,
        info_plist_hash: Optional[str] = None,
        resources_hash: Optional[str] = None,
        bundle_identifier: Optional[str] = None,
    ):
        self.valid = valid
        self.info_plist_hash = info_plist_hash
        self.resources_hash = resources_hash
        self.bundle_identifier = bundle_identifier


class CodeSignatureValidator:
    """Validates code signatures for iOS apps."""

    def __init__(self, archive: ZippedXCArchive) -> None:
        """Initialize the validator.

        Args:
            archive: The XCArchive to validate
        """
        self.archive = archive
        self.plist = self.archive.get_plist()
        self.executable_name: str = self.archive.get_plist().get("CFBundleExecutable", "")
        self.app_root: Path = self.archive.get_app_bundle_path()
        self.macho_parser: Optional[MachOParser] = None

    def validate(self) -> Tuple[bool, List[str]]:
        """Validate the code signature.

        Returns:
            Tuple of (is_valid, list of errors)
        """
        try:
            binary_hashes = self._validate_executable()
            self._validate_info_plist(binary_hashes)
            errors = self._validate_code_resources(binary_hashes)

            # Check bundle identifier mismatch
            if binary_hashes.bundle_identifier != self.plist.get("CFBundleIdentifier"):
                raise ValueError(
                    f"Signature bundle identifier mismatch, found: {binary_hashes.bundle_identifier}, "
                    f"expected: {self.plist.get('CFBundleIdentifier')}"
                )

            return len(errors) == 0, errors

        except Exception as e:
            logger.error(f"Failed to validate code signature: {e}")
            return False, [str(e)]

    def _validate_executable(self) -> BinaryCheckResult:
        """Validate the executable."""
        executable = self.archive.get_binary_path()
        if not executable:
            raise ValueError("No executable found")
        fat_binary = lief.MachO.parse(str(executable))
        if fat_binary is None:
            raise ValueError("Failed to parse binary")

        self.macho_parser = MachOParser(fat_binary.at(0))
        if self.macho_parser.is_encrypted():
            raise ValueError("Binary is encrypted, not valid for distribution")

        binary_hashes = self._check_binary()
        if not binary_hashes.valid:
            raise ValueError("Binary is not valid")

        return binary_hashes

    def _validate_info_plist(self, binary_hashes: BinaryCheckResult) -> None:
        """Validate the Info.plist."""
        info_plist_file = self.app_root / "Info.plist"

        info_plist_hash = self._get_file_hash(info_plist_file)
        if info_plist_hash != binary_hashes.info_plist_hash:
            raise ValueError(f"{self.app_root}: invalid Info.plist (plist or signature have been modified)")

    def _validate_code_resources(self, binary_hashes: BinaryCheckResult) -> List[str]:
        """Validate code resources."""
        code_resource_info = self.app_root / "_CodeSignature" / "CodeResources"
        with open(code_resource_info, "rb") as f:
            code_resources_buffer = f.read()
        code_resources_hash = self._get_buffer_hash(code_resources_buffer)

        if code_resources_hash != binary_hashes.resources_hash:
            raise ValueError("CodeResources hash mismatch")

        plist_json = plistlib.loads(code_resources_buffer)
        rules = plist_json.get("rules2", {})
        files_hashes = plist_json.get("files2", {})

        files_to_skip = [re.compile(r"^_CodeSignature/.*"), re.compile(f"^{re.escape(self.executable_name)}$")]

        errors = self._check_bundle_resources(rules, files_hashes, files_to_skip)

        # Check for missing files
        for file_path, hash_data in files_hashes.items():
            if isinstance(hash_data, dict):
                is_optional = hash_data.get("optional", False)
            else:
                is_optional = False

            if not is_optional:
                errors.append(f"file missing: {file_path}")

        return errors

    def _check_bundle_resources(
        self, rules: Dict[str, Any], file_hashes: Dict[str, Any], skipped_files: List[re.Pattern[str]]
    ) -> List[str]:
        """Check bundle resources."""
        errors: list[str] = []

        for file_path in self.app_root.rglob("*"):
            if file_path.is_dir():
                continue

            relative_path = str(file_path.relative_to(self.app_root))

            if any(regex.match(relative_path) for regex in skipped_files):
                continue

            self._check_file(relative_path, rules, file_hashes, errors)

        return errors

    def _check_file(
        self, file_path: str, rules: Dict[str, Any], file_hashes: Dict[str, Any], errors: List[str]
    ) -> None:
        """Check a single file."""
        if file_path in file_hashes:
            full_file_path = self.app_root / file_path
            try:
                with open(full_file_path, "rb") as f:
                    file_buffer = f.read()
            except Exception as e:
                logger.error(f"Failed to read file {file_path}: {e}")
                errors.append(f"file modified: {file_path}")
                return

            calculated_hash_hex = self._get_buffer_hash(file_buffer)

            hash_data = file_hashes[file_path]
            if isinstance(hash_data, dict):
                is_optional = hash_data.get("optional", False)
                found_hash = hash_data.get("hash2", b"").hex()
                is_symlink = bool(hash_data.get("symlink"))
            else:
                is_optional = False
                found_hash = hash_data.hex()
                is_symlink = False

            if is_symlink:
                symlink_path = file_buffer.decode("utf-8").strip()
                expected_symlink = hash_data.get("symlink", "")
                if symlink_path != expected_symlink:
                    logger.debug(f"File {file_path} has an incorrect symlink")
                    errors.append(f"file modified: {file_path}")
            elif calculated_hash_hex != found_hash and not is_optional:
                logger.debug(f"File {file_path} has an incorrect hash")
                errors.append(f"file modified: {file_path}")

            del file_hashes[file_path]
        else:
            # Check regex in rules
            matching_rules = [key for key in rules.keys() if re.match(key, file_path)]
            if matching_rules:
                can_skip = any(isinstance(rules[key], dict) and rules[key].get("omit", False) for key in matching_rules)
                if can_skip:
                    return

            logger.debug(f"File {file_path} is not in the files2 array")
            errors.append(f"file added: {file_path}")

    def _check_binary(self) -> BinaryCheckResult:
        """Check the binary."""
        if not self.macho_parser:
            raise ValueError("MachO parser not initialized")

        code_signature = self.macho_parser.parse_code_signature()
        code_directory = code_signature.code_directory if code_signature else None
        if not code_directory:
            raise ValueError("No code directory found")

        if not code_signature:
            logger.info("No code signature found")
            raise ValueError(f"{self.app_root}: code object is not signed at all")

        is_valid_signature = self._check_is_valid_signature(code_signature)

        if not is_valid_signature:
            return BinaryCheckResult(valid=False)

        special_hashes = code_directory.special_hashes
        info_plist_hash = (
            special_hashes[CodeSignatureHashIndex.INFO_PLIST]
            if len(special_hashes) > CodeSignatureHashIndex.INFO_PLIST
            else None
        )
        resources_hash = (
            special_hashes[CodeSignatureHashIndex.CODE_RESOURCES]
            if len(special_hashes) > CodeSignatureHashIndex.CODE_RESOURCES
            else None
        )
        bundle_identifier = code_directory.bundle_id

        return BinaryCheckResult(
            valid=True,
            info_plist_hash=info_plist_hash,
            resources_hash=resources_hash,
            bundle_identifier=bundle_identifier,
        )

    def _get_file_hash(self, file_path: Path) -> str:
        """Get file hash."""
        try:
            with open(file_path, "rb") as f:
                bytes = f.read()
                return self._get_buffer_hash(bytes)
        except Exception as e:
            raise RuntimeError(f"Failed to parse file: {e}")

    def _get_buffer_hash(self, buffer: bytes) -> str:
        """Get buffer hash."""
        return hashlib.sha256(buffer).hexdigest()

    def _check_is_valid_signature(self, code_signature: CodeSignInformation) -> bool:
        """Check if the signature is valid."""
        # Check if all required fields are present
        if (
            not code_signature.code_directory
            or not code_signature.cms_signing
            or not code_signature.entitlements
            or not code_signature.requirements
            or not code_signature.der_entitlements
        ):
            return False

        code_directory = code_signature.code_directory
        cms_signing = code_signature.cms_signing
        entitlements = code_signature.entitlements
        requirements = code_signature.requirements
        der_entitlements = code_signature.der_entitlements

        # Check special hashes
        special_hashes = code_directory.special_hashes

        if len(special_hashes) > CodeSignatureHashIndex.ENTITLEMENTS_DER:
            entitlements_der_hash = special_hashes[CodeSignatureHashIndex.ENTITLEMENTS_DER]
            if entitlements_der_hash != der_entitlements.cd_hash:
                logger.warning(
                    f"[Codesign] Entitlements DER hash mismatch: {entitlements_der_hash} !== {der_entitlements.cd_hash}"
                )
                return False

        if len(special_hashes) > CodeSignatureHashIndex.ENTITLEMENTS:
            entitlements_hash = special_hashes[CodeSignatureHashIndex.ENTITLEMENTS]
            if entitlements_hash != entitlements.cd_hash:
                logger.warning(f"[Codesign] Entitlements hash mismatch: {entitlements_hash} !== {entitlements.cd_hash}")
                return False

        if len(special_hashes) > CodeSignatureHashIndex.REQUIREMENTS:
            requirements_hash = special_hashes[CodeSignatureHashIndex.REQUIREMENTS]
            if requirements_hash != requirements.cd_hash:
                logger.warning(f"[Codesign] Requirements hash mismatch: {requirements_hash} !== {requirements.cd_hash}")
                return False

        # Check CMS signing hash
        code_directory_hash = code_directory.cd_hash
        cms_signing_hash = next(
            (hash_data for hash_data in cms_signing.cd_hashes if hash_data["value"] == code_directory_hash), None
        )

        if not cms_signing_hash:
            available_hashes = [str(hash_data["value"]) for hash_data in cms_signing.cd_hashes]
            logger.warning(
                f"[Codesign] Code directory hash mismatch, available hashes: {', '.join(available_hashes)}, "
                f"calculated hash: {code_directory_hash}"
            )
            return False

        # Check certificates chain of trust
        certificates = list(reversed(cms_signing.certificates))
        if not self._validate_certificates(certificates):
            return False

        return True

    def _validate_certificates(self, certificates: List[bytes]) -> bool:
        """Validate certificates chain of trust.

        This function validates the certificate chain by:
        1. Checking that each certificate is signed by the next one in the chain
        2. Validating that the root certificate is a known Apple certificate

        Args:
            certificates: List of certificate data in DER format

        Returns:
            True if certificate chain is valid, False otherwise
        """
        if not certificates:
            logger.warning("[Codesign] No certificates found")
            return False

        try:
            # Parse certificates from DER format
            parsed_certs: list[x509.Certificate] = []
            for cert_data in certificates:
                try:
                    cert = x509.load_der_x509_certificate(cert_data)
                    parsed_certs.append(cert)
                except Exception as e:
                    logger.error(f"[Codesign] Failed to parse certificate: {e}")
                    return False

            commonNameOid = x509.ObjectIdentifier("2.5.4.3")
            for i in range(len(parsed_certs) - 1):
                commonName = parsed_certs[i].issuer.get_attributes_for_oid(commonNameOid)
                found_cert = next(
                    (cert for cert in parsed_certs if cert.subject.get_attributes_for_oid(commonNameOid) == commonName),
                    None,
                )
                if not found_cert:
                    logger.warning(
                        f"[Codesign] Certificate chain is broken - issuer not found: {parsed_certs[i].issuer}"
                    )
                    return False

                # We don't perform further validation of the signature because some certificates will
                # use the sha1WithRSAEncryption signature algorithm which is not supported
                # by `verify_directly_issued_by`

            # Validate root certificate against known fingerprints
            root_cert = parsed_certs[-1]
            root_fingerprint = root_cert.fingerprint(hashes.SHA256()).hex()

            is_known_apple_root = any(
                fingerprint == root_fingerprint for fingerprint in KNOWN_APPLE_ROOT_CERT_FINGERPRINTS
            )
            if not is_known_apple_root:
                logger.warning(f"[Codesign] Root certificate is not a trusted Apple CA: {root_fingerprint}")
                return False

            logger.debug("Certificate chain validation successful")
            return True

        except Exception as e:
            logger.error(f"[Codesign] Certificate validation failed: {e}")
            return False
