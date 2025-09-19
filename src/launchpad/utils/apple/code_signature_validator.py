"""Code signature validation for iOS apps."""

from __future__ import annotations

import hashlib
import plistlib
import re

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import lief

from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive
from launchpad.parsers.apple.code_signature_parser import CodeSignInformation
from launchpad.parsers.apple.macho_parser import MachOParser

from ..logging import get_logger

logger = get_logger(__name__)


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

    def __init__(
        self,
        hash2: Optional[str] = None,
        optional: bool = False,
        symlink: Optional[str] = None,
    ):
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

        with open(executable, "rb") as f:
            fat_binary = lief.MachO.parse(f)  # type: ignore
        if fat_binary is None:
            raise ValueError("Failed to parse binary")

        self.macho_parser = MachOParser(fat_binary.at(0))
        if self.macho_parser.is_encrypted():
            return BinaryCheckResult(valid=False)

        return self._check_binary()

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

        files_to_skip = [
            re.compile(r"^_CodeSignature/.*"),
            re.compile(f"^{re.escape(self.executable_name)}$"),
        ]

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
        self,
        rules: Dict[str, Any],
        file_hashes: Dict[str, Any],
        skipped_files: List[re.Pattern[str]],
    ) -> List[str]:
        """Check bundle resources."""
        errors: list[str] = []

        for file_path in self.app_root.rglob("*"):
            if file_path.is_dir() and not file_path.is_symlink():
                continue

            relative_path = str(file_path.relative_to(self.app_root))

            if any(regex.match(relative_path) for regex in skipped_files):
                continue

            self._check_file(relative_path, rules, file_hashes, errors)

        return errors

    def _check_file(
        self,
        file_path: str,
        rules: Dict[str, Any],
        file_hashes: Dict[str, Any],
        errors: List[str],
    ) -> None:
        """Check a single file."""
        if file_path in file_hashes:
            full_file_path = self.app_root / file_path
            try:
                if full_file_path.is_symlink():
                    # For symlinks, read the target path as the file content
                    target_path = full_file_path.readlink()
                    file_buffer = str(target_path).encode("utf-8")
                else:
                    # For regular files, read the file contents
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
        if not code_signature:
            logger.info("No code signature found")
            return BinaryCheckResult(valid=False)

        code_directory = code_signature.code_directory
        if not code_directory:
            logger.info("No code directory found")
            return BinaryCheckResult(valid=False)

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
            (hash_data for hash_data in cms_signing.cd_hashes if hash_data["value"] == code_directory_hash),
            None,
        )

        if not cms_signing_hash:
            available_hashes = [str(hash_data["value"]) for hash_data in cms_signing.cd_hashes]
            logger.warning(
                f"[Codesign] Code directory hash mismatch, available hashes: {', '.join(available_hashes)}, "
                f"calculated hash: {code_directory_hash}"
            )
            return False

        return True
