"""Code signature parser for Mach-O binaries."""

from __future__ import annotations

import hashlib

from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING, Dict, List, Optional, Union

import lief

from asn1crypto import cms  # type: ignore[import-untyped]
from lief.MachO import CodeSignature

from ...utils.logging import get_logger

if TYPE_CHECKING:
    from .macho_parser import MachOParser

logger = get_logger(__name__)


class CSAlgorithm(IntEnum):
    """Code signing algorithm types."""

    NoHash = 0
    SHA1 = 1
    SHA256 = 2
    SHA256Truncated = 3
    SHA384 = 4
    SHA512 = 5


class CSSlot(IntEnum):
    """Code signing slot types."""

    CSSLOT_CODEDIRECTORY = 0
    CSSLOT_INFOSLOT = 1
    CSSLOT_REQUIREMENTS = 2
    CSSLOT_RESOURCEDIR = 3
    CSSLOT_APPLICATION = 4
    CSSLOT_ENTITLEMENTS = 5
    CSSLOT_DER_ENTITLEMENTS = 7
    CSSLOT_ALTERNATE_CODEDIRECTORIES = 0x1000
    CSSLOT_ALTERNATE_CODEDIRECTORY_MAX = 5
    CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT = 0x1005
    CSSLOT_SIGNATURESLOT = 0x10000
    CSSLOT_IDENTIFICATIONSLOT = 0x10001
    CSSLOT_TICKETSLOT = 0x10002


@dataclass
class CSBlobIndex:
    """Code signing blob index entry."""

    type: int
    offset: int


@dataclass
class CSCodeDirectory:
    """Code signing directory structure."""

    magic: int
    length: int
    version: int
    flags: int
    hash_offset: int
    ident_offset: int
    n_special_slots: int
    n_code_slots: int
    code_limit: int
    hash_size: int
    hash_type: int
    platform: int
    page_size: int  # log2 of the page size (example 12 -> 2^12 -> 4096)
    spare2: int
    # Version 0x20100
    scatter_offset: int = 0
    # Version 0x20200
    team_offset: int = 0
    # Version 0x20300
    spare3: int = 0
    code_limit64: int = 0
    # Version 0x20400
    exec_seg_base: int = 0
    exec_seg_limit: int = 0
    exec_seg_flags: int = 0


@dataclass
class CSSuperBlob:
    """Code signing super blob structure."""

    magic: int
    length: int
    count: int
    index: List[CSBlobIndex]


@dataclass
class CodeDirectory:
    """Code directory information."""

    bundle_id: str
    team_id: Optional[str]
    hash_size: int
    hash_type: CSAlgorithm
    page_size: int
    special_hashes: List[str]
    hashes: List[str]
    code_directory: CSCodeDirectory
    cd_hash: str


@dataclass
class Entitlements:
    """Entitlements information."""

    entitlements_plist: str
    cd_hash: str


@dataclass
class Requirements:
    """Requirements information."""

    requirements: bytes
    cd_hash: str


@dataclass
class DEREntitlements:
    """DER entitlements information."""

    der_data: bytes
    cd_hash: str


@dataclass
class CMSSigning:
    """CMS signing information."""

    cd_hashes: List[Dict[str, Union[CSAlgorithm, str]]]
    certificates: List[bytes]


@dataclass
class CodeSignInformation:
    """Complete code signing information."""

    code_directory: Optional[CodeDirectory]
    entitlements: Optional[Entitlements]
    requirements: Optional[Requirements]
    der_entitlements: Optional[DEREntitlements]
    cms_signing: Optional[CMSSigning]


class CodeSignatureParser:
    """Parser for code signature information in Mach-O binaries."""

    def __init__(self, binary: lief.MachO.Binary, macho_parser: "MachOParser") -> None:
        """Initialize the parser with a LIEF binary object and reference to main parser."""
        self.binary = binary
        self.macho_parser = macho_parser

    def parse_code_signature(self) -> Optional[CodeSignInformation]:
        """Parse the code signature information from the binary.

        Returns:
            CodeSignInformation object containing all code signing data, or None if not found
        """
        try:
            if not self.binary.has_code_signature:
                return None

            super_blob = self._parse_code_signature_command(self.binary.code_signature)
            if not super_blob:
                return None

            code_directory = self._parse_code_directory(super_blob, self.binary.code_signature)
            if not code_directory:
                logger.info("No code directory found")
                return None

            entitlements = self._parse_entitlements(super_blob, self.binary.code_signature, code_directory.hash_type)
            if not entitlements:
                logger.info("No entitlements found")
                return None

            requirements = self._parse_requirements(super_blob, self.binary.code_signature, code_directory.hash_type)
            if not requirements:
                logger.info("No requirements found")
                return None

            der_entitlements = self._parse_der_entitlements(
                super_blob, self.binary.code_signature, code_directory.hash_type
            )
            if not der_entitlements:
                logger.info("No DER entitlements found")
                return None

            cms_signing = self._parse_signature(super_blob, self.binary.code_signature)
            if not cms_signing:
                logger.info("No CMS signature found")
                return None

            return CodeSignInformation(
                code_directory=code_directory,
                entitlements=entitlements,
                requirements=requirements,
                der_entitlements=der_entitlements,
                cms_signing=cms_signing,
            )

        except Exception as e:
            logger.debug(f"Failed to parse code signature: {e}")
            return None

    def _parse_code_signature_command(self, cs: CodeSignature) -> Optional[CSSuperBlob]:
        """Parse the code signature command and extract super blob information.

        Returns:
            CSSuperBlob or None if not found
        """
        try:
            # Get the code signature data
            if not hasattr(self.binary, "code_signature") or not self.binary.code_signature:
                logger.debug("No code signature data found")
                return None

            data_offset = cs.data_offset
            data_size = cs.data_size

            logger.debug(f"Data offset: {data_offset}, Data size: {data_size}")

            # Read the SuperBlob header from the raw data
            raw_data = cs.content
            if len(raw_data) < 12:  # Minimum size for SuperBlob header
                logger.debug("Code signature data too small for SuperBlob header")
                return None

            # Parse SuperBlob header (magic, length, count)
            magic = int.from_bytes(raw_data[0:4], byteorder="big")
            length = int.from_bytes(raw_data[4:8], byteorder="big")
            count = int.from_bytes(raw_data[8:12], byteorder="big")

            logger.debug(f"Superblob magic: 0x{magic:08x}, Superblob length: {length}, Superblob count: {count}")

            # Read the blob indices
            index_entries: List[CSBlobIndex] = []
            offset = 12  # Start after header

            for i in range(count):
                if offset + 8 > len(raw_data):
                    logger.debug(f"Not enough data for blob index {i}")
                    break

                blob_type = int.from_bytes(raw_data[offset : offset + 4], byteorder="big")
                blob_offset = int.from_bytes(raw_data[offset + 4 : offset + 8], byteorder="big")

                index_entries.append(CSBlobIndex(type=blob_type, offset=blob_offset))
                offset += 8

            super_blob = CSSuperBlob(magic=magic, length=length, count=count, index=index_entries)

            return super_blob

        except Exception as e:
            logger.debug(f"Failed to parse code signature command: {e}")
            return None

    def _parse_code_directory(self, super_blob: CSSuperBlob, cs: CodeSignature) -> Optional[CodeDirectory]:
        """Parse the code directory from the super blob."""
        try:
            code_directory_index = next(
                (index for index in super_blob.index if index.type == CSSlot.CSSLOT_ALTERNATE_CODEDIRECTORIES),
                None,
            )
            if not code_directory_index:
                code_directory_index = next(
                    (index for index in super_blob.index if index.type == CSSlot.CSSLOT_CODEDIRECTORY),
                    None,
                )
            if not code_directory_index:
                logger.info("No code directory index found")
                return None

            logger.debug(
                f"Code directory index type: {code_directory_index.type}, "
                f"Code directory index offset: {code_directory_index.offset}"
            )

            content = cs.content
            cd_offset = code_directory_index.offset
            cd_data = content[cd_offset:]

            # Read basic fields (32 bytes)
            magic = int.from_bytes(cd_data[0:4], byteorder="big")
            length = int.from_bytes(cd_data[4:8], byteorder="big")
            version = int.from_bytes(cd_data[8:12], byteorder="big")
            flags = int.from_bytes(cd_data[12:16], byteorder="big")
            hash_offset = int.from_bytes(cd_data[16:20], byteorder="big")
            ident_offset = int.from_bytes(cd_data[20:24], byteorder="big")
            n_special_slots = int.from_bytes(cd_data[24:28], byteorder="big")
            n_code_slots = int.from_bytes(cd_data[28:32], byteorder="big")
            code_limit = int.from_bytes(cd_data[32:36], byteorder="big")
            hash_size = cd_data[36]
            hash_type = cd_data[37]
            platform = cd_data[38]
            page_size = cd_data[39]
            spare2 = int.from_bytes(cd_data[40:44], byteorder="big")

            # Initialize version-specific fields
            scatter_offset = 0
            team_offset = 0
            spare3 = 0
            code_limit64 = 0
            exec_seg_base = 0
            exec_seg_limit = 0
            exec_seg_flags = 0

            current_offset = 44

            # Handle version-specific fields
            if version >= 0x20100:
                if current_offset + 4 <= len(cd_data):
                    scatter_offset = int.from_bytes(cd_data[current_offset : current_offset + 4], byteorder="big")
                    current_offset += 4

            if version >= 0x20200:
                if current_offset + 4 <= len(cd_data):
                    team_offset = int.from_bytes(cd_data[current_offset : current_offset + 4], byteorder="big")
                    current_offset += 4

            if version >= 0x20300:
                if current_offset + 12 <= len(cd_data):
                    spare3 = int.from_bytes(cd_data[current_offset : current_offset + 4], byteorder="little")
                    code_limit64 = int.from_bytes(
                        cd_data[current_offset + 4 : current_offset + 12],
                        byteorder="little",
                    )
                    current_offset += 12

            if version >= 0x20400:
                if current_offset + 24 <= len(cd_data):
                    exec_seg_base = int.from_bytes(cd_data[current_offset : current_offset + 8], byteorder="little")
                    exec_seg_limit = int.from_bytes(
                        cd_data[current_offset + 8 : current_offset + 16],
                        byteorder="little",
                    )
                    exec_seg_flags = int.from_bytes(
                        cd_data[current_offset + 16 : current_offset + 24],
                        byteorder="little",
                    )
                    current_offset += 24

            # Create CSCodeDirectory object
            code_directory = CSCodeDirectory(
                magic=magic,
                length=length,
                version=version,
                flags=flags,
                hash_offset=hash_offset,
                ident_offset=ident_offset,
                n_special_slots=n_special_slots,
                n_code_slots=n_code_slots,
                code_limit=code_limit,
                hash_size=hash_size,
                hash_type=hash_type,
                platform=platform,
                page_size=page_size,
                spare2=spare2,
                scatter_offset=scatter_offset,
                team_offset=team_offset,
                spare3=spare3,
                code_limit64=code_limit64,
                exec_seg_base=exec_seg_base,
                exec_seg_limit=exec_seg_limit,
                exec_seg_flags=exec_seg_flags,
            )

            # Calculate hash table offset
            hash_table_offset = cd_offset + hash_offset

            # Read special slots (negative indices)
            special_hashes: List[str] = []
            special_start = hash_table_offset - hash_size * n_special_slots
            for i in range(-n_special_slots, 0):
                slot_offset = special_start + (i + n_special_slots) * hash_size
                if slot_offset + hash_size <= len(content):
                    hash_bytes = content[slot_offset : slot_offset + hash_size]
                    hash_hex = hash_bytes.hex()
                    logger.debug(f"[Slot {i}]: {hash_hex}")
                    special_hashes.append(hash_hex)

            # Read code slots
            hashes: List[str] = []
            for i in range(n_code_slots):
                slot_offset = hash_table_offset + i * hash_size
                if slot_offset + hash_size <= len(content):
                    hash_bytes = content[slot_offset : slot_offset + hash_size]
                    hashes.append(hash_bytes.hex())

            # Read identity (bundle ID)
            identity_offset = cd_offset + ident_offset
            identity = ""
            if identity_offset < len(content):
                # Read null-terminated string
                end_offset = identity_offset
                while end_offset < len(content) and content[end_offset] != 0:
                    end_offset += 1
                identity_bytes = bytes(content[identity_offset:end_offset])
                identity = identity_bytes.decode("utf8")

            # Read team ID (if available)
            team_id = None
            if version >= 0x20200 and team_offset > 0:
                team_id_offset = cd_offset + team_offset
                if team_id_offset < len(content):
                    # Read null-terminated string
                    end_offset = team_id_offset
                    while end_offset < len(content) and content[end_offset] != 0:
                        end_offset += 1
                    team_id_bytes = bytes(content[team_id_offset:end_offset])
                    team_id = team_id_bytes.decode("utf8")

            # Calculate CD hash
            blob_data = content[cd_offset : cd_offset + length]
            hash_algorithm = "sha1" if hash_type == CSAlgorithm.SHA1 else "sha256"
            cd_hash = hashlib.new(hash_algorithm, blob_data).hexdigest()

            return CodeDirectory(
                bundle_id=identity,
                team_id=team_id,
                hash_size=hash_size,
                hash_type=CSAlgorithm(hash_type),
                page_size=page_size,
                special_hashes=special_hashes,
                hashes=hashes,
                code_directory=code_directory,
                cd_hash=cd_hash,
            )

        except Exception as e:
            logger.error(f"Failed to parse code directory: {e}")
            return None

    def _parse_entitlements(
        self, super_blob: CSSuperBlob, cs: CodeSignature, hash_type: CSAlgorithm
    ) -> Optional[Entitlements]:
        """Parse the entitlements from the super blob."""
        try:
            # Find the entitlements index
            entitlements_index = next(
                (index for index in super_blob.index if index.type == CSSlot.CSSLOT_ENTITLEMENTS),
                None,
            )
            if not entitlements_index:
                return None

            # Read the entitlements blob
            content = cs.content
            ent_offset = entitlements_index.offset
            ent_data = content[ent_offset:]
            magic = int.from_bytes(ent_data[0:4], byteorder="big")  # magic, we don't need it
            entitlements_length = int.from_bytes(ent_data[4:8], byteorder="big")

            logger.debug(f"Entitlements magic: 0x{magic:08x}, length: {entitlements_length}")

            # Extract the entitlements plist (skip the 8-byte header)
            entitlements_start = ent_offset + 8
            entitlements_end = ent_offset + entitlements_length
            entitlements_bytes = bytes(content[entitlements_start:entitlements_end])

            # Convert to string
            entitlements_plist = entitlements_bytes.decode("utf-8")

            # Calculate CD hash for the entire blob
            blob_data = content[ent_offset : ent_offset + entitlements_length]
            hash_algorithm = "sha1" if hash_type == CSAlgorithm.SHA1 else "sha256"
            cd_hash = hashlib.new(hash_algorithm, blob_data).hexdigest()

            return Entitlements(entitlements_plist=entitlements_plist, cd_hash=cd_hash)

        except Exception as e:
            logger.error(f"Failed to parse entitlements: {e}")
            return None

    def _parse_requirements(
        self, super_blob: CSSuperBlob, cs: CodeSignature, hash_type: CSAlgorithm
    ) -> Optional[Requirements]:
        """Parse the requirements from the super blob."""
        try:
            requirements_index = next(
                (index for index in super_blob.index if index.type == CSSlot.CSSLOT_REQUIREMENTS),
                None,
            )
            if not requirements_index:
                return None

            # Read the requirements blob
            content = cs.content
            req_offset = requirements_index.offset

            req_data = content[req_offset:]
            magic = int.from_bytes(req_data[0:4], byteorder="big")  # magic
            req_length = int.from_bytes(req_data[4:8], byteorder="big")

            logger.debug(f"Requirements magic: 0x{magic:08x}, length: {req_length}")
            requirements_start = req_offset
            requirements_end = req_offset + req_length
            requirements_bytes = bytes(content[requirements_start:requirements_end])

            # Calculate CD hash for the entire blob
            hash_algorithm = "sha1" if hash_type == CSAlgorithm.SHA1 else "sha256"
            cd_hash = hashlib.new(hash_algorithm, requirements_bytes).hexdigest()

            return Requirements(requirements=requirements_bytes, cd_hash=cd_hash)

        except Exception as e:
            logger.error(f"Failed to parse requirements: {e}")
            return None

    def _parse_der_entitlements(
        self, super_blob: CSSuperBlob, cs: CodeSignature, hash_type: CSAlgorithm
    ) -> Optional[DEREntitlements]:
        """Parse the DER entitlements from the super blob."""
        try:
            der_index = next(
                (index for index in super_blob.index if index.type == CSSlot.CSSLOT_DER_ENTITLEMENTS),
                None,
            )
            if not der_index:
                return None

            # Read the DER entitlements blob
            content = cs.content
            der_offset = der_index.offset

            der_data = content[der_offset:]
            magic = int.from_bytes(der_data[0:4], byteorder="big")  # magic, we don't need it
            der_length = int.from_bytes(der_data[4:8], byteorder="big")

            logger.debug(f"DER entitlements magic: 0x{magic:08x}, length: {der_length}")

            # Extract the DER data (skip the 8-byte header)
            der_start = der_offset + 8
            der_end = der_offset + der_length
            der_bytes = bytes(content[der_start:der_end])

            # Calculate CD hash for the entire blob
            blob_data = bytes(content[der_offset : der_offset + der_length])
            hash_algorithm = "sha1" if hash_type == CSAlgorithm.SHA1 else "sha256"
            cd_hash = hashlib.new(hash_algorithm, blob_data).hexdigest()

            return DEREntitlements(der_data=der_bytes, cd_hash=cd_hash)

        except Exception as e:
            logger.error(f"Failed to parse DER entitlements: {e}")
            return None

    def _parse_signature(self, super_blob: CSSuperBlob, cs: CodeSignature) -> CMSSigning | None:
        """Parse the CMS signature from the super blob."""
        try:
            signature_index = next(
                (index for index in super_blob.index if index.type == CSSlot.CSSLOT_SIGNATURESLOT),
                None,
            )
            if not signature_index:
                return None

            # Read the signature blob
            content = cs.content
            sig_offset = signature_index.offset

            sig_data = content[sig_offset:]
            magic = int.from_bytes(sig_data[0:4], byteorder="big")  # magic
            signature_length = int.from_bytes(sig_data[4:8], byteorder="big")

            logger.debug(f"Signature magic: 0x{magic:08x}, length: {signature_length}")

            # Extract the signature content (skip the 8-byte header)
            sig_start = sig_offset + 8
            sig_end = sig_offset + signature_length
            signature_content = bytes(content[sig_start:sig_end])

            # Parse the CMS signature
            try:
                signature = cms.ContentInfo.load(signature_content)  # type: ignore[attr-defined]
            except Exception as e:
                logger.error(f"Failed to parse CMS signature: {e}")
                return None

            cd_hashes: List[Dict[str, Union[CSAlgorithm, str]]] = []
            certificates: List[bytes] = []

            # Check if this is a SignedData content type
            if signature["content_type"].native == "signed_data":  # type: ignore[attr-defined]
                signed_data = signature["content"]  # type: ignore[attr-defined]

                # Extract certificates
                if "certificates" in signed_data:
                    for cert in signed_data["certificates"]:  # type: ignore[attr-defined]
                        certificates.append(cert.dump())  # type: ignore[attr-defined]

                # Extract CD hashes from signed attributes
                for signer_info in signed_data["signer_infos"]:  # type: ignore[attr-defined]
                    if "signed_attrs" in signer_info:
                        for attr in signer_info["signed_attrs"]:  # type: ignore[attr-defined]
                            attr_type = attr["type"].native  # type: ignore[attr-defined]

                            # CDHash attribute type: 1.2.840.113635.100.9.2
                            if attr_type == "1.2.840.113635.100.9.2":
                                for value in attr["values"]:  # type: ignore[attr-defined]
                                    try:
                                        # Access the parsed value directly
                                        hash_block = value.native  # type: ignore[attr-defined]

                                        # The hash_block is an OrderedDict with hash_oid and hash_value
                                        if isinstance(hash_block, dict):
                                            # Get the hash algorithm OID and hash value from the dict
                                            hash_oid = hash_block.get("0", "")  # type: ignore[attr-defined]
                                            hash_value = hash_block.get("1", "").hex()  # type: ignore[attr-defined]

                                            # Determine hash type based on OID
                                            if hash_oid == "2.16.840.1.101.3.4.2.1":  # SHA-256
                                                hash_type = CSAlgorithm.SHA256
                                            else:  # Default to SHA-1
                                                hash_type = CSAlgorithm.SHA1

                                            cd_hashes.append({"type": hash_type, "value": hash_value})

                                    except Exception as e:
                                        logger.error(f"Failed to parse CD hash value: {e}")
                                        continue

            return CMSSigning(cd_hashes=cd_hashes, certificates=certificates)

        except Exception as e:
            logger.error(f"Failed to parse signature: {e}")
            return None
