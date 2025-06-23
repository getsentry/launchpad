"""Mach-O binary parser using LIEF."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import IntEnum
from typing import Dict, List, Optional, Union

import lief
from asn1crypto import cms  # type: ignore
from lief.MachO import CodeSignature

from ...utils.logging import get_logger

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
class SwiftProtocolConformance:
    """Swift protocol conformance information."""

    protocol_descriptor: int
    conformance_flags: int
    nominal_type_descriptor: int
    protocol_witness_table: int


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


class MachOParser:
    """Parser for Mach-O binaries using LIEF."""

    def __init__(self, binary: lief.MachO.Binary) -> None:
        """Initialize the parser with a LIEF binary object."""
        self.binary = binary

    def extract_architectures(self) -> List[str]:
        """Extract CPU architectures from the binary."""
        return [str(self.binary.header.cpu_type)]

    def extract_linked_libraries(self) -> List[str]:
        """Extract linked dynamic libraries from the binary."""
        return [str(lib.name) for lib in self.binary.libraries]

    def extract_sections(self) -> Dict[str, int]:
        """Extract binary sections and their sizes."""
        return {str(section.name): section.size for section in self.binary.sections}

    def extract_swift_sections(self) -> List[lief.Section]:
        """Get Swift sections from the binary."""
        return [section for section in self.binary.sections if "swift" in str(section.name).lower()]

    def get_header_size(self) -> int:
        """Get the size of the Mach-O header."""
        # Mach-O header is typically at the beginning
        # Size varies by architecture but 32 bytes is common for 64-bit
        header_size = 32
        # TODO: implement proper header size, seems hard to do with LIEF
        return header_size

    def _cpu_type_to_string(self, cpu_type: int) -> str | None:
        """Convert LIEF CPU type to string representation."""
        # Common CPU types from Mach-O
        cpu_types = {
            0x0000000C: "arm",  # ARM
            0x0100000C: "arm64",  # ARM64
            0x00000007: "x86",  # i386
            0x01000007: "x86_64",  # x86_64
        }
        return cpu_types.get(cpu_type)

    def get_section_bytes_at_offset(self, section_name: str, offset: int, size: int) -> bytes | None:
        """Get specific bytes from a section at a given offset.

        Args:
            section_name: Name of the section
            offset: Offset within the section
            size: Number of bytes to read

        Returns:
            Raw bytes at the specified offset, or None if not found
        """
        try:
            content = self.get_section_bytes(section_name)
            if content is None:
                return None

            if offset + size > len(content):
                logger.warning(f"Requested range {offset}:{offset+size} exceeds section size {len(content)}")
                return None

            return content[offset : offset + size]

        except Exception as e:
            logger.debug(f"Failed to get section bytes at offset for {section_name}: {e}")
            return None

    def get_section_bytes(self, section_name: str) -> bytes | None:
        """Get raw bytes content of a specific section.

        Args:
            section_name: Name of the section to retrieve

        Returns:
            Raw bytes of the section content, or None if section not found
        """
        try:
            if not hasattr(self.binary, "sections"):
                return None

            for section in self.binary.sections:
                if hasattr(section, "name") and section.name == section_name:
                    if hasattr(section, "content"):
                        content = section.content
                        return bytes(content)

            logger.debug(f"Section {section_name} not found")
            return None

        except Exception as e:
            logger.debug(f"Failed to get section content for {section_name}: {e}")
            return None

    def is_encrypted(self) -> bool:
        """Check if the Mach-O binary is encrypted.

        Returns:
            True if the binary is encrypted, False otherwise
        """
        try:
            # Check if the binary has encryption info
            if not self.binary.has_encryption_info:
                return False

            # If encryption_info exists and crypt_id is non-zero, the binary is encrypted
            return bool(self.binary.encryption_info.crypt_id)
        except Exception as e:
            logger.debug(f"Failed to check encryption status: {e}")
            return False

    def parse_swift_protocol_conformances(self) -> List[str]:
        """Parse the Swift protocol section."""
        swift_sections = self.extract_swift_sections()
        swift_proto_section = None
        for section in swift_sections:
            if section.name == "__swift5_proto":
                swift_proto_section = section
                break

        if swift_proto_section is None:
            return []

        swift_proto = self.get_section_bytes(str(swift_proto_section.name))
        if swift_proto is None:
            return []

        # The Swift proto section contains a list of offsets to protocol conformance descriptors
        # Each offset is a relative pointer that needs to be added to the base offset
        proto_offsets: List[tuple[int, int]] = []
        for i in range(0, len(swift_proto), 4):
            if i + 4 <= len(swift_proto):
                relative_pointer = int.from_bytes(swift_proto[i : i + 4], byteorder="little", signed=True)
                proto_offsets.append((i + swift_proto_section.offset, relative_pointer))

        # Parse the protocol conformance descriptors
        protocol_names: List[str] = []
        for base_offset, relative_pointer in proto_offsets:
            # Calculate the actual file address by adding relative pointer to base offset
            type_file_address = relative_pointer + base_offset

            protocol_data = self._parse_swift_protocol_conformance(type_file_address)
            if protocol_data:
                # For now, just add a placeholder since we're not extracting protocol names yet
                protocol_names.append(f"protocol_{protocol_data.protocol_descriptor:x}")

        return protocol_names

    def _parse_swift_protocol_conformance(self, offset: int) -> SwiftProtocolConformance | None:
        protocol_descriptor, bytes_read = self._read_indirect_pointer(offset)
        offset += bytes_read

        # Read conformance_flags from the binary using virtual address
        vm_address_result = self.binary.offset_to_virtual_address(offset)
        if isinstance(vm_address_result, lief.lief_errors):
            logger.debug(f"Failed to convert offset {offset} to virtual address: {vm_address_result}")
            return None
        vm_address = vm_address_result
        conformance_flags = self.binary.get_int_from_virtual_address(vm_address, 4, lief.Binary.VA_TYPES.AUTO)
        if conformance_flags is None:
            logger.debug(f"Failed to read conformance_flags at offset {offset}")
            return None

        offset += 4

        # Read nominal_type_descriptor from the binary using virtual address
        vm_address_result = self.binary.offset_to_virtual_address(offset)
        if isinstance(vm_address_result, lief.lief_errors):
            logger.debug(f"Failed to convert offset {offset} to virtual address: {vm_address_result}")
            return None
        vm_address = vm_address_result
        nominal_type_descriptor = self.binary.get_int_from_virtual_address(vm_address, 4, lief.Binary.VA_TYPES.AUTO)
        if nominal_type_descriptor is None:
            logger.debug(f"Failed to read nominal_type_descriptor at offset {offset}")
            return None

        offset += 4

        # Read protocol_witness_table from the binary using virtual address
        vm_address_result = self.binary.offset_to_virtual_address(offset)
        if isinstance(vm_address_result, lief.lief_errors):
            logger.debug(f"Failed to convert offset {offset} to virtual address: {vm_address_result}")
            return None
        vm_address = vm_address_result
        protocol_witness_table = self.binary.get_int_from_virtual_address(vm_address, 4, lief.Binary.VA_TYPES.AUTO)
        if protocol_witness_table is None:
            logger.debug(f"Failed to read protocol_witness_table at offset {offset}")
            return None

        return SwiftProtocolConformance(
            protocol_descriptor=protocol_descriptor,
            conformance_flags=conformance_flags,
            nominal_type_descriptor=nominal_type_descriptor,
            protocol_witness_table=protocol_witness_table,
        )

    def _read_indirect_pointer(self, offset: int) -> tuple[int, int]:
        vm_address_result = self.binary.offset_to_virtual_address(offset)

        # Handle the union type - check if it's an error
        if isinstance(vm_address_result, lief.lief_errors):
            logger.debug(f"Failed to convert offset {offset} to virtual address: {vm_address_result}")
            return (0, 4)  # Return 0 as fallback for error cases, consumed 4 bytes

        vm_address = vm_address_result
        indirect_offset = self.binary.get_int_from_virtual_address(vm_address, 4, lief.Binary.VA_TYPES.AUTO)
        if indirect_offset is None:
            logger.debug(f"Failed to convert offset {offset} to virtual address: {indirect_offset}")
            return (0, 4)  # Return 0 as fallback for error cases, consumed 4 bytes

        if indirect_offset % 2 == 1:
            contents = self.binary.get_content_from_virtual_address(
                vm_address + (indirect_offset & ~0x1), 8, lief.Binary.VA_TYPES.AUTO
            )
            return (int.from_bytes(contents, byteorder="little"), 4)  # Consumed 4 bytes
        else:
            return (vm_address + indirect_offset, 4)  # Consumed 4 bytes

    def _get_absolute_file_address(self, offset: int) -> int | None:
        # TODO: make more efficient
        for load_command in self.binary.commands:
            if offset >= load_command.command_offset and offset < load_command.command_offset + load_command.size:
                return None

            if isinstance(load_command, lief.MachO.SegmentCommand):
                for section in load_command.sections:
                    if offset >= section.offset and offset < section.offset + section.size:
                        return section.offset + (offset - section.virtual_address)

        return None

    def _parse_code_signature_command(self, cs: CodeSignature) -> Optional[CSSuperBlob]:
        """Parse the code signature command and extract super blob information.

        Returns:
            Tuple of (CSSuperBlob, base_offset) or None if not found
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
                (index for index in super_blob.index if index.type == CSSlot.CSSLOT_ALTERNATE_CODEDIRECTORIES), None
            )
            if not code_directory_index:
                code_directory_index = next(
                    (index for index in super_blob.index if index.type == CSSlot.CSSLOT_CODEDIRECTORY), None
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
                    code_limit64 = int.from_bytes(cd_data[current_offset + 4 : current_offset + 12], byteorder="little")
                    current_offset += 12

            if version >= 0x20400:
                if current_offset + 24 <= len(cd_data):
                    exec_seg_base = int.from_bytes(cd_data[current_offset : current_offset + 8], byteorder="little")
                    exec_seg_limit = int.from_bytes(
                        cd_data[current_offset + 8 : current_offset + 16], byteorder="little"
                    )
                    exec_seg_flags = int.from_bytes(
                        cd_data[current_offset + 16 : current_offset + 24], byteorder="little"
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
                identity = str(content[identity_offset:end_offset], "utf8")

            # Read team ID (if available)
            team_id = None
            if version >= 0x20200 and team_offset > 0:
                team_id_offset = cd_offset + team_offset
                if team_id_offset < len(content):
                    # Read null-terminated string
                    end_offset = team_id_offset
                    while end_offset < len(content) and content[end_offset] != 0:
                        end_offset += 1
                    team_id = str(content[team_id_offset:end_offset], "utf8")

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
                (index for index in super_blob.index if index.type == CSSlot.CSSLOT_ENTITLEMENTS), None
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
            entitlements_bytes = content[entitlements_start:entitlements_end]

            # Convert to string
            entitlements_plist = str(entitlements_bytes, "utf8")

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
                (index for index in super_blob.index if index.type == CSSlot.CSSLOT_REQUIREMENTS), None
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
                (index for index in super_blob.index if index.type == CSSlot.CSSLOT_DER_ENTITLEMENTS), None
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

    def _parse_signature(self, super_blob: CSSuperBlob, cs: CodeSignature) -> Optional[CMSSigning]:
        """Parse the CMS signature from the super blob."""
        try:
            signature_index = next(
                (index for index in super_blob.index if index.type == CSSlot.CSSLOT_SIGNATURESLOT), None
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
                signature = cms.ContentInfo.load(signature_content)
            except Exception as e:
                logger.error(f"Failed to parse CMS signature: {e}")
                return None

            cd_hashes: List[Dict[str, Union[CSAlgorithm, str]]] = []
            certificates: List[bytes] = []

            # Check if this is a SignedData content type
            if signature["content_type"].native == "signed_data":
                signed_data = signature["content"]

                # Extract certificates
                if "certificates" in signed_data:
                    for cert in signed_data["certificates"]:
                        certificates.append(cert.dump())

                # Extract CD hashes from signed attributes
                for signer_info in signed_data["signer_infos"]:
                    if "signed_attrs" in signer_info:
                        for attr in signer_info["signed_attrs"]:
                            attr_type = attr["type"].native

                            # CDHash attribute type: 1.2.840.113635.100.9.2
                            if attr_type == "1.2.840.113635.100.9.2":
                                for value in attr["values"]:
                                    try:
                                        # Access the parsed value directly
                                        hash_block = value.native

                                        # The hash_block is an OrderedDict with hash_oid and hash_value
                                        if isinstance(hash_block, dict):
                                            # Get the hash algorithm OID and hash value from the dict
                                            hash_oid = hash_block.get("0", "")
                                            hash_value = hash_block.get("1", "").hex()

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
