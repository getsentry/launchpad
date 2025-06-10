"""Utility functions for artifact analysis."""

from __future__ import annotations

import hashlib
import mimetypes
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from ..models.artifacts import (
    ArtifactCollection,
    ArtifactType,
    BaseArtifact,
    BinaryArtifact,
    CompressionType,
    FrameworkArtifact,
    LocalizationArtifact,
    MetadataArtifact,
    ResourceArtifact,
    ResourceType,
    SizeBreakdown,
)


class ArtifactAnalyzer:
    """Analyzer for categorizing and processing artifacts."""

    # File extension mappings to artifact types
    EXTENSION_TO_TYPE: Dict[str, ArtifactType] = {
        # Binaries
        ".o": ArtifactType.BINARY,
        ".a": ArtifactType.LIBRARY,
        ".so": ArtifactType.LIBRARY,
        ".dylib": ArtifactType.LIBRARY,
        ".dll": ArtifactType.LIBRARY,
        ".exe": ArtifactType.BINARY,
        # Frameworks
        ".framework": ArtifactType.FRAMEWORK,
        ".xcframework": ArtifactType.FRAMEWORK,
        # Resources
        ".png": ArtifactType.RESOURCE,
        ".jpg": ArtifactType.RESOURCE,
        ".jpeg": ArtifactType.RESOURCE,
        ".gif": ArtifactType.RESOURCE,
        ".svg": ArtifactType.RESOURCE,
        ".webp": ArtifactType.RESOURCE,
        ".mp4": ArtifactType.RESOURCE,
        ".mov": ArtifactType.RESOURCE,
        ".mp3": ArtifactType.RESOURCE,
        ".wav": ArtifactType.RESOURCE,
        ".ttf": ArtifactType.RESOURCE,
        ".otf": ArtifactType.RESOURCE,
        ".woff": ArtifactType.RESOURCE,
        ".woff2": ArtifactType.RESOURCE,
        # Localization
        ".strings": ArtifactType.LOCALIZATION,
        ".stringsdict": ArtifactType.LOCALIZATION,
        ".lproj": ArtifactType.LOCALIZATION,
        # Metadata
        ".plist": ArtifactType.METADATA,
        ".json": ArtifactType.METADATA,
        ".xml": ArtifactType.METADATA,
        ".yaml": ArtifactType.METADATA,
        ".yml": ArtifactType.METADATA,
        # Scripts
        ".js": ArtifactType.SCRIPT,
        ".py": ArtifactType.SCRIPT,
        ".sh": ArtifactType.SCRIPT,
        ".rb": ArtifactType.SCRIPT,
    }

    # Resource type mappings
    EXTENSION_TO_RESOURCE_TYPE: Dict[str, ResourceType] = {
        # Images
        ".png": ResourceType.IMAGE,
        ".jpg": ResourceType.IMAGE,
        ".jpeg": ResourceType.IMAGE,
        ".gif": ResourceType.IMAGE,
        ".svg": ResourceType.IMAGE,
        ".webp": ResourceType.IMAGE,
        ".bmp": ResourceType.IMAGE,
        ".ico": ResourceType.IMAGE,
        ".tiff": ResourceType.IMAGE,
        # Videos
        ".mp4": ResourceType.VIDEO,
        ".mov": ResourceType.VIDEO,
        ".avi": ResourceType.VIDEO,
        ".webm": ResourceType.VIDEO,
        ".mkv": ResourceType.VIDEO,
        # Audio
        ".mp3": ResourceType.AUDIO,
        ".wav": ResourceType.AUDIO,
        ".aac": ResourceType.AUDIO,
        ".ogg": ResourceType.AUDIO,
        ".m4a": ResourceType.AUDIO,
        # Fonts
        ".ttf": ResourceType.FONT,
        ".otf": ResourceType.FONT,
        ".woff": ResourceType.FONT,
        ".woff2": ResourceType.FONT,
        # iOS specific
        ".storyboard": ResourceType.STORYBOARD,
        ".xib": ResourceType.XIB,
        ".nib": ResourceType.NIFI,
        # Data formats
        ".plist": ResourceType.PLIST,
        ".json": ResourceType.JSON,
        ".xml": ResourceType.XML,
        ".html": ResourceType.HTML,
        ".css": ResourceType.CSS,
        ".js": ResourceType.JAVASCRIPT,
    }

    @classmethod
    def detect_artifact_type(cls, path: str) -> ArtifactType:
        """Detect artifact type based on file path."""
        path_obj = Path(path)
        
        # Check if it's a framework (directory with .framework extension)
        if path_obj.suffix == ".framework" or path_obj.suffix == ".xcframework":
            return ArtifactType.FRAMEWORK
            
        # Check by extension
        ext = path_obj.suffix.lower()
        return cls.EXTENSION_TO_TYPE.get(ext, ArtifactType.OTHER)

    @classmethod
    def detect_resource_type(cls, path: str) -> ResourceType:
        """Detect resource type based on file path."""
        path_obj = Path(path)
        ext = path_obj.suffix.lower()
        return cls.EXTENSION_TO_RESOURCE_TYPE.get(ext, ResourceType.OTHER)

    @classmethod
    def detect_compression(cls, data: bytes) -> CompressionType:
        """Detect compression type from file data."""
        if len(data) < 4:
            return CompressionType.NONE
            
        # Check magic bytes
        if data[:2] == b"\x1f\x8b":  # gzip
            return CompressionType.GZIP
        elif data[:2] == b"\x78\x9c" or data[:2] == b"\x78\x01":  # zlib
            return CompressionType.ZLIB
        elif data[:3] == b"\xfd\x37\x7a":  # xz/lzma
            return CompressionType.LZMA
        elif data[:4] == b"\x28\xb5\x2f\xfd":  # zstd
            return CompressionType.ZSTD
        
        return CompressionType.NONE

    @classmethod
    def calculate_hash(cls, file_path: Union[str, Path], algorithm: str = "sha256") -> str:
        """Calculate hash of a file."""
        hash_obj = hashlib.new(algorithm)
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()

    @classmethod
    def group_artifacts_by_type(cls, artifacts: List[BaseArtifact]) -> ArtifactCollection:
        """Group artifacts into an ArtifactCollection."""
        collection = ArtifactCollection()
        
        for artifact in artifacts:
            if isinstance(artifact, BinaryArtifact):
                collection.binaries.append(artifact)
            elif isinstance(artifact, FrameworkArtifact):
                collection.frameworks.append(artifact)
            elif isinstance(artifact, ResourceArtifact):
                collection.resources.append(artifact)
            elif isinstance(artifact, LocalizationArtifact):
                collection.localizations.append(artifact)
            elif isinstance(artifact, MetadataArtifact):
                collection.metadata.append(artifact)
            else:
                collection.other.append(artifact)
                
        return collection

    @classmethod
    def create_size_breakdown(
        cls,
        artifacts: List[BaseArtifact],
        group_by: str = "type",
        min_percentage: float = 0.1,
    ) -> List[SizeBreakdown]:
        """Create size breakdown from artifacts.
        
        Args:
            artifacts: List of artifacts to analyze
            group_by: How to group artifacts ("type", "extension", "directory")
            min_percentage: Minimum percentage to include in breakdown
            
        Returns:
            List of SizeBreakdown objects
        """
        total_size = sum(a.size for a in artifacts)
        if total_size == 0:
            return []
            
        groups: Dict[str, List[BaseArtifact]] = {}
        
        if group_by == "type":
            for artifact in artifacts:
                key = artifact.artifact_type.value
                groups.setdefault(key, []).append(artifact)
        elif group_by == "extension":
            for artifact in artifacts:
                ext = Path(artifact.path).suffix or "no_extension"
                groups.setdefault(ext, []).append(artifact)
        elif group_by == "directory":
            for artifact in artifacts:
                dir_path = str(Path(artifact.path).parent)
                groups.setdefault(dir_path, []).append(artifact)
                
        breakdowns = []
        for category, items in groups.items():
            size = sum(item.size for item in items)
            percentage = (size / total_size) * 100
            
            if percentage >= min_percentage:
                breakdown = SizeBreakdown(
                    category=category,
                    size=size,
                    percentage=percentage,
                    items=items,
                )
                breakdowns.append(breakdown)
                
        # Sort by size descending
        breakdowns.sort(key=lambda x: x.size, reverse=True)
        
        # Add "Other" category for small items
        other_items = []
        other_size = 0
        for category, items in groups.items():
            size = sum(item.size for item in items)
            percentage = (size / total_size) * 100
            if percentage < min_percentage:
                other_items.extend(items)
                other_size += size
                
        if other_items:
            other_percentage = (other_size / total_size) * 100
            breakdowns.append(
                SizeBreakdown(
                    category="Other",
                    size=other_size,
                    percentage=other_percentage,
                    items=other_items,
                )
            )
            
        return breakdowns

    @classmethod
    def find_duplicate_artifacts(
        cls,
        artifacts: List[BaseArtifact],
        by_hash: bool = True,
    ) -> List[List[BaseArtifact]]:
        """Find duplicate artifacts.
        
        Args:
            artifacts: List of artifacts to check
            by_hash: If True, compare by hash; otherwise by size and name
            
        Returns:
            List of duplicate groups
        """
        duplicates: Dict[str, List[BaseArtifact]] = {}
        
        for artifact in artifacts:
            if by_hash and artifact.hash_sha256:
                key = artifact.hash_sha256
            else:
                # Use size and filename as key
                filename = Path(artifact.path).name
                key = f"{artifact.size}:{filename}"
                
            duplicates.setdefault(key, []).append(artifact)
            
        # Return only groups with duplicates
        return [group for group in duplicates.values() if len(group) > 1]

    @classmethod
    def estimate_download_size(
        cls,
        artifacts: List[BaseArtifact],
        compression_ratio: float = 0.3,
    ) -> int:
        """Estimate download size for artifacts.
        
        Args:
            artifacts: List of artifacts
            compression_ratio: Estimated compression ratio (default 0.3 = 70% compression)
            
        Returns:
            Estimated download size in bytes
        """
        total_size = 0
        
        for artifact in artifacts:
            if artifact.compressed_size:
                # Use actual compressed size if available
                total_size += artifact.compressed_size
            elif artifact.compression != CompressionType.NONE:
                # Already compressed, use as is
                total_size += artifact.size
            else:
                # Apply estimated compression
                total_size += int(artifact.size * (1 - compression_ratio))
                
        return total_size