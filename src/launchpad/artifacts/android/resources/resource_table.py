from dataclasses import dataclass
from typing import Optional

# Default package id for app package is 0x7f
DEFAULT_PACKAGE_ID = 0x7F


@dataclass(frozen=True)
class ResourceTable:
    """Interface for resource table implementations."""

    def get_value_by_key(self, key: str, locale: Optional[str] = None) -> Optional[str]:
        """Get a resource value by its key and optional locale."""
        raise NotImplementedError()

    def get_value_by_id(self, id_val: int) -> Optional[str]:
        """Get a resource value by its ID."""
        raise NotImplementedError()
