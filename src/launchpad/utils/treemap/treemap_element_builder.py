from __future__ import annotations

from abc import ABC, abstractmethod

from ...models.common import FileInfo
from ...models.treemap import TreemapElement
from ..logging import get_logger

logger = get_logger(__name__)


class TreemapElementBuilder(ABC):
    def __init__(
        self,
        download_compression_ratio: float,
        filesystem_block_size: int,
    ) -> None:
        self.download_compression_ratio = max(0.0, min(1.0, download_compression_ratio))
        self.filesystem_block_size = filesystem_block_size

    @abstractmethod
    def build_element(self, file_info: FileInfo, display_name: str) -> TreemapElement | None:
        """Build a treemap element for the given file.
        @DefaultFileElementBuilder will be used if `None` returned.

        Args:
            file_info: File information
            display_name: Display name for the element

        Returns:
            Treemap element representing the file, `None` if the file is not supported
        """
        raise NotImplementedError("Not implemented")
