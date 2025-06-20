from ...models.common import FileInfo
from ...models.treemap import TreemapElement
from ...utils.file_utils import calculate_aligned_install_size
from .element_builder import TreemapElementBuilder


class DefaultFileElementBuilder(TreemapElementBuilder):
    def build_element(self, file_info: FileInfo, display_name: str) -> TreemapElement:
        install_size = calculate_aligned_install_size(file_info, self.filesystem_block_size)
        download_size = int(install_size * self.download_compression_ratio)

        details: dict[str, object] = {
            "hash": file_info.hash_md5,  # File hash for deduplication
        }

        # Add file extension only for actual files (not binary subsections)
        if file_info.file_type and file_info.file_type != "unknown":
            details["fileExtension"] = file_info.file_type

        return TreemapElement(
            name=display_name,
            install_size=install_size,
            download_size=download_size,
            element_type=file_info.treemap_type,
            path=file_info.path,
            is_directory=False,
            details=details,
        )
