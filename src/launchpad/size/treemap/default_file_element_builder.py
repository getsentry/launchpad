from launchpad.size.models.common import FileInfo
from launchpad.size.models.treemap import TreemapElement
from launchpad.size.treemap.treemap_element_builder import TreemapElementBuilder
from launchpad.utils.file_utils import to_nearest_block_size


class DefaultFileElementBuilder(TreemapElementBuilder):
    def build_element(self, file_info: FileInfo, display_name: str) -> TreemapElement:
        install_size = to_nearest_block_size(file_info.size, self.filesystem_block_size)
        download_size = int(file_info.size * self.download_compression_ratio)

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
            children=list(map(self.build_element, file_info.children, [display_name] * len(file_info.children))),
        )
