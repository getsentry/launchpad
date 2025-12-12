import os

from launchpad.size.models.common import FileInfo
from launchpad.size.models.treemap import TreemapElement, TreemapElementMisc
from launchpad.size.treemap.treemap_element_builder import TreemapElementBuilder
from launchpad.utils.file_utils import to_nearest_block_size


class DefaultFileElementBuilder(TreemapElementBuilder):
    def build_element(self, file_info: FileInfo, display_name: str) -> TreemapElement:
        size = to_nearest_block_size(file_info.size, self.filesystem_block_size)

        misc = None
        if file_info.scale is not None:
            misc = TreemapElementMisc(scale=file_info.scale)

        return TreemapElement(
            name=display_name,
            size=size,
            type=file_info.treemap_type,
            path=file_info.path,
            is_dir=False,
            children=[self.build_element(child, os.path.basename(child.path)) for child in file_info.children],
            misc=misc,
        )
