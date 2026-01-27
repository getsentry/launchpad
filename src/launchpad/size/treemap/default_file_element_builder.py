import os

from typing import Dict, List

from launchpad.size.models.common import FileInfo
from launchpad.size.models.treemap import TreemapElement, TreemapElementMisc
from launchpad.size.treemap.treemap_element_builder import TreemapElementBuilder
from launchpad.utils.file_utils import to_nearest_block_size


class DefaultFileElementBuilder(TreemapElementBuilder):
    def __init__(
        self,
        filesystem_block_size: int,
        insight_path_map: Dict[str, List[str]] | None = None,
    ) -> None:
        super().__init__(filesystem_block_size=filesystem_block_size)
        self.insight_path_map = insight_path_map or {}

    def build_element(self, file_info: FileInfo, display_name: str) -> TreemapElement:
        size = to_nearest_block_size(file_info.size, self.filesystem_block_size)

        misc = None
        if file_info.scale is not None:
            misc = TreemapElementMisc(scale=file_info.scale)

        flagged = self.insight_path_map.get(file_info.path, [])

        return TreemapElement(
            name=display_name,
            size=size,
            type=file_info.treemap_type,
            path=file_info.path,
            is_dir=False,
            children=[self.build_element(child, os.path.basename(child.path)) for child in file_info.children],
            misc=misc,
            flagged_insights=flagged,
        )
