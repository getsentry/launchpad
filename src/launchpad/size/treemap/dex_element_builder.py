from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from launchpad.parsers.android.dex.types import ClassDefinition
from launchpad.size.models.common import FileInfo
from launchpad.size.models.treemap import TreemapElement, TreemapType
from launchpad.size.treemap.treemap_element_builder import TreemapElementBuilder
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


class DexElementBuilder(TreemapElementBuilder):
    def __init__(
        self,
        download_compression_ratio: float,
        filesystem_block_size: int | None = None,
        class_definitions: list[ClassDefinition] | None = None,
    ) -> None:
        super().__init__(
            download_compression_ratio=download_compression_ratio,
            filesystem_block_size=filesystem_block_size,
        )
        self.class_definitions = class_definitions or []

    def build_element(self, file_info: FileInfo, display_name: str) -> TreemapElement | None:
        # Skips using the file_info.path and leverages the class_definitions
        # to build the treemap. This is because there could be multiple
        # DEX files in APK and we want to group them by package vs file.

        install_size = file_info.size
        download_size = int(install_size * self.download_compression_ratio)

        package_classes = self._group_classes_by_package()

        package_elements: list[TreemapElement] = []
        for package_name, classes in package_classes.items():
            package_element = self._create_package_element(package_name, classes)
            package_elements.append(package_element)

        details = {
            "fileExtension": file_info.file_type,
            "class_count": len(self.class_definitions),
        }

        return TreemapElement(
            name=display_name,
            install_size=install_size,
            download_size=download_size,
            element_type=TreemapType.DEX,
            path=file_info.path,
            is_directory=True,
            children=package_elements,
            details=details,
        )

    def _group_classes_by_package(self) -> Dict[str, List[ClassDefinition]]:
        package_classes: Dict[str, List[ClassDefinition]] = defaultdict(list)

        for class_def in self.class_definitions:
            package_name = self._extract_package_name(class_def)
            package_classes[package_name].append(class_def)

        return dict(package_classes)

    def _extract_package_name(self, class_def: ClassDefinition) -> str:
        fqn = class_def.fqn()
        parts = fqn.split(".")
        if len(parts) > 1:
            # Join all parts except the last one (class name)
            return ".".join(parts[:-1])
        else:
            raise ValueError(f"Invalid class definition: {fqn}")

    def _create_package_element(self, package_name: str, classes: List[ClassDefinition]) -> TreemapElement:
        class_elements = []
        total_package_size = 0

        for class_def in classes:
            class_element = self._create_class_element(class_def)
            class_elements.append(class_element)
            total_package_size += class_element.install_size

        download_size = int(total_package_size * self.download_compression_ratio)

        details = {
            "class_count": len(classes),
        }

        return TreemapElement(
            name=package_name,
            install_size=total_package_size,
            download_size=download_size,
            element_type=TreemapType.DEX,
            path=f"{package_name}/",
            is_directory=True,
            children=class_elements,
            details=details,
        )

    def _create_class_element(self, class_def: ClassDefinition) -> TreemapElement:
        class_size = class_def.size
        download_size = int(class_size * self.download_compression_ratio)

        details = {
            "fqn": class_def.fqn(),
            "source_file": class_def.source_file_name,
        }

        return TreemapElement(
            name=class_def.get_name(),
            install_size=class_size,
            download_size=download_size,
            element_type=TreemapType.DEX,
            path=class_def.fqn(),
            is_directory=False,
            children=[],
            details=details,
        )
