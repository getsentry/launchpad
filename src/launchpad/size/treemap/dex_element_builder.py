from __future__ import annotations

from launchpad.parsers.android.dex.types import ClassDefinition
from launchpad.size.models.common import FileInfo
from launchpad.size.models.treemap import TreemapElement, TreemapType
from launchpad.size.treemap.treemap_element_builder import TreemapElementBuilder
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


class DexElementBuilder(TreemapElementBuilder):
    def __init__(
        self,
        filesystem_block_size: int | None = None,
        class_definitions: list[ClassDefinition] | None = None,
    ) -> None:
        super().__init__(
            filesystem_block_size=filesystem_block_size,
        )
        self.class_definitions = class_definitions or []

    def build_element(self, file_info: FileInfo, display_name: str) -> TreemapElement | None:
        # Skips using the file_info.path and leverages the class_definitions
        # to build the treemap. This is because there could be multiple
        # DEX files in APK and we want to group them by package vs file.

        size = file_info.size

        root_packages = self._build_package_tree()

        return TreemapElement(
            name=display_name,
            size=size,
            type=TreemapType.DEX,
            path=file_info.path,
            is_dir=True,
            children=root_packages,
        )

    def _build_package_tree(self) -> list[TreemapElement]:
        package_tree: dict[str, dict] = {}

        for class_def in self.class_definitions:
            fqn = class_def.fqn()
            parts = fqn.split(".")

            if len(parts) < 2:
                logger.warning(f"Invalid class definition with no package: {fqn}")
                continue

            class_name = parts[-1]
            package_parts = parts[:-1]

            # Build the package hierarchy
            current_level = package_tree
            for package_part in package_parts:
                if package_part not in current_level:
                    current_level[package_part] = {"packages": {}, "classes": {}}
                current_level = current_level[package_part]["packages"]

            # Add the class to the leaf package
            leaf_package = package_tree
            for package_part in package_parts:
                leaf_package = leaf_package[package_part]["packages"]
            leaf_package[class_name] = {"class_def": class_def}

        return self._convert_tree_to_elements(package_tree)

    def _convert_tree_to_elements(self, package_tree: dict[str, dict], parent_path: str = "") -> list[TreemapElement]:
        elements: list[TreemapElement] = []

        for name, node in package_tree.items():
            if "class_def" in node:
                class_def = node["class_def"]
                class_element = self._create_class_element(class_def)
                elements.append(class_element)
            else:
                package_path = f"{parent_path}.{name}" if parent_path else f"{name}"

                # Process children (sub-packages and classes)
                children = self._convert_tree_to_elements(node["packages"], package_path)

                total_size = sum(child.size for child in children)

                elements.append(
                    TreemapElement(
                        name=name,
                        size=total_size,
                        type=TreemapType.DEX,
                        path=package_path,
                        is_dir=True,
                        children=children,
                    )
                )

        return elements

    def _create_class_element(self, class_def: ClassDefinition) -> TreemapElement:
        class_size = class_def.size

        return TreemapElement(
            name=class_def.get_name(),
            size=class_size,
            type=TreemapType.DEX,
            path=class_def.fqn(),
            is_dir=False,
            children=[],
        )
