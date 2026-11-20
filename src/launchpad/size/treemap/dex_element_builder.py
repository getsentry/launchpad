from __future__ import annotations

from launchpad.parsers.android.dex.types import ClassDefinition
from launchpad.size.models.common import FileInfo
from launchpad.size.models.treemap import TreemapElement, TreemapType
from launchpad.size.treemap.android_known_libraries import resolve_known_library
from launchpad.size.treemap.treemap_element_builder import TreemapElementBuilder
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)

LIBRARIES_NODE_NAME = "Libraries"


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

        children = self._build_children()
        size = sum(child.size for child in children)

        return TreemapElement(
            name=display_name,
            size=size,
            type=TreemapType.DEX,
            path=file_info.path,
            is_dir=True,
            children=children,
        )

    def _build_children(self) -> list[TreemapElement]:
        """Partition classes into known third-party libraries and first-party code.

        Recognized library classes are grouped under a single ``Libraries`` node
        (keyed by canonical library name, with the matched package prefix stripped
        from the nested hierarchy). Everything else keeps its normal package tree.
        Sizes are preserved since each class is placed exactly once.
        """
        # library name -> list of (package_parts, class_name, class_def) with the
        # matched library prefix stripped from the package path.
        library_entries: dict[str, list[tuple[list[str], str, ClassDefinition]]] = {}
        first_party: list[ClassDefinition] = []

        for class_def in self.class_definitions:
            fqn = class_def.fqn()
            match = resolve_known_library(fqn)
            if match is None:
                first_party.append(class_def)
                continue

            library_name, matched_prefix = match
            remainder = fqn[len(matched_prefix) + 1 :] if fqn.startswith(matched_prefix + ".") else ""
            parts = remainder.split(".") if remainder else []
            package_parts = parts[:-1]
            class_name = parts[-1] if parts else class_def.get_name()
            library_entries.setdefault(library_name, []).append((package_parts, class_name, class_def))

        children = self._build_package_elements(first_party)

        libraries_node = self._build_libraries_node(library_entries)
        if libraries_node is not None:
            children.insert(0, libraries_node)

        return children

    def _build_package_elements(self, class_definitions: list[ClassDefinition]) -> list[TreemapElement]:
        """Build the package hierarchy for a set of classes keyed by their FQN."""
        root = self._new_node()

        for class_def in class_definitions:
            fqn = class_def.fqn()
            parts = fqn.split(".")

            if len(parts) < 2:
                logger.warning(f"Invalid class definition with no package: {fqn}")
                continue

            self._insert_class(root, parts[:-1], parts[-1], class_def)

        return self._node_to_elements(root)

    def _build_libraries_node(
        self,
        library_entries: dict[str, list[tuple[list[str], str, ClassDefinition]]],
    ) -> TreemapElement | None:
        if not library_entries:
            return None

        library_children: list[TreemapElement] = []
        for library_name, entries in library_entries.items():
            root = self._new_node()
            for package_parts, class_name, class_def in entries:
                self._insert_class(root, package_parts, class_name, class_def)

            children = self._node_to_elements(root, parent_path=library_name)
            library_children.append(
                TreemapElement(
                    name=library_name,
                    size=sum(child.size for child in children),
                    type=TreemapType.DEX,
                    path=library_name,
                    is_dir=True,
                    children=children,
                )
            )

        library_children.sort(key=lambda child: child.size, reverse=True)

        return TreemapElement(
            name=LIBRARIES_NODE_NAME,
            size=sum(child.size for child in library_children),
            type=TreemapType.DEX,
            path=LIBRARIES_NODE_NAME,
            is_dir=True,
            children=library_children,
        )

    @staticmethod
    def _new_node() -> dict:
        return {"packages": {}, "classes": {}}

    def _insert_class(
        self,
        root: dict,
        package_parts: list[str],
        class_name: str,
        class_def: ClassDefinition,
    ) -> None:
        node = root
        for part in package_parts:
            node = node["packages"].setdefault(part, self._new_node())
        node["classes"][class_name] = class_def

    def _node_to_elements(self, node: dict, parent_path: str = "") -> list[TreemapElement]:
        elements: list[TreemapElement] = []

        for name, child_node in node["packages"].items():
            package_path = f"{parent_path}.{name}" if parent_path else name
            children = self._node_to_elements(child_node, package_path)
            elements.append(
                TreemapElement(
                    name=name,
                    size=sum(child.size for child in children),
                    type=TreemapType.DEX,
                    path=package_path,
                    is_dir=True,
                    children=children,
                )
            )

        for class_def in node["classes"].values():
            elements.append(self._create_class_element(class_def))

        return elements

    def _create_class_element(self, class_def: ClassDefinition) -> TreemapElement:
        return TreemapElement(
            name=class_def.get_name(),
            size=class_def.size,
            type=TreemapType.DEX,
            path=class_def.fqn(),
            is_dir=False,
            children=[],
        )
