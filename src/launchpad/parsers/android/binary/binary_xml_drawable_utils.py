from __future__ import annotations

import io
import re
import zipfile

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from PIL import Image, ImageDraw

from launchpad.artifacts.android.resources.binary import BinaryResourceTable
from launchpad.parsers.android.binary.android_binary_parser import AndroidBinaryParser
from launchpad.parsers.android.binary.types import XmlNode
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class VectorAttributes:
    """Attributes for a vector drawable."""

    width: str
    height: str
    viewport_width: str | None = None
    viewport_height: str | None = None
    tint: str | None = None


@dataclass
class PathAttributes:
    """Attributes for a path element in a vector drawable."""

    path_data: str | None = None
    fill_color: str | GradientInfo | None = None
    stroke_color: str | None = None
    stroke_width: str | None = None
    fill_alpha: str | None = None
    stroke_alpha: str | None = None


@dataclass
class GradientItem:
    """A single color stop in a gradient."""

    offset: str | None
    color: str | None


@dataclass
class GradientInfo:
    """Information about a gradient fill."""

    type: str = "linear"
    angle: str | None = None
    start_x: str | None = None
    start_y: str | None = None
    end_x: str | None = None
    end_y: str | None = None
    items: list[GradientItem] | None = None


class BinaryXmlDrawableUtils:
    """Utilities for handling Android binary XML drawables."""

    @staticmethod
    def handle_xml_drawable_from_path(
        xml_file_path: Path,
        extract_dir: Path,
        binary_res_tables: list[BinaryResourceTable],
    ) -> bytes | None:
        """Handle XML drawable from file system path.

        Args:
            xml_file_path: Path to the XML drawable file
            extract_dir: Root directory of extracted APK/AAB
            binary_res_tables: List of resource tables for resolving references

        Returns:
            PNG image data as bytes, or None if rendering fails
        """
        try:
            with open(xml_file_path, "rb") as f:
                vector_buffer = f.read()
            vector_node = AndroidBinaryParser(vector_buffer).parse_xml()
            if not vector_node:
                raise ValueError("Could not load vector drawable XML.")

            if vector_node.node_name == "vector":
                return BinaryXmlDrawableUtils._process_xml_vector_data_from_fs(
                    vector_node, binary_res_tables, extract_dir
                )
            elif vector_node.node_name == "shape":
                return BinaryXmlDrawableUtils._render_shape_to_buffer(vector_node, binary_res_tables)
            else:
                raise ValueError(f"Root is not a vector or shape: {vector_node.node_name}")
        except Exception:
            logger.exception("Error rendering vector drawable")
            return None

    @staticmethod
    def binary_xml_to_adaptive_icon_from_path(
        xml_file_path: Path,
        extract_dir: Path,
        binary_res_tables: list[BinaryResourceTable],
    ) -> bytes | None:
        """Parse binary XML for adaptive icons from file system path.

        Args:
            xml_file_path: Path to the adaptive icon XML file
            extract_dir: Root directory of extracted APK/AAB
            binary_res_tables: List of resource tables

        Returns:
            PNG image data as bytes, or None if rendering fails
        """
        try:
            with open(xml_file_path, "rb") as f:
                buffer = f.read()

            xml_node = AndroidBinaryParser(buffer).parse_xml()
            if not xml_node:
                raise ValueError("Could not load binary XML for adaptive icon.")

            # Find foreground and background nodes
            foreground_node = None
            background_node = None
            for node in xml_node.child_nodes:
                if hasattr(node, "node_name"):
                    if node.node_name == "foreground":
                        foreground_node = node
                    elif node.node_name == "background":
                        background_node = node

            if not foreground_node and not background_node:
                logger.warning("Could not find foreground or background nodes in adaptive icon XML")
                return None

            # Get drawable references
            foreground_attr = None
            background_attr = None
            if foreground_node:
                foreground_attr = next(
                    (attr for attr in foreground_node.attributes if attr.name == "drawable"),
                    None,
                )
            if background_node:
                background_attr = next(
                    (attr for attr in background_node.attributes if attr.name == "drawable"),
                    None,
                )

            if (
                not foreground_attr
                or not foreground_attr.typed_value
                or not background_attr
                or not background_attr.typed_value
            ):
                logger.warning("Missing drawable references in adaptive icon")
                return None

            # Resolve resource paths
            foreground_path = BinaryXmlDrawableUtils._get_resource_from_binary_resource_files(
                foreground_attr.typed_value.value, binary_res_tables
            )
            background_path = BinaryXmlDrawableUtils._get_resource_from_binary_resource_files(
                background_attr.typed_value.value, binary_res_tables
            )

            if not foreground_path and not background_path:
                logger.warning(
                    "Could not resolve resource paths\nforeground ref: %s\nbackground ref: %s",
                    foreground_attr.typed_value.value,
                    background_attr.typed_value.value,
                )
                return None

            return BinaryXmlDrawableUtils._process_adaptive_icon_layers_from_fs(
                foreground_path=foreground_path,
                background_path=background_path,
                extract_dir=extract_dir,
                binary_res_tables=binary_res_tables,
            )
        except Exception:
            logger.exception("Error parsing adaptive icon binary XML")
            return None

    @staticmethod
    def handle_xml_drawable(
        zip_file: zipfile.ZipFile,
        vector_file: zipfile.ZipInfo,
        binary_res_tables: list[BinaryResourceTable],
    ) -> bytes | None:
        """Handle XML drawable (vector or shape).

        Args:
            zip_file: The ZIP archive containing the drawable
            vector_file: The ZipInfo for the drawable file
            binary_res_tables: List of resource tables for resolving references

        Returns:
            PNG image data as bytes, or None if rendering fails
        """
        try:
            vector_buffer = zip_file.read(vector_file.filename)
            vector_node = AndroidBinaryParser(vector_buffer).parse_xml()
            if not vector_node:
                raise ValueError("Could not load vector drawable XML.")

            if vector_node.node_name == "vector":
                return BinaryXmlDrawableUtils._process_xml_vector_data(vector_node, binary_res_tables, zip_file)
            elif vector_node.node_name == "shape":
                return BinaryXmlDrawableUtils._render_shape_to_buffer(vector_node, binary_res_tables)
            else:
                raise ValueError(f"Root is not a vector or shape: {vector_node.node_name}")
        except Exception:
            logger.exception("Error rendering vector drawable")
            return None

    @staticmethod
    def _process_xml_vector_data_from_fs(
        root_element: XmlNode,
        binary_res_tables: list[BinaryResourceTable],
        extract_dir: Path,
    ) -> bytes | None:
        """Process vector drawable XML data from file system.

        Args:
            root_element: The root XML node of the vector drawable
            binary_res_tables: List of resource tables
            extract_dir: Root directory of extracted APK/AAB

        Returns:
            PNG image data as bytes, or None if rendering fails
        """
        try:
            # Extract vector attributes
            width = BinaryXmlDrawableUtils._get_required_attr_value(root_element.attributes, "width", binary_res_tables)
            height = BinaryXmlDrawableUtils._get_required_attr_value(
                root_element.attributes, "height", binary_res_tables
            )
            viewport_width = BinaryXmlDrawableUtils._get_optional_attr_value(
                root_element.attributes, "viewportWidth", binary_res_tables
            )
            viewport_height = BinaryXmlDrawableUtils._get_optional_attr_value(
                root_element.attributes, "viewportHeight", binary_res_tables
            )
            tint = BinaryXmlDrawableUtils._get_optional_attr_value(root_element.attributes, "tint", binary_res_tables)

            vector_attrs = VectorAttributes(
                width=width,
                height=height,
                viewport_width=viewport_width,
                viewport_height=viewport_height,
                tint=tint,
            )

            # Extract path elements
            path_elements: list[PathAttributes] = []
            for node in root_element.child_nodes:
                if not hasattr(node, "node_name") or node.node_name != "path":
                    continue

                path_data = BinaryXmlDrawableUtils._get_optional_attr_value(
                    node.attributes, "pathData", binary_res_tables
                )
                fill_color = BinaryXmlDrawableUtils._get_optional_attr_value(
                    node.attributes, "fillColor", binary_res_tables
                )
                stroke_color = BinaryXmlDrawableUtils._get_optional_attr_value(
                    node.attributes, "strokeColor", binary_res_tables
                )
                stroke_width = BinaryXmlDrawableUtils._get_optional_attr_value(
                    node.attributes, "strokeWidth", binary_res_tables
                )
                fill_alpha = BinaryXmlDrawableUtils._get_optional_attr_value(
                    node.attributes, "fillAlpha", binary_res_tables
                )
                stroke_alpha = BinaryXmlDrawableUtils._get_optional_attr_value(
                    node.attributes, "strokeAlpha", binary_res_tables
                )

                # Handle gradient fills
                fill_color_resolved: str | GradientInfo | None = fill_color
                if fill_color and fill_color.endswith(".xml"):
                    fill_color_resolved = BinaryXmlDrawableUtils._load_gradient_from_xml_fs(
                        extract_dir, fill_color, binary_res_tables
                    )

                path_attrs = PathAttributes(
                    path_data=path_data,
                    fill_color=fill_color_resolved,
                    stroke_color=stroke_color,
                    stroke_width=stroke_width,
                    fill_alpha=fill_alpha,
                    stroke_alpha=stroke_alpha,
                )
                path_elements.append(path_attrs)

            return BinaryXmlDrawableUtils._render_vector_to_buffer(vector_attrs, path_elements)
        except Exception:
            logger.exception("Error rendering vector")
            return None

    @staticmethod
    def _process_xml_vector_data(
        root_element: XmlNode,
        binary_res_tables: list[BinaryResourceTable],
        zip_file: zipfile.ZipFile,
    ) -> bytes | None:
        """Process vector drawable XML data.

        Args:
            root_element: The root XML node of the vector drawable
            binary_res_tables: List of resource tables
            zip_file: The ZIP archive for loading gradient files

        Returns:
            PNG image data as bytes, or None if rendering fails
        """
        try:
            # Extract vector attributes
            width = BinaryXmlDrawableUtils._get_required_attr_value(root_element.attributes, "width", binary_res_tables)
            height = BinaryXmlDrawableUtils._get_required_attr_value(
                root_element.attributes, "height", binary_res_tables
            )
            viewport_width = BinaryXmlDrawableUtils._get_optional_attr_value(
                root_element.attributes, "viewportWidth", binary_res_tables
            )
            viewport_height = BinaryXmlDrawableUtils._get_optional_attr_value(
                root_element.attributes, "viewportHeight", binary_res_tables
            )
            tint = BinaryXmlDrawableUtils._get_optional_attr_value(root_element.attributes, "tint", binary_res_tables)

            vector_attrs = VectorAttributes(
                width=width,
                height=height,
                viewport_width=viewport_width,
                viewport_height=viewport_height,
                tint=tint,
            )

            # Extract path elements
            path_elements: list[PathAttributes] = []
            for node in root_element.child_nodes:
                if not hasattr(node, "node_name") or node.node_name != "path":
                    continue

                path_data = BinaryXmlDrawableUtils._get_optional_attr_value(
                    node.attributes, "pathData", binary_res_tables
                )
                fill_color = BinaryXmlDrawableUtils._get_optional_attr_value(
                    node.attributes, "fillColor", binary_res_tables
                )
                stroke_color = BinaryXmlDrawableUtils._get_optional_attr_value(
                    node.attributes, "strokeColor", binary_res_tables
                )
                stroke_width = BinaryXmlDrawableUtils._get_optional_attr_value(
                    node.attributes, "strokeWidth", binary_res_tables
                )
                fill_alpha = BinaryXmlDrawableUtils._get_optional_attr_value(
                    node.attributes, "fillAlpha", binary_res_tables
                )
                stroke_alpha = BinaryXmlDrawableUtils._get_optional_attr_value(
                    node.attributes, "strokeAlpha", binary_res_tables
                )

                # Handle gradient fills
                fill_color_resolved: str | GradientInfo | None = fill_color
                if fill_color and fill_color.endswith(".xml"):
                    fill_color_resolved = BinaryXmlDrawableUtils._load_gradient_from_xml(
                        zip_file, fill_color, binary_res_tables
                    )

                path_attrs = PathAttributes(
                    path_data=path_data,
                    fill_color=fill_color_resolved,
                    stroke_color=stroke_color,
                    stroke_width=stroke_width,
                    fill_alpha=fill_alpha,
                    stroke_alpha=stroke_alpha,
                )
                path_elements.append(path_attrs)

            return BinaryXmlDrawableUtils._render_vector_to_buffer(vector_attrs, path_elements)
        except Exception:
            logger.exception("Error rendering vector")
            return None

    @staticmethod
    def _load_gradient_from_xml_fs(
        extract_dir: Path,
        gradient_file_name: str,
        binary_res_tables: list[BinaryResourceTable],
    ) -> GradientInfo | None:
        """Load gradient information from an XML file in the file system.

        Args:
            extract_dir: Root directory of extracted APK/AAB
            gradient_file_name: Name of the gradient XML file
            binary_res_tables: List of resource tables

        Returns:
            GradientInfo object, or None if loading fails
        """
        try:
            # Find the gradient file
            gradient_file = BinaryXmlDrawableUtils._find_file_in_fs(extract_dir, gradient_file_name)
            if not gradient_file:
                logger.warning("Could not find gradient file")
                return None

            with open(gradient_file, "rb") as f:
                gradient_file_buffer = f.read()
            gradient_node = AndroidBinaryParser(gradient_file_buffer).parse_xml()
            if not gradient_node:
                raise ValueError("Could not load gradient XML.")

            if gradient_node.node_name != "gradient":
                raise ValueError("Root element is not a gradient.")

            # Extract gradient attributes
            gradient_type = (
                BinaryXmlDrawableUtils._get_optional_attr_value(gradient_node.attributes, "type", binary_res_tables)
                or "linear"
            )
            angle = BinaryXmlDrawableUtils._get_optional_attr_value(
                gradient_node.attributes, "angle", binary_res_tables
            )
            start_x = BinaryXmlDrawableUtils._get_optional_attr_value(
                gradient_node.attributes, "startX", binary_res_tables
            )
            start_y = BinaryXmlDrawableUtils._get_optional_attr_value(
                gradient_node.attributes, "startY", binary_res_tables
            )
            end_x = BinaryXmlDrawableUtils._get_optional_attr_value(gradient_node.attributes, "endX", binary_res_tables)
            end_y = BinaryXmlDrawableUtils._get_optional_attr_value(gradient_node.attributes, "endY", binary_res_tables)

            # Extract gradient items (color stops)
            gradient_items: list[GradientItem] = []
            for child in gradient_node.child_nodes:
                if not hasattr(child, "node_name") or child.node_name != "item":
                    continue

                offset = BinaryXmlDrawableUtils._get_optional_attr_value(child.attributes, "offset", binary_res_tables)
                color = BinaryXmlDrawableUtils._get_optional_attr_value(child.attributes, "color", binary_res_tables)

                if not color:
                    logger.warning("Gradient item missing required attributes, color: %s", color)

                gradient_items.append(GradientItem(offset=offset, color=color))

            if len(gradient_items) < 2:
                logger.warning("Gradient must have at least 2 color stops")
                return None

            return GradientInfo(
                type=gradient_type,
                angle=angle,
                start_x=start_x,
                start_y=start_y,
                end_x=end_x,
                end_y=end_y,
                items=gradient_items,
            )
        except Exception:
            logger.exception("Error parsing gradient XML")
            return None

    @staticmethod
    def _load_gradient_from_xml(
        zip_file: zipfile.ZipFile,
        gradient_file_name: str,
        binary_res_tables: list[BinaryResourceTable],
    ) -> GradientInfo | None:
        """Load gradient information from an XML file.

        Args:
            zip_file: The ZIP archive
            gradient_file_name: Name of the gradient XML file
            binary_res_tables: List of resource tables

        Returns:
            GradientInfo object, or None if loading fails
        """
        try:
            # Find the gradient file in the ZIP
            gradient_file = BinaryXmlDrawableUtils._find_file_in_zip(zip_file, gradient_file_name)
            if not gradient_file:
                logger.warning("Could not find gradient file")
                return None

            gradient_file_buffer = zip_file.read(gradient_file.filename)
            gradient_node = AndroidBinaryParser(gradient_file_buffer).parse_xml()
            if not gradient_node:
                raise ValueError("Could not load gradient XML.")

            if gradient_node.node_name != "gradient":
                raise ValueError("Root element is not a gradient.")

            # Extract gradient attributes
            gradient_type = (
                BinaryXmlDrawableUtils._get_optional_attr_value(gradient_node.attributes, "type", binary_res_tables)
                or "linear"
            )
            angle = BinaryXmlDrawableUtils._get_optional_attr_value(
                gradient_node.attributes, "angle", binary_res_tables
            )
            start_x = BinaryXmlDrawableUtils._get_optional_attr_value(
                gradient_node.attributes, "startX", binary_res_tables
            )
            start_y = BinaryXmlDrawableUtils._get_optional_attr_value(
                gradient_node.attributes, "startY", binary_res_tables
            )
            end_x = BinaryXmlDrawableUtils._get_optional_attr_value(gradient_node.attributes, "endX", binary_res_tables)
            end_y = BinaryXmlDrawableUtils._get_optional_attr_value(gradient_node.attributes, "endY", binary_res_tables)

            # Extract gradient items (color stops)
            gradient_items: list[GradientItem] = []
            for child in gradient_node.child_nodes:
                if not hasattr(child, "node_name") or child.node_name != "item":
                    continue

                offset = BinaryXmlDrawableUtils._get_optional_attr_value(child.attributes, "offset", binary_res_tables)
                color = BinaryXmlDrawableUtils._get_optional_attr_value(child.attributes, "color", binary_res_tables)

                if not color:
                    logger.warning("Gradient item missing required attributes, color: %s", color)

                gradient_items.append(GradientItem(offset=offset, color=color))

            if len(gradient_items) < 2:
                logger.warning("Gradient must have at least 2 color stops")
                return None

            return GradientInfo(
                type=gradient_type,
                angle=angle,
                start_x=start_x,
                start_y=start_y,
                end_x=end_x,
                end_y=end_y,
                items=gradient_items,
            )
        except Exception:
            logger.exception("Error parsing gradient XML")
            return None

    @staticmethod
    def _render_shape_to_buffer(
        shape_node: XmlNode,
        binary_res_tables: list[BinaryResourceTable],
    ) -> bytes | None:
        """Render a shape drawable to a PNG buffer.

        Args:
            shape_node: The shape XML node
            binary_res_tables: List of resource tables

        Returns:
            PNG image data as bytes, or None if rendering fails
        """
        try:
            # Default size for shapes (matching vector drawable size)
            width = 108
            height = 108

            shape_type = BinaryXmlDrawableUtils._get_optional_attr_value(
                shape_node.attributes, "shape", binary_res_tables
            )
            if shape_type != "rectangle":
                logger.info("Only rectangle shapes are currently supported")
                return None

            # Find solid element
            solid_node = None
            for child in shape_node.child_nodes:
                if hasattr(child, "node_name") and child.node_name == "solid":
                    solid_node = child
                    break

            if not solid_node:
                logger.info("No solid element found in shape")
                return None

            color_ref = BinaryXmlDrawableUtils._get_optional_attr_value(
                solid_node.attributes, "color", binary_res_tables
            )
            if not color_ref:
                logger.info("No color attribute found in solid element")
                return None

            color = BinaryXmlDrawableUtils._resolve_color(color_ref)

            # Create image with solid color
            img = Image.new("RGBA", (width, height), color)
            buffer = io.BytesIO()
            img.save(buffer, format="PNG")
            return buffer.getvalue()
        except Exception:
            logger.exception("Error rendering shape drawable")
            return None

    @staticmethod
    def binary_xml_to_adaptive_icon(
        buffer: bytes,
        binary_res_tables: list[BinaryResourceTable],
        zip_file: zipfile.ZipFile,
    ) -> bytes | None:
        """Parse binary XML for adaptive icons.

        Args:
            buffer: Binary XML buffer
            binary_res_tables: List of resource tables
            zip_file: ZIP archive containing the icon layers

        Returns:
            PNG image data as bytes, or None if rendering fails
        """
        try:
            xml_node = AndroidBinaryParser(buffer).parse_xml()
            if not xml_node:
                raise ValueError("Could not load binary XML for adaptive icon.")

            # Find foreground and background nodes
            foreground_node = None
            background_node = None
            for node in xml_node.child_nodes:
                if hasattr(node, "node_name"):
                    if node.node_name == "foreground":
                        foreground_node = node
                    elif node.node_name == "background":
                        background_node = node

            if not foreground_node and not background_node:
                logger.warning("Could not find foreground or background nodes in adaptive icon XML")
                return None

            # Get drawable references
            foreground_attr = None
            background_attr = None
            if foreground_node:
                foreground_attr = next(
                    (attr for attr in foreground_node.attributes if attr.name == "drawable"),
                    None,
                )
            if background_node:
                background_attr = next(
                    (attr for attr in background_node.attributes if attr.name == "drawable"),
                    None,
                )

            if (
                not foreground_attr
                or not foreground_attr.typed_value
                or not background_attr
                or not background_attr.typed_value
            ):
                logger.warning("Missing drawable references in adaptive icon")
                return None

            # Resolve resource paths
            foreground_path = BinaryXmlDrawableUtils._get_resource_from_binary_resource_files(
                foreground_attr.typed_value.value, binary_res_tables
            )
            background_path = BinaryXmlDrawableUtils._get_resource_from_binary_resource_files(
                background_attr.typed_value.value, binary_res_tables
            )

            if not foreground_path and not background_path:
                logger.warning(
                    "Could not resolve resource paths\nforeground ref: %s\nbackground ref: %s",
                    foreground_attr.typed_value.value,
                    background_attr.typed_value.value,
                )
                return None

            return BinaryXmlDrawableUtils._process_adaptive_icon_layers(
                foreground_path=foreground_path,
                background_path=background_path,
                zip_file=zip_file,
                binary_res_tables=binary_res_tables,
            )
        except Exception:
            logger.exception("Error parsing adaptive icon binary XML")
            return None

    @staticmethod
    def _process_adaptive_icon_layers_from_fs(
        foreground_path: str | None,
        background_path: str | None,
        extract_dir: Path,
        binary_res_tables: list[BinaryResourceTable],
    ) -> bytes | None:
        """Process adaptive icon foreground and background layers from file system.

        Args:
            foreground_path: Path to foreground drawable
            background_path: Path to background drawable
            extract_dir: Root directory of extracted APK/AAB
            binary_res_tables: List of resource tables

        Returns:
            PNG image data as bytes, or None if rendering fails
        """
        try:
            # Load background layer
            background_img = None
            if background_path:
                background_file = BinaryXmlDrawableUtils._find_file_in_fs(extract_dir, background_path)
                if background_file:
                    if background_path.endswith(".xml"):
                        background_buffer = BinaryXmlDrawableUtils.handle_xml_drawable_from_path(
                            background_file, extract_dir, binary_res_tables
                        )
                        if background_buffer:
                            background_img = Image.open(io.BytesIO(background_buffer))
                    else:
                        # PNG or other image format
                        with open(background_file, "rb") as f:
                            background_img = Image.open(io.BytesIO(f.read()))

            # Load foreground layer
            foreground_img = None
            if foreground_path:
                foreground_file = BinaryXmlDrawableUtils._find_file_in_fs(extract_dir, foreground_path)
                if foreground_file:
                    if foreground_path.endswith(".xml"):
                        foreground_buffer = BinaryXmlDrawableUtils.handle_xml_drawable_from_path(
                            foreground_file, extract_dir, binary_res_tables
                        )
                        if foreground_buffer:
                            foreground_img = Image.open(io.BytesIO(foreground_buffer))
                    else:
                        # PNG or other image format
                        with open(foreground_file, "rb") as f:
                            foreground_img = Image.open(io.BytesIO(f.read()))

            # Composite the layers
            if not background_img and not foreground_img:
                return None

            # Use standard adaptive icon size (108x108 with 72x72 safe area)
            size = 108
            result = Image.new("RGBA", (size, size), (0, 0, 0, 0))

            if background_img:
                background_img = background_img.resize((size, size), Image.Resampling.LANCZOS)
                result.paste(
                    background_img,
                    (0, 0),
                    background_img if background_img.mode == "RGBA" else None,
                )

            if foreground_img:
                foreground_img = foreground_img.resize((size, size), Image.Resampling.LANCZOS)
                result.paste(
                    foreground_img,
                    (0, 0),
                    foreground_img if foreground_img.mode == "RGBA" else None,
                )

            buffer = io.BytesIO()
            result.save(buffer, format="PNG")
            return buffer.getvalue()
        except Exception:
            logger.exception("Error processing adaptive icon layers")
            return None

    @staticmethod
    def _process_adaptive_icon_layers(
        foreground_path: str | None,
        background_path: str | None,
        zip_file: zipfile.ZipFile,
        binary_res_tables: list[BinaryResourceTable],
    ) -> bytes | None:
        """Process adaptive icon foreground and background layers.

        Args:
            foreground_path: Path to foreground drawable
            background_path: Path to background drawable
            zip_file: ZIP archive
            binary_res_tables: List of resource tables

        Returns:
            PNG image data as bytes, or None if rendering fails
        """
        try:
            # Load background layer
            background_img = None
            if background_path:
                background_file = BinaryXmlDrawableUtils._find_file_in_zip(zip_file, background_path)
                if background_file:
                    if background_path.endswith(".xml"):
                        background_buffer = BinaryXmlDrawableUtils.handle_xml_drawable(
                            zip_file, background_file, binary_res_tables
                        )
                        if background_buffer:
                            background_img = Image.open(io.BytesIO(background_buffer))
                    else:
                        # PNG or other image format
                        background_img = Image.open(io.BytesIO(zip_file.read(background_file.filename)))

            # Load foreground layer
            foreground_img = None
            if foreground_path:
                foreground_file = BinaryXmlDrawableUtils._find_file_in_zip(zip_file, foreground_path)
                if foreground_file:
                    if foreground_path.endswith(".xml"):
                        foreground_buffer = BinaryXmlDrawableUtils.handle_xml_drawable(
                            zip_file, foreground_file, binary_res_tables
                        )
                        if foreground_buffer:
                            foreground_img = Image.open(io.BytesIO(foreground_buffer))
                    else:
                        # PNG or other image format
                        foreground_img = Image.open(io.BytesIO(zip_file.read(foreground_file.filename)))

            # Composite the layers
            if not background_img and not foreground_img:
                return None

            # Use standard adaptive icon size (108x108 with 72x72 safe area)
            size = 108
            result = Image.new("RGBA", (size, size), (0, 0, 0, 0))

            if background_img:
                background_img = background_img.resize((size, size), Image.Resampling.LANCZOS)
                result.paste(
                    background_img,
                    (0, 0),
                    background_img if background_img.mode == "RGBA" else None,
                )

            if foreground_img:
                foreground_img = foreground_img.resize((size, size), Image.Resampling.LANCZOS)
                result.paste(
                    foreground_img,
                    (0, 0),
                    foreground_img if foreground_img.mode == "RGBA" else None,
                )

            buffer = io.BytesIO()
            result.save(buffer, format="PNG")
            return buffer.getvalue()
        except Exception:
            logger.exception("Error processing adaptive icon layers")
            return None

    @staticmethod
    def _render_vector_to_buffer(
        vector_attrs: VectorAttributes,
        path_elements: list[PathAttributes],
    ) -> bytes | None:
        """Render a vector drawable to a PNG buffer.

        Note: This is a simplified implementation that only handles basic rectangles.
        Full SVG path rendering would require a more complete implementation.

        Args:
            vector_attrs: Vector drawable attributes
            path_elements: List of path elements

        Returns:
            PNG image data as bytes, or None if rendering fails
        """
        try:
            # Parse dimensions
            width = BinaryXmlDrawableUtils._parse_dimension(vector_attrs.width)
            height = BinaryXmlDrawableUtils._parse_dimension(vector_attrs.height)

            # Create image
            img = Image.new("RGBA", (width, height), (0, 0, 0, 0))
            draw = ImageDraw.Draw(img)

            # Simplified rendering: just fill with first path's color
            # Full implementation would parse and render SVG paths
            if path_elements and path_elements[0].fill_color:
                fill_color = path_elements[0].fill_color
                if isinstance(fill_color, str):
                    color = BinaryXmlDrawableUtils._resolve_color(fill_color)
                    draw.rectangle([(0, 0), (width, height)], fill=color)

            buffer = io.BytesIO()
            img.save(buffer, format="PNG")
            return buffer.getvalue()
        except Exception:
            logger.exception("Error rendering vector to buffer")
            return None

    # Helper methods

    @staticmethod
    def _get_optional_attr_value(
        attributes: list[Any],
        name: str,
        binary_res_tables: list[BinaryResourceTable],
    ) -> str | None:
        """Get optional attribute value, resolving resource references."""
        attr = next((a for a in attributes if a.name == name), None)
        if not attr:
            return None

        value = attr.value
        if not value and attr.typed_value:
            if attr.typed_value.type == "reference":
                return BinaryXmlDrawableUtils._get_resource_from_binary_resource_files(
                    attr.typed_value.value, binary_res_tables
                )
            elif attr.typed_value.type == "string":
                return str(attr.typed_value.value)
            elif attr.typed_value.type in ["int_dec", "int_hex"]:
                return str(attr.typed_value.value)
            elif attr.typed_value.type == "dimension":
                return f"{attr.typed_value.value.value}{attr.typed_value.value.unit}"
            elif attr.typed_value.type in ["rgb8", "argb8", "rgb4", "argb4"]:
                return attr.typed_value.value

        return value

    @staticmethod
    def _get_required_attr_value(
        attributes: list[Any],
        name: str,
        binary_res_tables: list[BinaryResourceTable],
    ) -> str:
        """Get required attribute value, raising error if not found."""
        value = BinaryXmlDrawableUtils._get_optional_attr_value(attributes, name, binary_res_tables)
        if value is None:
            raise ValueError(f"Missing required attribute: {name}")
        return value

    @staticmethod
    def _get_resource_from_binary_resource_files(
        value: str,
        binary_res_tables: list[BinaryResourceTable],
    ) -> str | None:
        """Get resource value from binary resource tables."""
        for table in binary_res_tables:
            try:
                return table.get_value_by_string_id(value)
            except Exception as e:
                logger.debug("Failed to get value from table: %s", e)
                continue
        return None

    @staticmethod
    def _find_file_in_fs(extract_dir: Path, filename: str) -> Path | None:
        """Find a file in an extracted directory, handling various path formats.

        Args:
            extract_dir: Root directory of extracted APK/AAB
            filename: Filename to find (e.g., "res/drawable/icon.png" or "drawable/icon.png")

        Returns:
            Path to the file if found, None otherwise
        """
        # Try exact match first
        exact_path = extract_dir / filename
        if exact_path.exists():
            return exact_path

        # Try with res/ prefix
        if not filename.startswith("res/"):
            res_path = extract_dir / "res" / filename
            if res_path.exists():
                return res_path

        # Search recursively (last resort)
        filename_lower = filename.lower()
        for file_path in extract_dir.rglob("*"):
            if file_path.is_file() and str(file_path).lower().endswith(filename_lower):
                return file_path

        return None

    @staticmethod
    def _find_file_in_zip(zip_file: zipfile.ZipFile, filename: str) -> zipfile.ZipInfo | None:
        """Find a file in a ZIP archive, handling various path formats."""
        # Try exact match first
        try:
            return zip_file.getinfo(filename)
        except KeyError:
            pass

        # Try with res/ prefix
        if not filename.startswith("res/"):
            try:
                return zip_file.getinfo(f"res/{filename}")
            except KeyError:
                pass

        # Search all files
        filename_lower = filename.lower()
        for info in zip_file.infolist():
            if info.filename.lower().endswith(filename_lower):
                return info

        return None

    @staticmethod
    def _resolve_color(color_ref: str) -> tuple[int, int, int, int]:
        """Resolve a color reference to RGBA tuple.

        Args:
            color_ref: Color reference (e.g., "#RRGGBB", "#AARRGGBB", or "resourceId:0x...")

        Returns:
            RGBA color tuple
        """
        if color_ref.startswith("#"):
            color_hex = color_ref[1:]
            if len(color_hex) == 6:
                # RGB
                r, g, b = (
                    int(color_hex[0:2], 16),
                    int(color_hex[2:4], 16),
                    int(color_hex[4:6], 16),
                )
                return (r, g, b, 255)
            elif len(color_hex) == 8:
                # ARGB
                a, r, g, b = (
                    int(color_hex[0:2], 16),
                    int(color_hex[2:4], 16),
                    int(color_hex[4:6], 16),
                    int(color_hex[6:8], 16),
                )
                return (r, g, b, a)
            elif len(color_hex) == 3:
                # RGB short form
                r, g, b = (
                    int(color_hex[0] * 2, 16),
                    int(color_hex[1] * 2, 16),
                    int(color_hex[2] * 2, 16),
                )
                return (r, g, b, 255)
            elif len(color_hex) == 4:
                # ARGB short form
                a, r, g, b = (
                    int(color_hex[0] * 2, 16),
                    int(color_hex[1] * 2, 16),
                    int(color_hex[2] * 2, 16),
                    int(color_hex[3] * 2, 16),
                )
                return (r, g, b, a)

        # Default to black
        return (0, 0, 0, 255)

    @staticmethod
    def _parse_dimension(dim_str: str) -> int:
        """Parse a dimension string (e.g., "24dp", "48px") to pixels.

        Args:
            dim_str: Dimension string

        Returns:
            Dimension in pixels
        """
        match = re.match(r"(\d+(?:\.\d+)?)(dp|dip|px|sp)?", dim_str)
        if match:
            value = float(match.group(1))
            unit = match.group(2) or "px"

            # Simple conversion (assuming 160 dpi for dp)
            if unit in ["dp", "dip"]:
                return int(value)
            elif unit == "px":
                return int(value)
            elif unit == "sp":
                return int(value)

        return 108  # Default size
