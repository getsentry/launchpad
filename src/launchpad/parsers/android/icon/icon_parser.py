"""Base class for Android icon parsers (binary XML and protobuf XML)."""

from __future__ import annotations

import io
import re

from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw

from launchpad.parsers.android.binary.types import XmlNode
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class VectorAttributes:
    width: str
    height: str
    viewport_width: str | None = None
    viewport_height: str | None = None
    tint: str | None = None


@dataclass
class PathAttributes:
    path_data: str | None = None
    fill_color: str | GradientInfo | None = None
    stroke_color: str | None = None
    stroke_width: str | None = None
    fill_alpha: str | None = None
    stroke_alpha: str | None = None


@dataclass
class GradientItem:
    offset: str | None
    color: str | None


@dataclass
class GradientInfo:
    type: str = "linear"
    angle: str | None = None
    start_x: str | None = None
    start_y: str | None = None
    end_x: str | None = None
    end_y: str | None = None
    items: list[GradientItem] | None = None


DEFAULT_ICON_SIZE = 108


class IconParser:
    def __init__(self, extract_dir: Path) -> None:
        self.extract_dir = extract_dir

    def _get_attr_value(self, attributes: list, name: str, required: bool = False) -> str | None:
        raise NotImplementedError

    def _get_resource_path(self, resource_ref: str) -> str | None:
        raise NotImplementedError

    def _parse_xml_node(self, buffer: bytes) -> XmlNode:
        raise NotImplementedError

    def render_from_path(self, xml_file_path: Path) -> bytes | None:
        try:
            with open(xml_file_path, "rb") as f:
                buffer = f.read()

            root_node = self._parse_xml_node(buffer)

            if root_node.node_name == "adaptive-icon":
                return self._render_adaptive_icon(root_node)

            return self._render_vector_drawable(root_node)
        except Exception:
            logger.exception("Error rendering icon from path")
            return None

    def _render_adaptive_icon(self, root_element: XmlNode) -> bytes | None:
        foreground_node = None
        background_node = None
        for node in root_element.child_nodes:
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
        foreground_path = self._get_resource_path(foreground_attr.typed_value.value)
        background_path = self._get_resource_path(background_attr.typed_value.value)

        if not foreground_path and not background_path:
            logger.warning(
                "Could not resolve resource paths",
                extra={
                    "foreground_ref": foreground_attr.typed_value.value,
                    "background_ref": background_attr.typed_value.value,
                },
            )
            return None

        return self._process_adaptive_icon_layers(
            foreground_path=foreground_path,
            background_path=background_path,
        )

    def _render_vector_drawable(self, root_element: XmlNode) -> bytes | None:
        # Extract vector attributes
        width = self._get_attr_value(root_element.attributes, "width", required=True)
        height = self._get_attr_value(root_element.attributes, "height", required=True)
        viewport_width = self._get_attr_value(root_element.attributes, "viewportWidth")
        viewport_height = self._get_attr_value(root_element.attributes, "viewportHeight")
        tint = self._get_attr_value(root_element.attributes, "tint")

        if not width or not height:
            logger.warning("Vector drawable missing required width/height")
            return None

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

            path_data = self._get_attr_value(node.attributes, "pathData")
            fill_color = self._get_attr_value(node.attributes, "fillColor")
            stroke_color = self._get_attr_value(node.attributes, "strokeColor")
            stroke_width = self._get_attr_value(node.attributes, "strokeWidth")
            fill_alpha = self._get_attr_value(node.attributes, "fillAlpha")
            stroke_alpha = self._get_attr_value(node.attributes, "strokeAlpha")

            # Handle gradient fills
            fill_color_resolved: str | GradientInfo | None = fill_color
            if fill_color and fill_color.endswith(".xml"):
                fill_color_resolved = self._gradient_from_xml(fill_color)

            path_attrs = PathAttributes(
                path_data=path_data,
                fill_color=fill_color_resolved,
                stroke_color=stroke_color,
                stroke_width=stroke_width,
                fill_alpha=fill_alpha,
                stroke_alpha=stroke_alpha,
            )
            path_elements.append(path_attrs)

        return self._render_vector_to_buffer(vector_attrs, path_elements)

    def _gradient_from_xml(self, gradient_file_name: str) -> GradientInfo | None:
        # Find the gradient file
        gradient_file = self._find_file(gradient_file_name)
        if not gradient_file:
            logger.warning(
                "Could not find gradient file",
                extra={"gradient_file_name": gradient_file_name},
            )
            return None

        with open(gradient_file, "rb") as f:
            gradient_file_buffer = f.read()
        gradient_node = self._parse_xml_node(gradient_file_buffer)

        if gradient_node.node_name != "gradient":
            logger.warning(
                "Root element is not a gradient.",
                extra={"gradient_file_name": gradient_file_name},
            )
            return None

        # Extract gradient attributes
        gradient_type = self._get_attr_value(gradient_node.attributes, "type") or "linear"
        angle = self._get_attr_value(gradient_node.attributes, "angle")
        start_x = self._get_attr_value(gradient_node.attributes, "startX")
        start_y = self._get_attr_value(gradient_node.attributes, "startY")
        end_x = self._get_attr_value(gradient_node.attributes, "endX")
        end_y = self._get_attr_value(gradient_node.attributes, "endY")

        # Extract gradient items (color stops)
        gradient_items: list[GradientItem] = []
        for child in gradient_node.child_nodes:
            if not hasattr(child, "node_name") or child.node_name != "item":
                continue

            offset = self._get_attr_value(child.attributes, "offset")
            color = self._get_attr_value(child.attributes, "color")

            if not color:
                logger.warning(
                    "Gradient item missing required attributes",
                    extra={"color": color},
                )

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

    def _process_adaptive_icon_layers(
        self,
        foreground_path: str | None,
        background_path: str | None,
    ) -> bytes | None:
        # Load background layer
        background_img = None
        if background_path:
            background_file = self._find_file(background_path)
            if background_file:
                if background_path.endswith(".xml"):
                    background_buffer = self.render_from_path(background_file)
                    if background_buffer:
                        background_img = Image.open(io.BytesIO(background_buffer))
                else:
                    # PNG or other image format
                    with open(background_file, "rb") as f:
                        background_img = Image.open(io.BytesIO(f.read()))

        # Load foreground layer
        foreground_img = None
        if foreground_path:
            foreground_file = self._find_file(foreground_path)
            if foreground_file:
                if foreground_path.endswith(".xml"):
                    foreground_buffer = self.render_from_path(foreground_file)
                    if foreground_buffer:
                        foreground_img = Image.open(io.BytesIO(foreground_buffer))
                else:
                    # PNG or other image format
                    with open(foreground_file, "rb") as f:
                        foreground_img = Image.open(io.BytesIO(f.read()))

        # Composite the layers
        if not background_img and not foreground_img:
            return None

        size = DEFAULT_ICON_SIZE
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

    def _render_vector_to_buffer(
        self,
        vector_attrs: VectorAttributes,
        path_elements: list[PathAttributes],
    ) -> bytes | None:
        # Parse dimensions
        width = self._parse_dimension(vector_attrs.width)
        height = self._parse_dimension(vector_attrs.height)

        # Create image
        img = Image.new("RGBA", (width, height), (0, 0, 0, 0))

        # Render each path element
        for path_elem in path_elements:
            if not path_elem.fill_color:
                continue

            fill_color = path_elem.fill_color

            # Handle gradient fills
            if isinstance(fill_color, GradientInfo):
                img = self._render_gradient(fill_color, width, height, img)
            # Handle solid color fills
            elif isinstance(fill_color, str):
                draw = ImageDraw.Draw(img)
                color = self._resolve_color(fill_color)
                # Simplified: render as rectangle (would need full path parsing for complex shapes)
                draw.rectangle([(0, 0), (width, height)], fill=color)

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        return buffer.getvalue()

    def _render_gradient(self, gradient: GradientInfo, width: int, height: int, base_img: Image.Image) -> Image.Image:
        if not gradient.items or len(gradient.items) < 2:
            logger.warning("Gradient must have at least 2 color stops")
            return base_img

        # Parse gradient direction from angle or coordinates
        if gradient.angle:
            angle = float(gradient.angle)
            # Convert angle to start/end coordinates
            if angle == 0:
                x1, y1, x2, y2 = 0, height / 2, width, height / 2
            elif angle == 90:
                x1, y1, x2, y2 = width / 2, height, width / 2, 0
            elif angle == 180:
                x1, y1, x2, y2 = width, height / 2, 0, height / 2
            elif angle == 270:
                x1, y1, x2, y2 = width / 2, 0, width / 2, height
            else:
                x1, y1, x2, y2 = width / 2, 0, width / 2, height
        elif gradient.start_x and gradient.start_y and gradient.end_x and gradient.end_y:
            x1 = float(gradient.start_x)
            y1 = float(gradient.start_y)
            x2 = float(gradient.end_x)
            y2 = float(gradient.end_y)
        else:
            x1, y1, x2, y2 = width / 2, 0, width / 2, height

        # Create gradient image
        gradient_img = Image.new("RGBA", (width, height))
        items = sorted(gradient.items, key=lambda item: float(item.offset or "0"))

        # For vertical gradients
        if x1 == x2:
            for y in range(height):
                if y2 != y1:
                    position = (y - y1) / (y2 - y1)
                else:
                    position = 0.0
                position = max(0.0, min(1.0, position))

                color = self._interpolate_gradient_color(items, position)
                if color:
                    draw = ImageDraw.Draw(gradient_img)
                    draw.line([(0, y), (width, y)], fill=color, width=1)
        # For horizontal gradients
        elif y1 == y2:
            for x in range(width):
                if x2 != x1:
                    position = (x - x1) / (x2 - x1)
                else:
                    position = 0.0
                position = max(0.0, min(1.0, position))

                color = self._interpolate_gradient_color(items, position)
                if color:
                    draw = ImageDraw.Draw(gradient_img)
                    draw.line([(x, 0), (x, height)], fill=color, width=1)
        else:
            # Diagonal - use vertical as fallback
            for y in range(height):
                position = y / height
                color = self._interpolate_gradient_color(items, position)
                if color:
                    draw = ImageDraw.Draw(gradient_img)
                    draw.line([(0, y), (width, y)], fill=color, width=1)

        base_img = Image.alpha_composite(base_img.convert("RGBA"), gradient_img)
        return base_img

    def _interpolate_gradient_color(
        self, items: list[GradientItem], position: float
    ) -> tuple[int, int, int, int] | None:
        if position <= 0.0:
            color = items[0].color
            if color:
                return self._resolve_color(color)
            return None

        if position >= 1.0:
            color = items[-1].color
            if color:
                return self._resolve_color(color)
            return None

        for i in range(len(items) - 1):
            offset1 = float(items[i].offset or "0")
            offset2 = float(items[i + 1].offset or "1")

            if offset1 <= position <= offset2:
                color1_str = items[i].color
                color2_str = items[i + 1].color

                if not color1_str or not color2_str:
                    return None

                color1 = self._resolve_color(color1_str)
                color2 = self._resolve_color(color2_str)

                if offset2 != offset1:
                    factor = (position - offset1) / (offset2 - offset1)
                else:
                    factor = 0.0

                r = int(color1[0] + (color2[0] - color1[0]) * factor)
                g = int(color1[1] + (color2[1] - color1[1]) * factor)
                b = int(color1[2] + (color2[2] - color1[2]) * factor)
                a = int(color1[3] + (color2[3] - color1[3]) * factor)

                return (r, g, b, a)

        color = items[-1].color
        if color:
            return self._resolve_color(color)
        return None

    def _find_file(self, filename: str) -> Path | None:
        # Try exact match first
        exact_path = self.extract_dir / filename
        if exact_path.exists():
            return exact_path

        # Try with res/ prefix
        if not filename.startswith("res/"):
            res_path = self.extract_dir / "res" / filename
            if res_path.exists():
                return res_path

        # Search recursively (last resort)
        filename_lower = filename.lower()
        for file_path in self.extract_dir.rglob("*"):
            if file_path.is_file() and str(file_path).lower().endswith(filename_lower):
                return file_path

        return None

    def _resolve_color(self, color_ref: str) -> tuple[int, int, int, int]:
        if color_ref.startswith("#"):
            color_hex = color_ref[1:]
            if len(color_hex) == 6:
                r, g, b = (
                    int(color_hex[0:2], 16),
                    int(color_hex[2:4], 16),
                    int(color_hex[4:6], 16),
                )
                return (r, g, b, 255)
            elif len(color_hex) == 8:
                a, r, g, b = (
                    int(color_hex[0:2], 16),
                    int(color_hex[2:4], 16),
                    int(color_hex[4:6], 16),
                    int(color_hex[6:8], 16),
                )
                return (r, g, b, a)
            elif len(color_hex) == 3:
                r, g, b = (
                    int(color_hex[0] * 2, 16),
                    int(color_hex[1] * 2, 16),
                    int(color_hex[2] * 2, 16),
                )
                return (r, g, b, 255)
            elif len(color_hex) == 4:
                a, r, g, b = (
                    int(color_hex[0] * 2, 16),
                    int(color_hex[1] * 2, 16),
                    int(color_hex[2] * 2, 16),
                    int(color_hex[3] * 2, 16),
                )
                return (r, g, b, a)

        return (0, 0, 0, 255)

    def _parse_dimension(self, dim_str: str) -> int:
        match = re.match(r"(\d+(?:\.\d+)?)(dp|dip|px|sp)?", dim_str)
        if match:
            value = float(match.group(1))
            unit = match.group(2) or "px"

            if unit in ["dp", "dip"]:
                return int(value)
            elif unit == "px":
                return int(value)
            elif unit == "sp":
                return int(value)

        return DEFAULT_ICON_SIZE
