"""Tests for binary XML drawable utilities."""

import io
import zipfile

from unittest.mock import Mock, patch

import pytest

from PIL import Image

from launchpad.parsers.android.binary.binary_xml_drawable_utils import (
    BinaryXmlDrawableUtils,
    GradientInfo,
    GradientItem,
    PathAttributes,
    VectorAttributes,
)
from launchpad.parsers.android.binary.types import XmlNode


class TestBinaryXmlDrawableUtils:
    """Test suite for BinaryXmlDrawableUtils."""

    def test_resolve_color_hex6(self):
        """Test resolving 6-digit hex color."""
        result = BinaryXmlDrawableUtils._resolve_color("#FF5733")
        assert result == (255, 87, 51, 255)

    def test_resolve_color_hex8(self):
        """Test resolving 8-digit hex color (ARGB)."""
        result = BinaryXmlDrawableUtils._resolve_color("#80FF5733")
        assert result == (255, 87, 51, 128)

    def test_resolve_color_hex3(self):
        """Test resolving 3-digit hex color."""
        result = BinaryXmlDrawableUtils._resolve_color("#F53")
        assert result == (255, 85, 51, 255)

    def test_resolve_color_hex4(self):
        """Test resolving 4-digit hex color (ARGB short form)."""
        result = BinaryXmlDrawableUtils._resolve_color("#8F53")
        assert result == (255, 85, 51, 136)

    def test_resolve_color_default(self):
        """Test resolving invalid color returns black."""
        result = BinaryXmlDrawableUtils._resolve_color("invalid")
        assert result == (0, 0, 0, 255)

    def test_parse_dimension_dp(self):
        """Test parsing dimension with dp unit."""
        result = BinaryXmlDrawableUtils._parse_dimension("24dp")
        assert result == 24

    def test_parse_dimension_px(self):
        """Test parsing dimension with px unit."""
        result = BinaryXmlDrawableUtils._parse_dimension("48px")
        assert result == 48

    def test_parse_dimension_no_unit(self):
        """Test parsing dimension without unit."""
        result = BinaryXmlDrawableUtils._parse_dimension("100")
        assert result == 100

    def test_parse_dimension_float(self):
        """Test parsing dimension with float value."""
        result = BinaryXmlDrawableUtils._parse_dimension("24.5dp")
        assert result == 24

    def test_parse_dimension_invalid(self):
        """Test parsing invalid dimension returns default."""
        result = BinaryXmlDrawableUtils._parse_dimension("invalid")
        assert result == 108

    def test_get_optional_attr_value_found(self):
        """Test getting optional attribute value when present."""
        attr = Mock()
        attr.name = "width"
        attr.value = "24dp"
        attr.typed_value = None
        attributes = [attr]

        result = BinaryXmlDrawableUtils._get_optional_attr_value(attributes, "width", [])
        assert result == "24dp"

    def test_get_optional_attr_value_not_found(self):
        """Test getting optional attribute value when not present."""
        attributes = []
        result = BinaryXmlDrawableUtils._get_optional_attr_value(attributes, "width", [])
        assert result is None

    def test_get_optional_attr_value_typed_string(self):
        """Test getting optional attribute value from typed value (string)."""
        typed_value = Mock()
        typed_value.type = "string"
        typed_value.value = "test_string"

        attr = Mock()
        attr.name = "label"
        attr.value = None
        attr.typed_value = typed_value
        attributes = [attr]

        result = BinaryXmlDrawableUtils._get_optional_attr_value(attributes, "label", [])
        assert result == "test_string"

    def test_get_optional_attr_value_typed_int(self):
        """Test getting optional attribute value from typed value (int)."""
        typed_value = Mock()
        typed_value.type = "int_dec"
        typed_value.value = 42

        attr = Mock()
        attr.name = "count"
        attr.value = None
        attr.typed_value = typed_value
        attributes = [attr]

        result = BinaryXmlDrawableUtils._get_optional_attr_value(attributes, "count", [])
        assert result == "42"

    def test_get_required_attr_value_found(self):
        """Test getting required attribute value when present."""
        attr = Mock()
        attr.name = "width"
        attr.value = "24dp"
        attr.typed_value = None
        attributes = [attr]

        result = BinaryXmlDrawableUtils._get_required_attr_value(attributes, "width", [])
        assert result == "24dp"

    def test_get_required_attr_value_not_found(self):
        """Test getting required attribute value raises when not present."""
        attributes = []
        with pytest.raises(ValueError, match="Missing required attribute: width"):
            BinaryXmlDrawableUtils._get_required_attr_value(attributes, "width", [])

    def test_find_file_in_zip_exact_match(self):
        """Test finding file in ZIP with exact match."""
        # Create a mock ZIP file
        mock_zip = Mock(spec=zipfile.ZipFile)
        mock_info = Mock(spec=zipfile.ZipInfo)
        mock_info.filename = "test.xml"
        mock_zip.getinfo.return_value = mock_info

        result = BinaryXmlDrawableUtils._find_file_in_zip(mock_zip, "test.xml")
        assert result == mock_info

    def test_find_file_in_zip_not_found(self):
        """Test finding file in ZIP when not found."""
        mock_zip = Mock(spec=zipfile.ZipFile)
        mock_zip.getinfo.side_effect = KeyError("not found")
        mock_zip.infolist.return_value = []

        result = BinaryXmlDrawableUtils._find_file_in_zip(mock_zip, "nonexistent.xml")
        assert result is None

    @patch("launchpad.parsers.android.binary.binary_xml_drawable_utils.AndroidBinaryParser")
    def test_render_shape_to_buffer_rectangle(self, mock_parser_class):
        """Test rendering a rectangle shape to buffer."""
        # Create mock shape node
        shape_node = Mock(spec=XmlNode)
        shape_attr = Mock()
        shape_attr.name = "shape"
        shape_attr.value = "rectangle"
        shape_attr.typed_value = None
        shape_node.attributes = [shape_attr]

        # Create mock solid child node
        solid_node = Mock(spec=XmlNode)
        solid_node.node_name = "solid"
        color_attr = Mock()
        color_attr.name = "color"
        color_attr.value = "#FF5733"
        color_attr.typed_value = None
        solid_node.attributes = [color_attr]

        shape_node.child_nodes = [solid_node]

        result = BinaryXmlDrawableUtils._render_shape_to_buffer(shape_node, [])
        assert result is not None
        assert isinstance(result, bytes)

        # Verify it's a valid PNG
        img = Image.open(io.BytesIO(result))
        assert img.format == "PNG"
        assert img.size == (108, 108)

    @patch("launchpad.parsers.android.binary.binary_xml_drawable_utils.AndroidBinaryParser")
    def test_render_shape_to_buffer_unsupported_shape(self, mock_parser_class):
        """Test rendering unsupported shape type returns None."""
        shape_node = Mock(spec=XmlNode)
        shape_attr = Mock()
        shape_attr.name = "shape"
        shape_attr.value = "circle"
        shape_attr.typed_value = None
        shape_node.attributes = [shape_attr]
        shape_node.child_nodes = []

        result = BinaryXmlDrawableUtils._render_shape_to_buffer(shape_node, [])
        assert result is None

    def test_render_vector_to_buffer_basic(self):
        """Test rendering a basic vector drawable."""
        vector_attrs = VectorAttributes(
            width="24dp",
            height="24dp",
            viewport_width="24",
            viewport_height="24",
        )
        path_attrs = PathAttributes(
            fill_color="#FF5733",
            path_data="M 0 0 L 100 100",
        )
        path_elements = [path_attrs]

        result = BinaryXmlDrawableUtils._render_vector_to_buffer(vector_attrs, path_elements)
        assert result is not None
        assert isinstance(result, bytes)

        # Verify it's a valid PNG
        img = Image.open(io.BytesIO(result))
        assert img.format == "PNG"

    def test_render_vector_to_buffer_empty_paths(self):
        """Test rendering vector with no paths."""
        vector_attrs = VectorAttributes(
            width="24dp",
            height="24dp",
        )
        path_elements = []

        result = BinaryXmlDrawableUtils._render_vector_to_buffer(vector_attrs, path_elements)
        assert result is not None
        assert isinstance(result, bytes)

    def test_gradient_info_creation(self):
        """Test creating GradientInfo object."""
        items = [
            GradientItem(offset="0", color="#FF0000"),
            GradientItem(offset="1", color="#0000FF"),
        ]
        gradient = GradientInfo(
            type="linear",
            angle="45",
            items=items,
        )
        assert gradient.type == "linear"
        assert gradient.angle == "45"
        assert gradient.items is not None
        assert len(gradient.items) == 2

    def test_vector_attributes_creation(self):
        """Test creating VectorAttributes object."""
        vector_attrs = VectorAttributes(
            width="24dp",
            height="24dp",
            viewport_width="24",
            viewport_height="24",
            tint="#FF0000",
        )
        assert vector_attrs.width == "24dp"
        assert vector_attrs.height == "24dp"
        assert vector_attrs.viewport_width == "24"
        assert vector_attrs.viewport_height == "24"
        assert vector_attrs.tint == "#FF0000"

    def test_path_attributes_creation(self):
        """Test creating PathAttributes object."""
        path_attrs = PathAttributes(
            path_data="M 0 0 L 100 100",
            fill_color="#FF0000",
            stroke_color="#0000FF",
            stroke_width="2",
            fill_alpha="0.5",
            stroke_alpha="1.0",
        )
        assert path_attrs.path_data == "M 0 0 L 100 100"
        assert path_attrs.fill_color == "#FF0000"
        assert path_attrs.stroke_color == "#0000FF"
        assert path_attrs.stroke_width == "2"
        assert path_attrs.fill_alpha == "0.5"
        assert path_attrs.stroke_alpha == "1.0"

    @patch("launchpad.parsers.android.binary.binary_xml_drawable_utils.Image")
    def test_process_adaptive_icon_layers_both_layers(self, mock_image_class):
        """Test processing adaptive icon with both foreground and background."""
        # Create mock images
        mock_bg = Mock(spec=Image.Image)
        mock_bg.mode = "RGBA"
        mock_bg.resize.return_value = mock_bg

        mock_fg = Mock(spec=Image.Image)
        mock_fg.mode = "RGBA"
        mock_fg.resize.return_value = mock_fg

        mock_result = Mock(spec=Image.Image)
        mock_image_class.new.return_value = mock_result
        mock_image_class.open.side_effect = [mock_bg, mock_fg]
        mock_image_class.Resampling = Mock()
        mock_image_class.Resampling.LANCZOS = 1

        # Create mock ZIP
        mock_zip = Mock(spec=zipfile.ZipFile)
        mock_bg_info = Mock(spec=zipfile.ZipInfo)
        mock_bg_info.filename = "res/drawable/background.png"
        mock_fg_info = Mock(spec=zipfile.ZipInfo)
        mock_fg_info.filename = "res/drawable/foreground.png"

        def mock_getinfo(name):
            if "background" in name:
                return mock_bg_info
            elif "foreground" in name:
                return mock_fg_info
            raise KeyError(name)

        mock_zip.getinfo.side_effect = mock_getinfo
        mock_zip.read.return_value = b"fake image data"

        # Mock save method
        mock_result.save = lambda buf, format: buf.write(b"fake png data")

        result = BinaryXmlDrawableUtils._process_adaptive_icon_layers(
            foreground_path="res/drawable/foreground.png",
            background_path="res/drawable/background.png",
            zip_file=mock_zip,
            binary_res_tables=[],
        )

        assert result is not None
        assert isinstance(result, bytes)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
