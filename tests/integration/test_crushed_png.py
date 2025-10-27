"""Integration tests for crushed PNG parser using iOS app fixtures."""

import io

from pathlib import Path

from PIL import Image

from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive
from launchpad.artifacts.artifact_factory import ArtifactFactory
from launchpad.parsers.apple.crushed_png import decode_crushed_png


class TestCrushedPNGIntegration:
    """Integration tests for crushed PNG parsing with real iOS app data."""

    def test_decode_app_icon(self, hackernews_xcarchive: Path):
        artifact = ArtifactFactory.from_path(hackernews_xcarchive)
        assert isinstance(artifact, ZippedXCArchive)

        decoded_icon = artifact.get_app_icon()

        assert decoded_icon is not None, "get_app_icon() should return icon data"
        assert decoded_icon.startswith(b"\x89PNG\r\n\x1a\n")
        assert b"CgBI" not in decoded_icon
        assert b"IEND" in decoded_icon

        img = Image.open(io.BytesIO(decoded_icon))
        assert img.format == "PNG"
        assert img.mode == "RGBA"
        assert img.size == (120, 120)
        img.load()

    def test_invalid_png_handling(self):
        # Test with non-PNG data
        invalid_data = b"This is not a PNG file"
        result = decode_crushed_png(invalid_data)
        assert result is None, "Invalid PNG should return None"

        # Test with partial PNG header
        partial_png = b"\x89PNG"
        result = decode_crushed_png(partial_png)
        assert result is None, "Partial PNG header should return None"

    def test_standard_png_passthrough(self):
        """Test that standard (non-crushed) PNGs are returned as-is."""
        # Create a minimal valid PNG (1x1 pixel, white)
        standard_png = (
            b"\x89PNG\r\n\x1a\n"  # PNG signature
            b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
            b"\x08\x02\x00\x00\x00\x90wS\xde"  # IHDR chunk
            b"\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\r\xa2\xdb"  # IDAT chunk
            b"\x00\x00\x00\x00IEND\xae\x42\x60\x82"  # IEND chunk
        )

        result = decode_crushed_png(standard_png)
        assert result == standard_png, "Standard PNG should be returned unchanged"
