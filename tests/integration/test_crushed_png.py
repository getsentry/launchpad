"""Integration tests for crushed PNG parser using iOS app fixtures."""

import tempfile

from pathlib import Path

from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive
from launchpad.artifacts.artifact_factory import ArtifactFactory
from launchpad.parsers.apple.crushed_png import decode_crushed_png


class TestCrushedPNGIntegration:
    """Integration tests for crushed PNG parsing with real iOS app data."""

    def test_decode_app_icons_from_hackernews(self, hackernews_xcarchive: Path):
        """Test decoding crushed PNGs from HackerNews iOS app fixture."""
        # Load the artifact
        artifact = ArtifactFactory.from_path(hackernews_xcarchive)
        assert isinstance(artifact, ZippedXCArchive)

        # Get app bundle path
        app_bundle_path = artifact.get_app_bundle_path()
        assert app_bundle_path.exists()

        # Find PNG files in the app bundle (excluding nested frameworks/appex)
        png_files = [
            f
            for f in app_bundle_path.glob("*.png")
            if f.is_file() and "__MACOSX" not in str(f) and not f.name.startswith(".")
        ]

        # Should find at least one PNG file
        assert len(png_files) > 0, f"Expected to find PNG files in {app_bundle_path}"

        decoded_count = 0
        crushed_count = 0

        for png_file in png_files:
            with open(png_file, "rb") as f:
                png_data = f.read()

            # Check if this is a crushed PNG (contains CgBI marker)
            is_crushed = b"CgBI" in png_data

            # Decode the PNG
            decoded_png = decode_crushed_png(png_data, debug=False)

            if is_crushed:
                crushed_count += 1
                # For crushed PNGs, we should get decoded data
                assert decoded_png is not None, f"Failed to decode crushed PNG: {png_file.name}"
                assert len(decoded_png) > 0
                assert decoded_png != png_data, "Decoded data should differ from original crushed PNG"

                # Verify the output is a valid PNG
                assert decoded_png.startswith(b"\x89PNG\r\n\x1a\n"), "Decoded output should have valid PNG header"

                # Verify CgBI marker is removed
                assert b"CgBI" not in decoded_png, "Decoded PNG should not contain CgBI marker"

                decoded_count += 1
            else:
                # For standard PNGs, we should get the original data back
                if decoded_png is not None:
                    assert decoded_png == png_data, "Standard PNG should be returned as-is"

        # Log summary
        print(f"\nFound {len(png_files)} PNG files")
        print(f"Crushed PNGs: {crushed_count}")
        print(f"Successfully decoded: {decoded_count}")

        # We expect to find at least some crushed PNGs in an iOS app
        assert crushed_count > 0, "Expected to find at least one crushed PNG in iOS app bundle"

    def test_decode_and_save_app_icon(self, hackernews_xcarchive: Path):
        """Test decoding an app icon using get_app_icon() method."""
        artifact = ArtifactFactory.from_path(hackernews_xcarchive)
        assert isinstance(artifact, ZippedXCArchive)

        # Test get_app_icon() method
        decoded_icon = artifact.get_app_icon()

        assert decoded_icon is not None, "get_app_icon() should return icon data"

        # Verify decoded icon is valid PNG
        assert decoded_icon.startswith(b"\x89PNG\r\n\x1a\n"), "Should be valid PNG"
        assert b"CgBI" not in decoded_icon, "Should not contain CgBI marker"
        assert b"IEND" in decoded_icon, "Should have IEND chunk"

        # Save to temp file to verify it's readable
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp_file:
            tmp_file.write(decoded_icon)
            tmp_path = Path(tmp_file.name)

        # Verify file was written
        assert tmp_path.exists()
        assert tmp_path.stat().st_size == len(decoded_icon)

        # Clean up
        tmp_path.unlink()

        print("\nSuccessfully decoded app icon via get_app_icon()")
        print(f"Decoded size: {len(decoded_icon)} bytes")

    def test_invalid_png_handling(self):
        """Test that parser handles invalid PNG data gracefully."""
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
