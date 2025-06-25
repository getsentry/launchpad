import subprocess
import tempfile

from pathlib import Path

from launchpad.artifacts.artifact_factory import ArtifactFactory


class TestIPA:
    def test_ipa_generation(self):
        artifact = ArtifactFactory.from_path(Path("tests/_fixtures/ios/HackerNews.xcarchive.zip"))
        temp_dir = Path(tempfile.mkdtemp())
        ipa_path = temp_dir / "HackerNews.ipa"

        artifact.generate_ipa(ipa_path)

        assert ipa_path.exists()

        extract_dir = temp_dir / "extracted_ipa"
        extract_dir.mkdir()

        try:
            subprocess.run(
                ["unzip", "-q", str(ipa_path), "-d", str(extract_dir)],
                check=True,
                capture_output=True,  # Quiet mode
            )
        except subprocess.CalledProcessError as e:
            raise AssertionError(f"Failed to extract IPA: {e.stderr}")

        payload_dir = extract_dir / "Payload"
        app_bundles = list(payload_dir.glob("*.app"))
        assert len(app_bundles) == 1, f"Expected exactly one .app bundle, found {len(app_bundles)}"
