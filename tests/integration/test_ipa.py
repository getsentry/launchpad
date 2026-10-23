import tempfile
import zipfile

from pathlib import Path

from launchpad.artifacts.artifact_factory import ArtifactFactory


class TestIPA:
    def test_ipa_generation(self, hackernews_xcarchive: Path):
        artifact = ArtifactFactory.from_path(hackernews_xcarchive)
        temp_dir = Path(tempfile.mkdtemp())
        ipa_path = temp_dir / "HackerNews.ipa"

        artifact.generate_ipa(ipa_path)

        assert ipa_path.exists()

        extract_dir = temp_dir / "extracted_ipa"
        extract_dir.mkdir()

        with zipfile.ZipFile(ipa_path) as zf:
            assert zf.testzip() is None
            zf.extractall(extract_dir)

        payload_dir = extract_dir / "Payload"
        app_bundles = list(payload_dir.glob("*.app"))
        assert len(app_bundles) == 1, f"Expected exactly one .app bundle, found {len(app_bundles)}"
