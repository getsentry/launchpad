import subprocess

from pathlib import Path
from zipfile import ZipFile

from launchpad.artifacts.artifact_factory import ArtifactFactory


class TestIPA:
    def test_ipa_generation(self, hackernews_xcarchive: Path, tmp_path: Path):
        artifact = ArtifactFactory.from_path(hackernews_xcarchive)
        ipa_path = tmp_path / "HackerNews.ipa"

        artifact.generate_ipa(ipa_path)

        assert ipa_path.exists()

        extract_dir = tmp_path / "extracted_ipa"
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

        app = app_bundles[0].relative_to(extract_dir)
        with ZipFile(ipa_path) as ipa:
            for executable in (
                app / "HackerNews",
                app / "Frameworks/Sentry.framework/Sentry",
                app / "PlugIns/HackerNewsHomeWidgetExtension.appex/HackerNewsHomeWidgetExtension",
            ):
                assert (ipa.getinfo(executable.as_posix()).external_attr >> 16) & 0o111 == 0o111
            assert (ipa.getinfo((app / "Info.plist").as_posix()).external_attr >> 16) & 0o111 == 0
