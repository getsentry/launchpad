import os
import plistlib
import stat
import subprocess

from pathlib import Path
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZIP_ZSTANDARD, ZipFile, ZipInfo

import pytest

from launchpad.artifacts.artifact_factory import ArtifactFactory


class TestIPA:
    def test_ipa_generation(self, hackernews_xcarchive: Path, tmp_path: Path):
        artifact = ArtifactFactory.from_path(hackernews_xcarchive)
        ipa_path = tmp_path / "HackerNews.ipa"
        artifact.generate_ipa(ipa_path)
        with ZipFile(ipa_path) as ipa:
            executable = ipa.getinfo("Payload/HackerNews.app/HackerNews")
            assert stat.S_IMODE(executable.external_attr >> 16) == 0o755

        subprocess.run(["unzip", "-q", ipa_path, "-d", tmp_path], check=True)
        (app,) = (tmp_path / "Payload").glob("*.app")
        resource = Path("PlugIns/HackerNewsHomeWidgetExtension.appex/Fonts_Fonts.bundle")
        with (app / "_CodeSignature/CodeResources").open("rb") as f:
            seal = plistlib.load(f)["files2"][resource.as_posix()]
        assert (app / resource).is_symlink()
        assert os.readlink(app / resource) == seal["symlink"] == "../../Fonts_Fonts.bundle"
        assert (app / resource).samefile(app / "Fonts_Fonts.bundle")
        analysis_resource = artifact.get_app_bundle_path() / resource
        assert not analysis_resource.is_symlink()
        assert analysis_resource.read_bytes() == b"../../Fonts_Fonts.bundle"

    @pytest.mark.parametrize("compression", [ZIP_STORED, ZIP_ZSTANDARD], ids=["stored", "zstd"])
    def test_upload_compression(self, tmp_path: Path, compression: int):
        archive = tmp_path / "Example.zip"
        app = "Example.xcarchive/Products/Applications/Example.app"
        with ZipFile(archive, "w", compression=compression) as source:
            source.writestr("Example.xcarchive/Info.plist", b"")
            source.writestr(f"./{app}/Resource", b"resource contents")
            alias = ZipInfo(f"{app}/Alias")
            alias.create_system = 3  # Unix
            alias.external_attr = (stat.S_IFLNK | 0o777) << 16
            source.writestr(alias, b"../missing", compress_type=compression)

        output = tmp_path / "Example.ipa"
        ArtifactFactory.from_path(archive).generate_ipa(output)
        with ZipFile(output) as ipa:
            assert set(ipa.namelist()) == {"Payload/Example.app/Resource", "Payload/Example.app/Alias"}
            resource = ipa.getinfo("Payload/Example.app/Resource")
            link = ipa.getinfo("Payload/Example.app/Alias")
            assert resource.compress_type == link.compress_type == ZIP_DEFLATED
            assert ipa.read(resource) == b"resource contents"
            assert stat.S_ISLNK(link.external_attr >> 16)
            assert ipa.read(link) == b"../missing"  # The target is copied verbatim without being resolved.
