import os
import plistlib
import stat
import subprocess

from pathlib import Path
from zipfile import ZipFile, ZipInfo

import pytest

from launchpad.artifacts.artifact_factory import ArtifactFactory
from launchpad.artifacts.providers.exceptions import UnsafePathError


def symlink_entry(name: str) -> ZipInfo:
    entry = ZipInfo(name)
    entry.create_system = 3  # Unix
    entry.external_attr = (stat.S_IFLNK | 0o777) << 16
    return entry


class TestIPA:
    def test_ipa_generation(self, hackernews_xcarchive: Path, tmp_path: Path):
        artifact = ArtifactFactory.from_path(hackernews_xcarchive)
        ipa_path = tmp_path / "HackerNews.ipa"
        artifact.generate_ipa(ipa_path)

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

    @pytest.mark.parametrize("alias", ["Alias", "./Alias"])
    @pytest.mark.parametrize("last_is_link", [False, True])
    @pytest.mark.filterwarnings("ignore:Duplicate name:UserWarning")
    def test_duplicate_entry_uses_final_type_and_contents(self, tmp_path: Path, alias: str, last_is_link: bool):
        archive = tmp_path / "Example.zip"
        app = "Example.xcarchive/Products/Applications/Example.app"
        with ZipFile(archive, "w") as source:
            source.writestr("Example.xcarchive/Info.plist", b"")
            source.writestr(f"{app}/Resource", b"resource contents")
            first = f"{app}/Alias"
            last = f"{app}/{alias}"
            if last_is_link:
                source.writestr(first, b"regular contents")
                source.writestr(symlink_entry(last), b"Resource")
            else:
                source.writestr(symlink_entry(first), b"Resource")
                source.writestr(last, b"regular contents")

        output = tmp_path / "Example.ipa"
        ArtifactFactory.from_path(archive).generate_ipa(output)
        with ZipFile(output) as ipa:
            entry = ipa.getinfo("Payload/Example.app/Alias")
            assert stat.S_IFMT(entry.external_attr >> 16) == (stat.S_IFLNK if last_is_link else stat.S_IFREG)
            assert ipa.read(entry) == (b"Resource" if last_is_link else b"regular contents")

    @pytest.mark.parametrize("target", ["/Fonts.bundle", "../Fonts.bundle", "Fonts.bundle"])
    def test_invalid_link_rejected_before_packaging(self, tmp_path: Path, target: str):
        archive = tmp_path / "Example.zip"
        with ZipFile(archive, "w") as source:
            source.writestr("Example.xcarchive/Info.plist", b"")
            source.writestr(symlink_entry("Example.xcarchive/Products/Applications/Example.app/Fonts.bundle"), target)

        artifact = ArtifactFactory.from_path(archive)
        output = tmp_path / "Example.ipa"
        with pytest.raises(UnsafePathError):
            artifact.generate_ipa(output)
        assert not output.exists()
