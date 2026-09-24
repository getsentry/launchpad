import os
import stat
import zipfile

from pathlib import Path

from launchpad.utils.zip_utils import zip_directory


def _make_bundle(tmp_path: Path) -> Path:
    bundle = tmp_path / "Test.app"
    (bundle / "Frameworks" / "Foo.framework" / "Versions" / "A").mkdir(parents=True)
    (bundle / "Frameworks" / "Foo.framework" / "Versions" / "A" / "Foo").write_bytes(b"binary" * 100)
    (bundle / "Info.plist").write_text("<plist/>")
    executable = bundle / "Test"
    executable.write_bytes(b"\xcf\xfa\xed\xfe")
    executable.chmod(0o755)
    os.symlink("Versions/A/Foo", bundle / "Frameworks" / "Foo.framework" / "Foo")
    return bundle


def test_zip_directory_preserves_symlinks_and_permissions(tmp_path: Path) -> None:
    bundle = _make_bundle(tmp_path)
    out = tmp_path / "out.zip"

    zip_directory(bundle, out, preserve_symlinks=True)

    with zipfile.ZipFile(out) as zf:
        assert zf.testzip() is None
        infos = {i.filename: i for i in zf.infolist()}

        # Entries are rooted at the bundle name, and directories are present, like `zip -r`
        assert "Test.app/" in infos
        assert infos["Test.app/"].is_dir()
        assert infos["Test.app/Info.plist"].compress_type == zipfile.ZIP_DEFLATED

        link = infos["Test.app/Frameworks/Foo.framework/Foo"]
        assert stat.S_ISLNK(link.external_attr >> 16)
        assert zf.read(link) == b"Versions/A/Foo"

        assert stat.S_IMODE(infos["Test.app/Test"].external_attr >> 16) == 0o755


def test_zip_directory_follows_symlinks_when_requested(tmp_path: Path) -> None:
    bundle = _make_bundle(tmp_path)
    os.symlink("does-not-exist", bundle / "dangling")
    out = tmp_path / "out.zip"

    zip_directory(bundle, out, preserve_symlinks=False)

    with zipfile.ZipFile(out) as zf:
        infos = {i.filename: i for i in zf.infolist()}
        link = infos["Test.app/Frameworks/Foo.framework/Foo"]
        assert stat.S_ISREG(link.external_attr >> 16)
        assert zf.read(link) == b"binary" * 100
        assert "Test.app/dangling" not in infos
