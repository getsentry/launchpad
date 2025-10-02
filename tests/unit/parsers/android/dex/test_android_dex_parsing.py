import zipfile

from pathlib import Path

from launchpad.artifacts.android.apk import APK


def extract_classes_dex_from_apk(apk_path: Path) -> bytes:
    with zipfile.ZipFile(apk_path, "r") as zf:
        with zf.open("classes.dex") as dex_file:
            return dex_file.read()


def test_parse_dex_from_hn_apk(hn_apk):
    apk = APK(hn_apk)
    classes = apk.get_class_definitions()

    assert len(classes) == 4755


def test_parse_dex_from_debug_apk(debug_apk):
    apk = APK(debug_apk)
    classes = apk.get_class_definitions()

    assert len(classes) == 14950
