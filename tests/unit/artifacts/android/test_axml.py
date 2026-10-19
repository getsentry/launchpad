from pathlib import Path

from launchpad.artifacts.android.manifest.axml import AxmlUtils, BinaryXmlParser
from launchpad.artifacts.android.manifest.manifest import AndroidApplication, AndroidManifest
from launchpad.parsers.android.binary.android_binary_parser import AndroidBinaryParser
from launchpad.parsers.android.binary.types import XmlCData, XmlNode


def _load_manifest_with_text(fixtures_root: Path) -> bytes:
    # Synthetic manifest compiled with aapt2:
    # <manifest><application><activity>
    #   <meta-data android:name="com.example.flag" android:value="true" />example text
    # </activity></application></manifest>
    return (fixtures_root / "android/manifest-with-text/AndroidManifest.axml").read_bytes()


def test_parse_manifest_with_stray_activity_text(fixtures_root: Path) -> None:
    buffer = _load_manifest_with_text(fixtures_root)
    root = AndroidBinaryParser(buffer).parse_xml()

    application = root.child_nodes[0]
    assert isinstance(application, XmlNode)
    assert application.node_name == "application"
    activity = application.child_nodes[0]
    assert isinstance(activity, XmlNode)
    assert activity.node_name == "activity"
    metadata, text = activity.child_nodes
    assert isinstance(metadata, XmlNode)
    assert metadata.node_name == "meta-data"
    assert isinstance(text, XmlCData)
    assert text.data == "example text"
    root = BinaryXmlParser(buffer).parse_xml()

    assert root is not None
    activity = root.child_nodes[0].child_nodes[0]
    assert [child.node_name for child in activity.child_nodes] == ["meta-data"]
    assert {attr.name: attr.value for attr in activity.child_nodes[0].attributes} == {
        "name": "com.example.flag",
        "value": "True",
    }

    assert AxmlUtils.binary_xml_to_android_manifest(buffer, []) == AndroidManifest(
        package_name="com.example.app",
        min_sdk_version=1,
        application=AndroidApplication(label="Example App", uses_cleartext_traffic=False, reaper_instrumented=False),
    )
