from pathlib import Path

import pytest

from launchpad.utils.java import find_jar, find_java, find_keytool


def test_find_java_prefers_java_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    java = tmp_path / "bin" / "java"
    java.parent.mkdir()
    java.touch()
    keytool = java.with_name("keytool")
    keytool.touch()
    monkeypatch.setenv("JAVA_HOME", str(tmp_path))

    assert find_java() == str(java)
    assert find_keytool() == str(keytool)


def test_find_java_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("JAVA_HOME", raising=False)
    monkeypatch.setenv("PATH", str(tmp_path))

    with pytest.raises(FileNotFoundError):
        find_java()


def test_find_jar_searches_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    jar = tmp_path / "bin" / "bundletool.jar"
    jar.parent.mkdir()
    jar.touch()
    monkeypatch.setenv("PATH", f"/nonexistent:{jar.parent}")

    assert find_jar("bundletool.jar") == str(jar)
    with pytest.raises(FileNotFoundError):
        find_jar("missing.jar")
