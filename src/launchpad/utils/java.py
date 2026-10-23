"""Locating the Java runtime and the jars launchpad shells out to.

The jars are invoked directly with ``java -jar`` rather than through the shell launchers
that ship with them, so they work in the distroless image where there is no shell.
"""

import os
import shutil

from pathlib import Path


def find_java() -> str:
    """Return the path to the ``java`` executable.

    Honors ``JAVA_HOME`` first, then falls back to ``PATH``.
    """
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        candidate = Path(java_home) / "bin" / "java"
        if candidate.is_file():
            return str(candidate)

    java = shutil.which("java")
    if java is None:
        raise FileNotFoundError("java not found in JAVA_HOME or PATH")
    return java


def find_keytool() -> str:
    """Return the path to ``keytool``, preferring the one next to the resolved ``java``."""
    sibling = Path(find_java()).with_name("keytool")
    if sibling.is_file():
        return str(sibling)

    keytool = shutil.which("keytool")
    if keytool is None:
        raise FileNotFoundError("keytool not found next to java or in PATH")
    return keytool


def find_jar(name: str) -> str:
    """Return the path to ``name`` (e.g. ``bundletool.jar``) by searching the ``PATH`` directories.

    ``scripts/deps`` installs the jars into a ``bin`` directory that is on ``PATH``.
    """
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if not directory:
            continue
        candidate = Path(directory) / name
        if candidate.is_file():
            return str(candidate)
    raise FileNotFoundError(f"{name} not found in any PATH directory; run scripts/deps")
