import os

from pathlib import Path
from typing import Generator

from .exceptions import UnsafePathError


class SafeDirectory:
    """A directory wrapper that validates untrusted paths stay within bounds.

    Use .resolve(untrusted) for attacker-controlled input (manifest values,
    plist entries, zip member names). Trusted Path operations (glob, rglob,
    iterdir, /, etc.) are delegated directly.
    """

    def __init__(self, base: Path) -> None:
        self._base = base.resolve()

    @property
    def path(self) -> Path:
        return self._base

    def resolve(self, untrusted: str) -> Path:
        """Resolve an untrusted path within this directory.

        Raises UnsafePathError if the resolved path escapes the base.
        """
        try:
            target = (self._base / untrusted).resolve()
        except RuntimeError:
            raise UnsafePathError(f"Path traversal attempt: {untrusted}")
        if not target.is_relative_to(self._base):
            raise UnsafePathError(f"Path traversal attempt: {untrusted}")
        return target

    def child(self, untrusted: str) -> "SafeDirectory":
        """Return a new SafeDirectory scoped to a validated subdirectory."""
        return SafeDirectory(self.resolve(untrusted))

    # -- Trusted Path delegations --

    def __truediv__(self, other: str | os.PathLike[str]) -> Path:
        return self._base / other

    def __str__(self) -> str:
        return str(self._base)

    def __repr__(self) -> str:
        return f"SafeDirectory({self._base})"

    def __fspath__(self) -> str:
        return str(self._base)

    def glob(self, pattern: str) -> Generator[Path, None, None]:
        return self._base.glob(pattern)

    def rglob(self, pattern: str) -> Generator[Path, None, None]:
        return self._base.rglob(pattern)

    def iterdir(self) -> Generator[Path, None, None]:
        return self._base.iterdir()

    def exists(self) -> bool:
        return self._base.exists()

    def is_dir(self) -> bool:
        return self._base.is_dir()

    def is_file(self) -> bool:
        return self._base.is_file()

    def relative_to(self, other: str | os.PathLike[str]) -> Path:
        return self._base.relative_to(other)

    @property
    def name(self) -> str:
        return self._base.name

    @property
    def stem(self) -> str:
        return self._base.stem

    @property
    def suffix(self) -> str:
        return self._base.suffix

    @property
    def parent(self) -> Path:
        return self._base.parent
