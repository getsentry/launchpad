from pathlib import Path

from .exceptions import UnsafePathError


class SafeDirectory:
    """A directory wrapper that validates untrusted paths stay within bounds.

    Use .resolve(untrusted) for attacker-controlled input (manifest values,
    plist entries, zip member names). Use .path for trusted operations
    (glob, rglob, iterdir).
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

    def __repr__(self) -> str:
        return f"SafeDirectory({self._base})"

    def __str__(self) -> str:
        return str(self._base)
