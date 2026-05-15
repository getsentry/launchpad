class UnreasonableZipError(ValueError):
    """Raised when a zip file exceeds reasonable limits."""

    pass


class UnsafePathError(ValueError):
    """Raised when a zip file contains unsafe path entries that could lead to path traversal attacks."""

    pass
