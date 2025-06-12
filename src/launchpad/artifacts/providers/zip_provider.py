from io import BytesIO
from typing import Optional
from zipfile import ZipFile


class ZipProvider:
    """Provider for handling zip file operations."""

    def __init__(self, content: bytes) -> None:
        """Initialize the zip provider.

        Args:
            content: Raw bytes of the zip file
        """
        self.content = content
        self._zip: Optional[ZipFile] = None

    def get_zip(self) -> ZipFile:
        """Get the ZipFile object, creating it if it doesn't exist.

        Returns:
            ZipFile object for accessing the archive contents
        """
        if self._zip is None:
            self._zip = ZipFile(BytesIO(self.content))
        return self._zip

    def __del__(self) -> None:
        """Clean up resources when object is destroyed."""
        if self._zip is not None:
            self._zip.close()
