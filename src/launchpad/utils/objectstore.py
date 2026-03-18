from dataclasses import dataclass

from objectstore_client import (
    Client as ObjectstoreClient,
)
from objectstore_client import (
    Permission,
    TokenGenerator,
)

from launchpad.utils.logging import get_logger

logger = get_logger(__name__)

_cached_keyfiles: dict[str, str] = {}

TOKEN_PERMISSIONS: list[Permission] = [
    Permission.OBJECT_READ,
    Permission.OBJECT_WRITE,
    Permission.OBJECT_DELETE,
]


@dataclass
class ObjectstoreConfig:
    """Objectstore client configuration data."""

    objectstore_url: str | None
    key_id: str | None = None
    key_file: str | None = None
    token_expiry_seconds: int = 60


def _read_keyfile(path: str) -> str | None:
    global _cached_keyfiles
    if path not in _cached_keyfiles:
        try:
            with open(path) as f:
                _cached_keyfiles[path] = f.read().strip()
        except Exception:
            logger.exception(f"Failed to load objectstore keyfile at {path}")

    return _cached_keyfiles.get(path)


def create_objectstore_client(config: ObjectstoreConfig) -> ObjectstoreClient | None:
    if not config.objectstore_url:
        return None

    token_generator = None
    if config.key_id and config.key_file:
        if secret_key := _read_keyfile(config.key_file):
            token_generator = TokenGenerator(
                config.key_id,
                secret_key,
                config.token_expiry_seconds,
                TOKEN_PERMISSIONS,
            )

    return ObjectstoreClient(config.objectstore_url, token=token_generator)
