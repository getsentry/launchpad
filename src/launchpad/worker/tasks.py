import logging

from typing import Any

from .app import app

logger = logging.getLogger(__name__)


# Create a namespace and register tasks
default = app.taskregistry.create_namespace("default")


@default.register(name="process_something")
def process_something(*args: list[Any], **kwargs: dict[str, Any]) -> None:
    print("Received task 🎉")
