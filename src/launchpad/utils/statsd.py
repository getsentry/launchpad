import os

from typing import Literal

from datadog.dogstatsd.base import DogStatsd

# There are a few weird issues with DataDog documented in other Sentry repos.
# See:
# - https://github.com/getsentry/sentry/blob/81e1b8694f2ab3a63ecab3accf9911cc97accbb0/src/sentry/metrics/dogstatsd.py#L30
# - https://github.com/getsentry/seer/blob/992299aa44ce744366fe1be0c20b11d99987fa1d/src/seer/fastapi_app.py#L33
# - https://github.com/DataDog/datadogpy/issues/764
# Minimize these by:
# - turning off the problem features
# - not using the global initialize() and statsd instances.


_statsd_instances: dict[str, DogStatsd] = {}


def get_statsd(environment: Literal["default", "consumer"] = "default") -> DogStatsd:
    global _statsd_instances

    if environment in _statsd_instances:
        return _statsd_instances[environment]

    disable_telemetry = True
    origin_detection_enabled = False

    host = os.getenv("STATSD_HOST", "127.0.0.1")
    port_str = os.getenv("STATSD_PORT", "8125")

    try:
        port = int(port_str)
    except ValueError:
        raise ValueError(f"STATSD_PORT must be a valid integer, got: {port_str}")

    # Create namespace with environment
    namespace = "launchpad" if environment == "default" else "launchpad_consumer"

    _statsd_instances[environment] = DogStatsd(
        host=host,
        port=port,
        namespace=namespace,
        disable_telemetry=disable_telemetry,
        origin_detection_enabled=origin_detection_enabled,
    )
    return _statsd_instances[environment]
