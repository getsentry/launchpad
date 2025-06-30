from datadog.dogstatsd.base import DogStatsd

# There are a few weird issues with DataDog documented in other Sentry repos.
# See:
# - https://github.com/getsentry/sentry/blob/81e1b8694f2ab3a63ecab3accf9911cc97accbb0/src/sentry/metrics/dogstatsd.py#L30
# - https://github.com/getsentry/seer/blob/992299aa44ce744366fe1be0c20b11d99987fa1d/src/seer/fastapi_app.py#L33
# - https://github.com/DataDog/datadogpy/issues/764
# Minimize these by:
# - turning off the problem features
# - not using the global initialize() and statsd instances.


def get_statsd(host: str = "127.0.0.1", port: int = 8125) -> DogStatsd:
    disable_telemetry = True
    origin_detection_enabled = False
    return DogStatsd(
        host=host, port=port, disable_telemetry=disable_telemetry, origin_detection_enabled=origin_detection_enabled
    )
