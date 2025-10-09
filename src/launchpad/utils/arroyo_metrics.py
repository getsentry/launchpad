"""DataDog metrics backend for Arroyo."""

from __future__ import annotations

from typing import Optional, Union

from arroyo.utils.metrics import MetricName, Metrics, Tags

from launchpad.utils.statsd import get_statsd


class DatadogMetricsBackend(Metrics):
    """
    DataDog metrics backend that implements Arroyo's Metrics protocol.

    This bridges Arroyo's metrics interface with DataDog StatsD.
    """

    def __init__(self, group_id: str) -> None:
        self._statsd = get_statsd("sentry.consumer")
        self._constant_tags = {"consumer_group": group_id}

    def increment(
        self,
        name: MetricName,
        value: Union[int, float] = 1,
        tags: Optional[Tags] = None,
    ) -> None:
        """Increments a counter metric by a given value."""
        self._statsd.increment(name, value, tags=self._format_tags(tags))

    def gauge(self, name: MetricName, value: Union[int, float], tags: Optional[Tags] = None) -> None:
        """Sets a gauge metric to the given value."""
        self._statsd.gauge(name, value, tags=self._format_tags(tags))

    def timing(self, name: MetricName, value: Union[int, float], tags: Optional[Tags] = None) -> None:
        """Records a timing metric."""
        self._statsd.timing(name, value, tags=self._format_tags(tags))

    def _format_tags(self, tags: Optional[Tags]) -> Optional[list[str]]:
        """Convert Arroyo tags format to DataDog tags format, merging with constant tags."""
        merged_tags = self._constant_tags.copy()
        if tags:
            merged_tags.update(tags)

        if not merged_tags:
            return None
        return [f"{key}:{value}" for key, value in merged_tags.items()]
