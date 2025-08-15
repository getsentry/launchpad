from launchpad.utils.statsd import get_statsd


def test_statsd_is_singleton():
    assert get_statsd()
    assert get_statsd() is get_statsd()
