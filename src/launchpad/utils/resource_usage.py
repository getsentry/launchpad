import resource
import sys


def get_peak_rss_bytes() -> int:
    """Return the current process's lifetime peak RSS in bytes."""
    peak_rss_bytes = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    # macOS reports bytes; Linux reports KiB.
    if sys.platform != "darwin":
        peak_rss_bytes *= 1024
    return peak_rss_bytes
