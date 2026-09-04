"""Catalog of well-known Android libraries for DEX treemap grouping.

DEX classes are grouped into a package hierarchy (e.g. ``com`` > ``google`` >
``firebase`` > …). Third-party SDKs are indistinguishable from the app's own code
in that hierarchy. This catalog maps distinctive Java/Kotlin package prefixes to a
canonical library name so the treemap builder can pull recognized classes out and
group them under a single ``Libraries`` node.

Keep entries conservative: use prefixes that are distinctive enough to avoid
colliding with first-party code. In particular, prefer specific sub-packages over
broad vendor roots (e.g. ``com.emergetools.snapshots`` rather than
``com.emergetools``, which would also match an app shipped by Emerge Tools).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class KnownLibrary:
    """A known Android library and the package prefixes used to recognize it."""

    name: str
    # Distinctive package prefixes that map to this library. Matching is done on
    # package boundaries: a prefix matches an FQN that equals it or starts with
    # ``prefix + "."``.
    package_prefixes: tuple[str, ...]


# Curated, non-exhaustive catalog of popular Android libraries. Extend as needed.
KNOWN_LIBRARIES: tuple[KnownLibrary, ...] = (
    # Jetpack / Kotlin
    KnownLibrary("AndroidX", ("androidx",)),
    KnownLibrary("Android Support", ("android.support",)),
    KnownLibrary("Kotlin", ("kotlin", "kotlinx")),
    # Google
    KnownLibrary("Firebase", ("com.google.firebase",)),
    KnownLibrary("Google Play Services", ("com.google.android.gms",)),
    KnownLibrary("Google Play Core", ("com.google.android.play",)),
    KnownLibrary("Material Components", ("com.google.android.material",)),
    KnownLibrary("Gson", ("com.google.gson",)),
    KnownLibrary("Guava", ("com.google.common",)),
    KnownLibrary("Protobuf", ("com.google.protobuf",)),
    KnownLibrary("Dagger", ("dagger",)),
    # Square
    KnownLibrary("OkHttp", ("okhttp3",)),
    KnownLibrary("Okio", ("okio",)),
    KnownLibrary("Retrofit", ("retrofit2",)),
    KnownLibrary("Moshi", ("com.squareup.moshi",)),
    KnownLibrary("Picasso", ("com.squareup.picasso",)),
    KnownLibrary("LeakCanary", ("leakcanary", "com.squareup.leakcanary")),
    # Image loading
    KnownLibrary("Coil", ("coil",)),
    KnownLibrary("Glide", ("com.bumptech.glide",)),
    # Reactive / async
    KnownLibrary("RxJava", ("io.reactivex", "rx")),
    KnownLibrary("Timber", ("timber.log",)),
    KnownLibrary("EventBus", ("org.greenrobot.eventbus",)),
    # Serialization
    KnownLibrary("Jackson", ("com.fasterxml.jackson",)),
    KnownLibrary("Apache Commons", ("org.apache.commons",)),
    # Observability
    KnownLibrary("Sentry", ("io.sentry",)),
    KnownLibrary("Bugsnag", ("com.bugsnag",)),
    KnownLibrary("Datadog", ("com.datadog",)),
    # Analytics / attribution
    KnownLibrary("Amplitude", ("com.amplitude",)),
    KnownLibrary("Mixpanel", ("com.mixpanel",)),
    KnownLibrary("Segment", ("com.segment.analytics",)),
    KnownLibrary("Adjust", ("com.adjust.sdk",)),
    KnownLibrary("AppsFlyer", ("com.appsflyer",)),
    KnownLibrary("Branch", ("io.branch",)),
    KnownLibrary("Braze", ("com.braze", "com.appboy")),
    # Other popular SDKs
    KnownLibrary("Facebook", ("com.facebook",)),
    KnownLibrary("Stripe", ("com.stripe",)),
    KnownLibrary("Lottie", ("com.airbnb.lottie",)),
    KnownLibrary("Realm", ("io.realm",)),
    KnownLibrary("Koin", ("org.koin",)),
    KnownLibrary("Ktor", ("io.ktor",)),
    KnownLibrary("ThreeTenABP", ("org.threeten.bp", "com.jakewharton.threetenabp")),
    KnownLibrary("EmergeTools", ("com.emergetools.snapshots",)),
)


def _build_prefix_index() -> tuple[tuple[str, str], ...]:
    # Sort by descending prefix length so the most specific prefix wins (e.g.
    # ``com.google.firebase`` is preferred over a hypothetical ``com.google``).
    pairs = [(prefix, library.name) for library in KNOWN_LIBRARIES for prefix in library.package_prefixes]
    pairs.sort(key=lambda pair: len(pair[0]), reverse=True)
    return tuple(pairs)


_PREFIX_INDEX = _build_prefix_index()


def resolve_known_library(fqn: str) -> tuple[str, str] | None:
    """Resolve a class FQN to a known library.

    Returns ``(library_name, matched_prefix)`` for the most specific matching
    package prefix, or ``None`` when the FQN doesn't belong to a known library.
    Matching is done on package boundaries so ``androidx`` matches
    ``androidx.core.App`` but not ``androidxfoo.Bar``.
    """
    if not fqn:
        return None

    for prefix, library_name in _PREFIX_INDEX:
        if fqn == prefix or fqn.startswith(prefix + "."):
            return library_name, prefix

    return None
