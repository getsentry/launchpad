"""Catalog of well-known iOS libraries for treemap grouping.

Statically-linked third-party libraries show up in the main binary as Swift module
nodes (e.g. ``Alamofire``) or Objective-C class nodes (e.g. ``FIRApp``). This catalog
lets the treemap builder recognize those nodes and group them under a single
``Libraries`` parent so reviewers can see how much size known SDKs contribute.

Keep entries conservative: exact Swift module names, and distinctive Objective-C class
prefixes (3+ chars) that are unlikely to collide with first-party code.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class KnownLibrary:
    """A known iOS library and the identifiers used to recognize it."""

    name: str
    # Exact Swift module names that map to this library.
    swift_modules: frozenset[str] = field(default_factory=frozenset)
    # Distinctive Objective-C class-name prefixes that map to this library.
    objc_prefixes: tuple[str, ...] = ()


# Curated, non-exhaustive catalog of popular iOS libraries. Extend as needed.
KNOWN_LIBRARIES: tuple[KnownLibrary, ...] = (
    KnownLibrary("Sentry", frozenset({"Sentry", "SentrySwift", "SentrySwiftUI"}), ("Sentry",)),
    KnownLibrary(
        "Firebase",
        frozenset(
            {
                "FirebaseCore",
                "FirebaseCoreInternal",
                "FirebaseAnalytics",
                "FirebaseCrashlytics",
                "FirebaseMessaging",
                "FirebaseFirestore",
                "FirebaseFirestoreSwift",
                "FirebaseAuth",
                "FirebaseDatabase",
                "FirebaseStorage",
                "FirebaseRemoteConfig",
                "FirebaseInstallations",
                "FirebasePerformance",
                "FirebaseDynamicLinks",
                "FirebaseInAppMessaging",
                "FirebaseAppCheck",
            }
        ),
        ("FIR", "FBLPromise", "GUL"),
    ),
    KnownLibrary("Alamofire", frozenset({"Alamofire"})),
    KnownLibrary("Lottie", frozenset({"Lottie"})),
    KnownLibrary("Kingfisher", frozenset({"Kingfisher"})),
    KnownLibrary("SnapKit", frozenset({"SnapKit"})),
    KnownLibrary("Nuke", frozenset({"Nuke", "NukeUI"})),
    KnownLibrary("SDWebImage", frozenset({"SDWebImage", "SDWebImageSwiftUI"}), ("SDWeb", "SDImage", "SDAnimated")),
    KnownLibrary("RxSwift", frozenset({"RxSwift", "RxCocoa", "RxRelay", "RxBlocking"})),
    KnownLibrary("Realm", frozenset({"Realm", "RealmSwift"}), ("RLM",)),
    KnownLibrary("GoogleMaps", frozenset({"GoogleMaps", "GoogleMapsBase"}), ("GMS",)),
    KnownLibrary("GoogleSignIn", frozenset({"GoogleSignIn"}), ("GID",)),
    KnownLibrary("Facebook", frozenset({"FacebookCore", "FacebookLogin", "FacebookShare"}), ("FBSDK",)),
    KnownLibrary("AFNetworking", frozenset(), ("AFHTTP", "AFURL", "AFNetwork", "AFSecurity")),
    KnownLibrary("Stripe", frozenset({"Stripe", "StripeCore", "StripePayments", "StripeUICore"}), ("STP",)),
    KnownLibrary("Branch", frozenset({"BranchSDK"}), ("BNC", "Branch")),
    KnownLibrary("Mixpanel", frozenset({"Mixpanel"}), ("Mixpanel",)),
    KnownLibrary("Amplitude", frozenset({"Amplitude", "AmplitudeSwift"}), ("AMP",)),
    KnownLibrary("Segment", frozenset({"Segment"}), ("SEG",)),
    KnownLibrary("Adjust", frozenset({"Adjust", "AdjustSdk"}), ("ADJ",)),
    KnownLibrary("AppsFlyer", frozenset({"AppsFlyerLib"}), ("AppsFlyer",)),
    KnownLibrary("Bugsnag", frozenset({"Bugsnag"}), ("BSG", "Bugsnag")),
    KnownLibrary(
        "Datadog", frozenset({"Datadog", "DatadogCore", "DatadogLogs", "DatadogRUM", "DatadogTrace"}), ("DD",)
    ),
    KnownLibrary("Charts", frozenset({"Charts", "DGCharts"})),
    KnownLibrary("SwiftyJSON", frozenset({"SwiftyJSON"})),
    KnownLibrary("Moya", frozenset({"Moya"})),
    KnownLibrary("PromiseKit", frozenset({"PromiseKit"})),
    KnownLibrary("EmergeTools", frozenset({"EmergeSnapshots", "SnapshotPreferences", "SnapshotPreviewsCore"})),
)


def _build_swift_module_index() -> dict[str, str]:
    index: dict[str, str] = {}
    for library in KNOWN_LIBRARIES:
        for module in library.swift_modules:
            index[module] = library.name
    return index


def _build_objc_prefix_index() -> tuple[tuple[str, str], ...]:
    # Sort by descending prefix length so the most specific prefix wins.
    pairs = [(prefix, library.name) for library in KNOWN_LIBRARIES for prefix in library.objc_prefixes]
    pairs.sort(key=lambda pair: len(pair[0]), reverse=True)
    return tuple(pairs)


_SWIFT_MODULE_INDEX = _build_swift_module_index()
_OBJC_PREFIX_INDEX = _build_objc_prefix_index()


def resolve_known_library(node_name: str) -> str | None:
    """Resolve a treemap node name to a known library's canonical name.

    Matches an exact Swift module name first, then a distinctive Objective-C class
    prefix. Returns ``None`` when the name doesn't correspond to a known library.
    """
    if not node_name:
        return None

    library = _SWIFT_MODULE_INDEX.get(node_name)
    if library is not None:
        return library

    for prefix, library_name in _OBJC_PREFIX_INDEX:
        if node_name.startswith(prefix):
            return library_name

    return None
