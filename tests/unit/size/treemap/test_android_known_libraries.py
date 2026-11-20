"""Unit tests for the Android known-libraries catalog."""

from launchpad.size.treemap.android_known_libraries import resolve_known_library


def test_resolves_prefix_to_library() -> None:
    assert resolve_known_library("androidx.core.app.NotificationCompat") == ("AndroidX", "androidx")
    assert resolve_known_library("kotlin.collections.CollectionsKt") == ("Kotlin", "kotlin")
    assert resolve_known_library("io.sentry.Sentry") == ("Sentry", "io.sentry")


def test_most_specific_prefix_wins() -> None:
    # com.google.firebase is more specific than any shorter com.google.* prefix.
    assert resolve_known_library("com.google.firebase.analytics.FirebaseAnalytics") == (
        "Firebase",
        "com.google.firebase",
    )
    assert resolve_known_library("com.google.android.gms.tasks.Task") == (
        "Google Play Services",
        "com.google.android.gms",
    )


def test_matches_on_package_boundaries() -> None:
    # Exact prefix match (class living directly in the prefix package).
    assert resolve_known_library("androidx") == ("AndroidX", "androidx")
    # A package that merely starts with the prefix string must not match.
    assert resolve_known_library("androidxtra.Foo") is None
    assert resolve_known_library("kotlinpoet.Foo") is None


def test_emergetools_snapshots_is_grouped_but_app_is_not() -> None:
    assert resolve_known_library("com.emergetools.snapshots.SnapshotTest") == (
        "EmergeTools",
        "com.emergetools.snapshots",
    )
    # A first-party Emerge Tools app must not be grouped as a library.
    assert resolve_known_library("com.emergetools.hackernews.MainActivity") is None


def test_unknown_and_empty_names_return_none() -> None:
    assert resolve_known_library("com.example.myapp.MainActivity") is None
    assert resolve_known_library("") is None
