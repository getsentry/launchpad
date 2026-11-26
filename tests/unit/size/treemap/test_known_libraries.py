"""Unit tests for the known-libraries catalog."""

from launchpad.size.treemap.known_libraries import resolve_known_library


def test_resolves_exact_swift_module() -> None:
    assert resolve_known_library("Alamofire") == "Alamofire"
    assert resolve_known_library("Lottie") == "Lottie"
    assert resolve_known_library("RxCocoa") == "RxSwift"


def test_groups_multiple_modules_to_one_library() -> None:
    assert resolve_known_library("FirebaseCore") == "Firebase"
    assert resolve_known_library("FirebaseAnalytics") == "Firebase"


def test_resolves_objc_class_prefix() -> None:
    assert resolve_known_library("FIRApp") == "Firebase"
    assert resolve_known_library("RLMRealm") == "Realm"
    assert resolve_known_library("GMSMapView") == "GoogleMaps"


def test_swift_module_takes_priority_over_prefix() -> None:
    # "Sentry" is both an exact module and an ObjC prefix; either way it resolves
    # to the same library, but the exact-module path should win.
    assert resolve_known_library("Sentry") == "Sentry"


def test_unknown_and_empty_names_return_none() -> None:
    assert resolve_known_library("MyApp") is None
    assert resolve_known_library("AppViewModel") is None
    assert resolve_known_library("") is None
