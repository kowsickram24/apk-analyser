"""
Dependency Detector.

Detects common third-party libraries from DEX package names.
Does NOT invent version numbers.
"""

from __future__ import annotations

from .models import Confidence, Dependency


# ---------------------------------------------------------------------------
# Known dependency rules
# (package_prefix, library_name, confidence)
# ---------------------------------------------------------------------------

_DEPENDENCY_RULES: list[tuple[str, str, Confidence]] = [
    # Firebase
    ("com.google.firebase.analytics", "Firebase Analytics", Confidence.HIGH),
    ("com.google.firebase.crashlytics", "Firebase Crashlytics", Confidence.HIGH),
    ("com.google.firebase.messaging", "Firebase Cloud Messaging", Confidence.HIGH),
    ("com.google.firebase.auth", "Firebase Auth", Confidence.HIGH),
    ("com.google.firebase.firestore", "Firebase Firestore", Confidence.HIGH),
    ("com.google.firebase.database", "Firebase Realtime Database", Confidence.HIGH),
    ("com.google.firebase.storage", "Firebase Storage", Confidence.HIGH),
    ("com.google.firebase.remoteconfig", "Firebase Remote Config", Confidence.HIGH),
    ("com.google.firebase.perf", "Firebase Performance", Confidence.HIGH),
    ("com.google.firebase", "Firebase", Confidence.MEDIUM),

    # Google Play / Services
    ("com.google.android.gms.maps", "Google Maps SDK", Confidence.HIGH),
    ("com.google.android.gms.auth", "Google Auth", Confidence.HIGH),
    ("com.google.android.gms.location", "Google Location Services", Confidence.HIGH),
    ("com.google.android.gms.ads", "Google Mobile Ads (AdMob)", Confidence.HIGH),
    ("com.google.android.gms", "Google Play Services", Confidence.MEDIUM),
    ("com.google.android.play", "Google Play Core", Confidence.HIGH),

    # Networking
    ("okhttp3", "OkHttp 3", Confidence.HIGH),
    ("okhttp", "OkHttp", Confidence.HIGH),
    ("retrofit2", "Retrofit 2", Confidence.HIGH),
    ("retrofit", "Retrofit", Confidence.MEDIUM),
    ("com.squareup.okhttp3", "OkHttp 3", Confidence.HIGH),
    ("com.squareup.retrofit2", "Retrofit 2", Confidence.HIGH),
    ("com.squareup.okio", "Okio", Confidence.HIGH),
    ("io.ktor", "Ktor", Confidence.HIGH),
    ("io.grpc", "gRPC", Confidence.HIGH),

    # Image loading
    ("com.bumptech.glide", "Glide", Confidence.HIGH),
    ("com.squareup.picasso", "Picasso", Confidence.HIGH),
    ("coil", "Coil", Confidence.HIGH),
    ("io.coil", "Coil", Confidence.HIGH),
    ("com.facebook.fresco", "Fresco (Facebook)", Confidence.HIGH),

    # Crash / Error reporting
    ("io.sentry", "Sentry", Confidence.HIGH),
    ("com.bugsnag.android", "Bugsnag", Confidence.HIGH),
    ("com.datadog", "Datadog", Confidence.HIGH),
    ("com.instabug", "Instabug", Confidence.HIGH),
    ("com.rollbar", "Rollbar", Confidence.HIGH),

    # Analytics
    ("com.amplitude.android", "Amplitude", Confidence.HIGH),
    ("com.mixpanel.android", "Mixpanel", Confidence.HIGH),
    ("com.segment.analytics", "Segment", Confidence.HIGH),
    ("com.posthog", "PostHog", Confidence.HIGH),
    ("com.appsflyer", "AppsFlyer", Confidence.HIGH),
    ("com.adjust.sdk", "Adjust", Confidence.HIGH),
    ("com.braze", "Braze", Confidence.HIGH),
    ("com.clevertap", "CleverTap", Confidence.HIGH),
    ("com.moengage", "MoEngage", Confidence.HIGH),
    ("io.intercom.android", "Intercom", Confidence.HIGH),

    # Push notifications
    ("com.onesignal", "OneSignal", Confidence.HIGH),
    ("com.urbanairship", "Airship", Confidence.HIGH),
    ("com.pusher", "Pusher", Confidence.HIGH),

    # Payments
    ("com.stripe.android", "Stripe", Confidence.HIGH),
    ("com.braintreepayments", "Braintree", Confidence.HIGH),
    ("com.paypal.android", "PayPal", Confidence.HIGH),
    ("com.revenuecat", "RevenueCat", Confidence.HIGH),
    ("com.adapty", "Adapty", Confidence.HIGH),

    # Databases
    ("androidx.room", "Room (Jetpack)", Confidence.HIGH),
    ("io.realm", "Realm", Confidence.HIGH),
    ("com.couchbase.lite", "Couchbase Lite", Confidence.HIGH),
    ("net.sqlcipher", "SQLCipher", Confidence.HIGH),
    ("com.tencent.mmkv", "MMKV", Confidence.HIGH),
    ("com.getkeepsafe.relinker", "ReLinker", Confidence.HIGH),

    # Dependency Injection
    ("dagger.hilt", "Hilt (Dagger)", Confidence.HIGH),
    ("dagger", "Dagger", Confidence.MEDIUM),
    ("org.koin", "Koin", Confidence.HIGH),
    ("toothpick", "Toothpick", Confidence.HIGH),

    # Architecture / Reactive
    ("io.reactivex.rxjava3", "RxJava 3", Confidence.HIGH),
    ("io.reactivex.rxjava2", "RxJava 2", Confidence.HIGH),
    ("io.reactivex", "RxJava", Confidence.MEDIUM),
    ("kotlinx.coroutines", "Kotlin Coroutines", Confidence.HIGH),
    ("androidx.lifecycle", "Jetpack Lifecycle", Confidence.HIGH),
    ("androidx.navigation", "Jetpack Navigation", Confidence.HIGH),
    ("androidx.paging", "Jetpack Paging", Confidence.HIGH),
    ("androidx.work", "WorkManager", Confidence.HIGH),

    # Maps / Location
    ("com.mapbox.maps", "Mapbox Maps", Confidence.HIGH),
    ("com.here.sdk", "HERE Maps", Confidence.HIGH),
    ("com.yandex.mapkit", "Yandex Maps", Confidence.HIGH),

    # Video / Media
    ("com.google.android.exoplayer2", "ExoPlayer 2", Confidence.HIGH),
    ("androidx.media3", "Media3 / ExoPlayer 3", Confidence.HIGH),

    # JSON
    ("com.google.gson", "Gson", Confidence.HIGH),
    ("com.fasterxml.jackson", "Jackson", Confidence.HIGH),
    ("kotlinx.serialization", "Kotlinx Serialization", Confidence.HIGH),
    ("org.json", "org.json", Confidence.MEDIUM),

    # Social / Auth
    ("com.facebook.login", "Facebook Login", Confidence.HIGH),
    ("com.facebook.share", "Facebook Share", Confidence.HIGH),
    ("com.twitter.sdk", "Twitter SDK", Confidence.HIGH),
    ("com.google.android.recaptcha", "reCAPTCHA", Confidence.HIGH),

    # Security / Crypto
    ("androidx.security.crypto", "Jetpack Security Crypto", Confidence.HIGH),
    ("org.bouncycastle", "Bouncy Castle", Confidence.HIGH),

    # Testing (may be in debug builds)
    ("androidx.test", "AndroidX Test", Confidence.HIGH),
    ("io.mockk", "MockK", Confidence.HIGH),
    ("org.mockito", "Mockito", Confidence.HIGH),
    ("junit", "JUnit", Confidence.MEDIUM),

    # React Native community libs
    ("com.reactnativecommunity", "React Native Community Libraries", Confidence.HIGH),
    ("com.swmansion", "Software Mansion (RN)", Confidence.HIGH),
    ("com.th3rdwave", "React Native Screens", Confidence.HIGH),
    ("com.horcrux.svg", "React Native SVG", Confidence.HIGH),

    # Flutter plugins
    ("io.flutter.plugins", "Flutter Plugins", Confidence.HIGH),

    # Expo
    ("expo", "Expo SDK", Confidence.HIGH),
    ("host.exp", "Expo", Confidence.HIGH),

    # Ads
    ("com.mopub", "MoPub", Confidence.HIGH),
    ("com.ironsource.mediationsdk", "IronSource", Confidence.HIGH),
    ("com.applovin", "AppLovin MAX", Confidence.HIGH),
    ("com.chartboost", "Chartboost", Confidence.HIGH),
    ("com.unity3d.ads", "Unity Ads", Confidence.HIGH),
    ("com.vungle", "Vungle", Confidence.HIGH),
]


def detect_dependencies(packages: list[str]) -> list[Dependency]:
    """
    Detect third-party dependencies from the package list extracted from DEX files.
    """
    found: dict[str, Dependency] = {}  # name → Dependency (deduplicate)

    for package_prefix, lib_name, confidence in _DEPENDENCY_RULES:
        prefix_lower = package_prefix.lower()
        matched = any(
            p.lower() == prefix_lower or p.lower().startswith(prefix_lower + ".")
            for p in packages
        )
        if matched and lib_name not in found:
            found[lib_name] = Dependency(
                name=lib_name,
                version="",   # never invent versions
                evidence_type="DEX package",
                confidence=confidence,
                package_prefix=package_prefix,
            )

    # Sort by confidence then name
    _order = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2, Confidence.UNKNOWN: 3}
    return sorted(found.values(), key=lambda d: (_order[d.confidence], d.name))
