"""
Framework Fingerprint Engine.

Rule-based, deterministic framework detection.
Each detector returns a FrameworkDetection with explicit evidence.

Evidence scoring:
  STRONG × 3 points
  MEDIUM × 2 points
  WEAK   × 1 point

Confidence thresholds:
  HIGH    ≥ 6 points  (at least 2 strong signals)
  MEDIUM  ≥ 3 points
  LOW     ≥ 1 point
  UNKNOWN = 0
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

from .models import (
    Confidence,
    Evidence,
    EvidenceStrength,
    EvidenceType,
    FrameworkDetection,
    NativeLibrary,
    NegativeEvidence,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _score(evidence: list[Evidence]) -> int:
    total = 0
    for e in evidence:
        if e.strength == EvidenceStrength.STRONG:
            total += 3
        elif e.strength == EvidenceStrength.MEDIUM:
            total += 2
        else:
            total += 1
    return total


def _to_confidence(score: int) -> Confidence:
    if score >= 6:
        return Confidence.HIGH
    if score >= 3:
        return Confidence.MEDIUM
    if score >= 1:
        return Confidence.LOW
    return Confidence.UNKNOWN


def _has_so(libs: list[NativeLibrary], name: str) -> Optional[NativeLibrary]:
    name_lower = name.lower()
    for lib in libs:
        if lib.name.lower() == name_lower:
            return lib
    return None


def _has_so_prefix(libs: list[NativeLibrary], prefix: str) -> list[NativeLibrary]:
    prefix_lower = prefix.lower()
    return [lib for lib in libs if lib.name.lower().startswith(prefix_lower)]


def _has_package(packages: list[str], prefix: str) -> bool:
    return any(p == prefix or p.startswith(prefix + ".") for p in packages)


def _file_exists(extract_dir: str, rel_path: str) -> bool:
    return (Path(extract_dir) / rel_path).exists()


def _any_file_in_dir(extract_dir: str, rel_dir: str) -> bool:
    d = Path(extract_dir) / rel_dir
    return d.exists() and d.is_dir() and any(d.iterdir())


def _file_contains(extract_dir: str, rel_path: str, needle: str) -> bool:
    p = Path(extract_dir) / rel_path
    if not p.exists() or p.stat().st_size > 50 * 1024 * 1024:
        return False
    try:
        return needle in p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False


def _glob_exists(extract_dir: str, pattern: str) -> list[Path]:
    return list(Path(extract_dir).glob(pattern))


def _so_library_evidence(lib: NativeLibrary, description: str) -> Evidence:
    return Evidence(
        type=EvidenceType.NATIVE_LIBRARY,
        artifact=f"lib/{lib.abi}/{lib.name}",
        strength=EvidenceStrength.STRONG,
        description=description,
        location=f"lib/{lib.abi}/{lib.name}",
    )


def _package_evidence(pkg: str, strength: EvidenceStrength, description: str) -> Evidence:
    return Evidence(
        type=EvidenceType.DEX_PACKAGE,
        artifact=pkg,
        strength=strength,
        description=description,
    )


def _asset_evidence(path: str, strength: EvidenceStrength, description: str) -> Evidence:
    return Evidence(
        type=EvidenceType.ASSET_FILE,
        artifact=path,
        strength=strength,
        description=description,
        location=path,
    )


def _manifest_evidence(attribute: str, strength: EvidenceStrength, description: str) -> Evidence:
    return Evidence(
        type=EvidenceType.MANIFEST_ATTRIBUTE,
        artifact=attribute,
        strength=strength,
        description=description,
    )


def _component_evidence(class_name: str, strength: EvidenceStrength, description: str) -> Evidence:
    return Evidence(
        type=EvidenceType.MANIFEST_COMPONENT,
        artifact=class_name,
        strength=strength,
        description=description,
    )


# ---------------------------------------------------------------------------
# Individual Framework Detectors
# ---------------------------------------------------------------------------

class ReactNativeDetector:
    NAME = "React Native"

    STRONG_PACKAGES = [
        "com.facebook.react",
        "com.facebook.hermes",
        "com.facebook.jni",
    ]
    MEDIUM_PACKAGES = [
        "com.facebook.react.devsupport",
        "com.reactnativecommunity",
        "com.th3rdwave",   # react-native-screens
    ]
    WEAK_PACKAGES = [
        "com.facebook.soloader",
    ]

    STRONG_LIBS = ["libhermes.so", "libreactnative.so", "libreact_native.so"]
    MEDIUM_LIBS = ["libjscexecutor.so", "libjsi.so", "libfabricjni.so", "librnscreens.so"]
    WEAK_LIBS   = ["libreanimated.so", "librnsvg.so", "libjsc.so"]

    BUNDLE_FILES = [
        "assets/index.android.bundle",
        "assets/index.android.js",
        "assets/main.android.js",
        "assets/main.jsbundle",
    ]

    NEGATIVE = [
        ("libflutter.so", "Flutter engine not detected"),
        ("assets/flutter_assets/", "Flutter assets not detected"),
    ]

    @classmethod
    def detect(
        cls,
        extract_dir: str,
        packages: list[str],
        libs: list[NativeLibrary],
        activities: list[str],
    ) -> FrameworkDetection:
        evidence: list[Evidence] = []
        neg_evidence: list[NegativeEvidence] = []

        # Native libraries
        for lib_name in cls.STRONG_LIBS:
            found = _has_so(libs, lib_name)
            if not found:
                # Try without lib prefix
                found = _has_so(libs, lib_name)
            if found:
                evidence.append(_so_library_evidence(found, f"{lib_name} detected"))

        for lib_name in cls.MEDIUM_LIBS:
            found = _has_so(libs, lib_name)
            if found:
                evidence.append(Evidence(
                    type=EvidenceType.NATIVE_LIBRARY,
                    artifact=f"lib/{found.abi}/{found.name}",
                    strength=EvidenceStrength.MEDIUM,
                    description=f"{lib_name} detected",
                    location=f"lib/{found.abi}/{found.name}",
                ))

        for lib_name in cls.WEAK_LIBS:
            found = _has_so(libs, lib_name)
            if found:
                evidence.append(Evidence(
                    type=EvidenceType.NATIVE_LIBRARY,
                    artifact=f"lib/{found.abi}/{found.name}",
                    strength=EvidenceStrength.WEAK,
                    description=f"{lib_name} detected",
                    location=f"lib/{found.abi}/{found.name}",
                ))

        # DEX packages
        for pkg in cls.STRONG_PACKAGES:
            if _has_package(packages, pkg):
                evidence.append(_package_evidence(
                    pkg, EvidenceStrength.STRONG,
                    f"{pkg}.* classes detected"
                ))

        for pkg in cls.MEDIUM_PACKAGES:
            if _has_package(packages, pkg):
                evidence.append(_package_evidence(
                    pkg, EvidenceStrength.MEDIUM,
                    f"{pkg}.* classes detected"
                ))

        for pkg in cls.WEAK_PACKAGES:
            if _has_package(packages, pkg):
                evidence.append(_package_evidence(
                    pkg, EvidenceStrength.WEAK,
                    f"{pkg}.* classes detected"
                ))

        # JS bundle
        for bundle_path in cls.BUNDLE_FILES:
            if _file_exists(extract_dir, bundle_path):
                evidence.append(_asset_evidence(
                    bundle_path, EvidenceStrength.STRONG,
                    "React Native JS bundle detected"
                ))
                break

        # Activity check
        for act in activities:
            if "ReactActivity" in act or "ReactNativeActivity" in act:
                evidence.append(_component_evidence(
                    act, EvidenceStrength.STRONG,
                    "ReactActivity component detected"
                ))
                break

        # Negative evidence
        if not _has_so(libs, "libflutter.so"):
            neg_evidence.append(NegativeEvidence("libflutter.so", "Flutter engine not detected"))
        if not _any_file_in_dir(extract_dir, "assets/flutter_assets"):
            neg_evidence.append(NegativeEvidence("assets/flutter_assets/", "Flutter assets not detected"))

        # Determine runtime
        sub_techs: dict[str, str] = {}
        if _has_so(libs, "libhermes.so"):
            sub_techs["js_runtime"] = "Hermes"
        elif _has_so(libs, "libjscexecutor.so") or _has_so(libs, "libjsc.so"):
            sub_techs["js_runtime"] = "JavaScriptCore"

        confidence = _to_confidence(_score(evidence))
        return FrameworkDetection(
            name=cls.NAME,
            confidence=confidence,
            evidence=evidence,
            negative_evidence=neg_evidence,
            sub_technologies=sub_techs,
        )


class FlutterDetector:
    NAME = "Flutter"

    STRONG_LIBS = ["libflutter.so"]
    MEDIUM_LIBS = ["libapp.so"]
    STRONG_ASSETS = ["assets/flutter_assets/AssetManifest.json", "assets/flutter_assets/"]
    STRONG_PACKAGES = ["io.flutter"]
    MEDIUM_PACKAGES = ["io.flutter.embedding", "io.flutter.plugin"]

    NEGATIVE = [
        ("libhermes.so", "Hermes JS engine not detected"),
        ("assets/index.android.bundle", "React Native bundle not detected"),
    ]

    @classmethod
    def detect(
        cls,
        extract_dir: str,
        packages: list[str],
        libs: list[NativeLibrary],
        activities: list[str],
    ) -> FrameworkDetection:
        evidence: list[Evidence] = []
        neg_evidence: list[NegativeEvidence] = []

        for lib_name in cls.STRONG_LIBS:
            found = _has_so(libs, lib_name)
            if found:
                evidence.append(_so_library_evidence(found, f"{lib_name} — Flutter engine"))

        for lib_name in cls.MEDIUM_LIBS:
            found = _has_so(libs, lib_name)
            if found:
                evidence.append(Evidence(
                    type=EvidenceType.NATIVE_LIBRARY,
                    artifact=f"lib/{found.abi}/{found.name}",
                    strength=EvidenceStrength.MEDIUM,
                    description=f"{lib_name} — Flutter compiled app",
                    location=f"lib/{found.abi}/{found.name}",
                ))

        # Flutter assets directory
        if _any_file_in_dir(extract_dir, "assets/flutter_assets"):
            evidence.append(_asset_evidence(
                "assets/flutter_assets/",
                EvidenceStrength.STRONG,
                "Flutter assets directory present"
            ))

        if _file_exists(extract_dir, "assets/flutter_assets/AssetManifest.json"):
            evidence.append(_asset_evidence(
                "assets/flutter_assets/AssetManifest.json",
                EvidenceStrength.STRONG,
                "Flutter AssetManifest.json detected"
            ))

        if _file_exists(extract_dir, "assets/flutter_assets/FontManifest.json"):
            evidence.append(_asset_evidence(
                "assets/flutter_assets/FontManifest.json",
                EvidenceStrength.MEDIUM,
                "Flutter FontManifest.json detected"
            ))

        for pkg in cls.STRONG_PACKAGES:
            if _has_package(packages, pkg):
                evidence.append(_package_evidence(
                    pkg, EvidenceStrength.STRONG,
                    f"{pkg}.* classes detected"
                ))

        for pkg in cls.MEDIUM_PACKAGES:
            if _has_package(packages, pkg):
                evidence.append(_package_evidence(
                    pkg, EvidenceStrength.MEDIUM,
                    f"{pkg}.* classes detected"
                ))

        for act in activities:
            if "FlutterActivity" in act or "FlutterFragmentActivity" in act:
                evidence.append(_component_evidence(
                    act, EvidenceStrength.STRONG,
                    "FlutterActivity component detected"
                ))
                break

        # Negative
        if not _has_so(libs, "libhermes.so"):
            neg_evidence.append(NegativeEvidence("libhermes.so", "Hermes JS engine not detected"))
        for bundle_path in ["assets/index.android.bundle", "assets/main.jsbundle"]:
            if not _file_exists(extract_dir, bundle_path):
                neg_evidence.append(NegativeEvidence(bundle_path, "React Native bundle not detected"))
                break

        confidence = _to_confidence(_score(evidence))
        return FrameworkDetection(
            name=cls.NAME,
            confidence=confidence,
            evidence=evidence,
            negative_evidence=neg_evidence,
            sub_technologies={"engine": "Flutter"} if evidence else {},
        )


class UnityDetector:
    NAME = "Unity"

    STRONG_LIBS = ["libunity.so", "libil2cpp.so"]
    MEDIUM_LIBS = ["libunityplayer.so"]
    STRONG_ASSETS = ["assets/bin/Data/"]
    STRONG_PACKAGES = ["com.unity3d"]
    MEDIUM_PACKAGES = ["com.unity"]

    @classmethod
    def detect(
        cls,
        extract_dir: str,
        packages: list[str],
        libs: list[NativeLibrary],
        activities: list[str],
    ) -> FrameworkDetection:
        evidence: list[Evidence] = []

        for lib_name in cls.STRONG_LIBS:
            found = _has_so(libs, lib_name)
            if found:
                evidence.append(_so_library_evidence(found, f"{lib_name} — Unity engine"))

        for lib_name in cls.MEDIUM_LIBS:
            found = _has_so(libs, lib_name)
            if found:
                evidence.append(Evidence(
                    type=EvidenceType.NATIVE_LIBRARY,
                    artifact=f"lib/{found.abi}/{found.name}",
                    strength=EvidenceStrength.MEDIUM,
                    description=f"{lib_name} — Unity player",
                    location=f"lib/{found.abi}/{found.name}",
                ))

        if _any_file_in_dir(extract_dir, "assets/bin/Data"):
            evidence.append(_asset_evidence(
                "assets/bin/Data/",
                EvidenceStrength.STRONG,
                "Unity assets data directory"
            ))

        for pkg in cls.STRONG_PACKAGES:
            if _has_package(packages, pkg):
                evidence.append(_package_evidence(
                    pkg, EvidenceStrength.STRONG,
                    f"{pkg}.* Unity classes detected"
                ))

        for act in activities:
            if "UnityPlayerActivity" in act or "UnityPlayer" in act:
                evidence.append(_component_evidence(
                    act, EvidenceStrength.STRONG,
                    "Unity player activity detected"
                ))
                break

        # IL2CPP vs Mono
        sub_techs: dict[str, str] = {}
        if _has_so(libs, "libil2cpp.so"):
            sub_techs["runtime"] = "IL2CPP"
        elif _has_so(libs, "libmono.so") or _has_so(libs, "libmonosgen-2.0.so"):
            sub_techs["runtime"] = "Mono"

        confidence = _to_confidence(_score(evidence))
        return FrameworkDetection(
            name=cls.NAME,
            confidence=confidence,
            evidence=evidence,
            sub_technologies=sub_techs,
        )


class UnrealDetector:
    NAME = "Unreal Engine"

    STRONG_LIBS = ["libUnreal.so", "libUE4.so", "libUE5.so", "libUEGame.so"]
    MEDIUM_LIBS = ["libGamekit.so", "libEpicGames.so"]
    STRONG_PACKAGES = ["com.epicgames.unreal", "com.epicgames.ue4", "com.epicgames.ue5"]

    @classmethod
    def detect(
        cls,
        extract_dir: str,
        packages: list[str],
        libs: list[NativeLibrary],
        activities: list[str],
    ) -> FrameworkDetection:
        evidence: list[Evidence] = []

        for lib_name in cls.STRONG_LIBS:
            found = _has_so(libs, lib_name)
            if not found:
                # Case-insensitive search
                found = next(
                    (l for l in libs if l.name.lower() == lib_name.lower()), None
                )
            if found:
                evidence.append(_so_library_evidence(found, f"{found.name} — Unreal Engine"))

        for lib_name in cls.MEDIUM_LIBS:
            found = _has_so(libs, lib_name)
            if found:
                evidence.append(Evidence(
                    type=EvidenceType.NATIVE_LIBRARY,
                    artifact=f"lib/{found.abi}/{found.name}",
                    strength=EvidenceStrength.MEDIUM,
                    description=f"{found.name} — Unreal Engine",
                    location=f"lib/{found.abi}/{found.name}",
                ))

        for pkg in cls.STRONG_PACKAGES:
            if _has_package(packages, pkg):
                evidence.append(_package_evidence(
                    pkg, EvidenceStrength.STRONG,
                    f"{pkg}.* Unreal classes detected"
                ))

        for pkg in ["com.epicgames"]:
            if _has_package(packages, pkg):
                evidence.append(_package_evidence(
                    pkg, EvidenceStrength.MEDIUM,
                    "Epic Games package detected"
                ))

        sub_techs: dict[str, str] = {}
        if _has_so(libs, "libUE5.so") or _has_package(packages, "com.epicgames.ue5"):
            sub_techs["version"] = "Unreal Engine 5"
        elif _has_so(libs, "libUE4.so") or _has_package(packages, "com.epicgames.ue4"):
            sub_techs["version"] = "Unreal Engine 4"

        confidence = _to_confidence(_score(evidence))
        return FrameworkDetection(
            name=cls.NAME,
            confidence=confidence,
            evidence=evidence,
            sub_technologies=sub_techs,
        )


class CordovaDetector:
    NAME = "Apache Cordova"

    STRONG_ASSETS = ["assets/www/cordova.js", "assets/www/cordova_plugins.js"]
    MEDIUM_ASSETS = ["assets/www/"]
    STRONG_PACKAGES = ["org.apache.cordova"]
    MEDIUM_PACKAGES = ["com.ionic"]

    @classmethod
    def detect(
        cls,
        extract_dir: str,
        packages: list[str],
        libs: list[NativeLibrary],
        activities: list[str],
    ) -> FrameworkDetection:
        evidence: list[Evidence] = []

        for asset in cls.STRONG_ASSETS:
            if _file_exists(extract_dir, asset):
                evidence.append(_asset_evidence(asset, EvidenceStrength.STRONG, f"{asset} detected"))

        if _any_file_in_dir(extract_dir, "assets/www"):
            evidence.append(_asset_evidence(
                "assets/www/", EvidenceStrength.MEDIUM,
                "Cordova/hybrid web assets directory"
            ))

        for pkg in cls.STRONG_PACKAGES:
            if _has_package(packages, pkg):
                evidence.append(_package_evidence(
                    pkg, EvidenceStrength.STRONG,
                    f"Apache Cordova package detected"
                ))

        # Check config.xml
        if _file_exists(extract_dir, "assets/www/config.xml"):
            evidence.append(_asset_evidence(
                "assets/www/config.xml", EvidenceStrength.MEDIUM,
                "Cordova config.xml detected"
            ))

        confidence = _to_confidence(_score(evidence))
        return FrameworkDetection(
            name=cls.NAME,
            confidence=confidence,
            evidence=evidence,
        )


class IonicDetector:
    NAME = "Ionic"

    STRONG_PACKAGES = ["io.ionic", "com.ionicframework"]
    STRONG_ASSETS = ["assets/www/index.html"]  # with ionic content
    MEDIUM_PACKAGES = ["com.ionic.portals"]

    @classmethod
    def detect(
        cls,
        extract_dir: str,
        packages: list[str],
        libs: list[NativeLibrary],
        activities: list[str],
    ) -> FrameworkDetection:
        evidence: list[Evidence] = []

        for pkg in cls.STRONG_PACKAGES:
            if _has_package(packages, pkg):
                evidence.append(_package_evidence(
                    pkg, EvidenceStrength.STRONG,
                    "Ionic framework package detected"
                ))

        for pkg in cls.MEDIUM_PACKAGES:
            if _has_package(packages, pkg):
                evidence.append(_package_evidence(
                    pkg, EvidenceStrength.MEDIUM,
                    "Ionic Portals package detected"
                ))

        # Check for Ionic in www/index.html
        if _file_contains(extract_dir, "assets/www/index.html", "ionic"):
            evidence.append(_asset_evidence(
                "assets/www/index.html", EvidenceStrength.MEDIUM,
                "Ionic reference in www/index.html"
            ))

        confidence = _to_confidence(_score(evidence))
        return FrameworkDetection(
            name=cls.NAME,
            confidence=confidence,
            evidence=evidence,
        )


class CapacitorDetector:
    NAME = "Capacitor"

    STRONG_PACKAGES = ["com.getcapacitor", "com.capacitorjs"]
    STRONG_ASSETS = ["assets/capacitor.config.json", "assets/capacitor.config.ts"]

    @classmethod
    def detect(
        cls,
        extract_dir: str,
        packages: list[str],
        libs: list[NativeLibrary],
        activities: list[str],
    ) -> FrameworkDetection:
        evidence: list[Evidence] = []

        for pkg in cls.STRONG_PACKAGES:
            if _has_package(packages, pkg):
                evidence.append(_package_evidence(
                    pkg, EvidenceStrength.STRONG,
                    "Capacitor package detected"
                ))

        for asset in cls.STRONG_ASSETS:
            if _file_exists(extract_dir, asset):
                evidence.append(_asset_evidence(
                    asset, EvidenceStrength.STRONG, f"{asset} detected"
                ))

        confidence = _to_confidence(_score(evidence))
        return FrameworkDetection(
            name=cls.NAME,
            confidence=confidence,
            evidence=evidence,
        )


class XamarinMauiDetector:
    NAME = "Xamarin / .NET MAUI"

    STRONG_LIBS = ["libmono.so", "libmonosgen-2.0.so", "libxamarin.so", "libxamarin-app.so"]
    STRONG_PACKAGES = [
        "mono.android",
        "com.xamarin",
        "microsoft.maui",
        "Microsoft.Maui",
    ]
    MEDIUM_PACKAGES = ["Mono.Android", "Xamarin.Android", "Xamarin.Forms"]
    STRONG_ASSETS = ["assemblies/"]

    @classmethod
    def detect(
        cls,
        extract_dir: str,
        packages: list[str],
        libs: list[NativeLibrary],
        activities: list[str],
    ) -> FrameworkDetection:
        evidence: list[Evidence] = []

        for lib_name in cls.STRONG_LIBS:
            found = _has_so(libs, lib_name)
            if found:
                evidence.append(_so_library_evidence(found, f"{lib_name} — Mono/.NET runtime"))

        for pkg in cls.STRONG_PACKAGES:
            pkg_lower = pkg.lower()
            if any(p.lower() == pkg_lower or p.lower().startswith(pkg_lower + ".") for p in packages):
                evidence.append(_package_evidence(
                    pkg, EvidenceStrength.STRONG,
                    f"Mono/Xamarin package detected"
                ))

        for pkg in cls.MEDIUM_PACKAGES:
            pkg_lower = pkg.lower()
            if any(p.lower() == pkg_lower or p.lower().startswith(pkg_lower + ".") for p in packages):
                evidence.append(_package_evidence(
                    pkg, EvidenceStrength.MEDIUM,
                    f"Xamarin package detected"
                ))

        # Assemblies directory (Xamarin ships .NET assemblies)
        if _any_file_in_dir(extract_dir, "assemblies"):
            evidence.append(_asset_evidence(
                "assemblies/", EvidenceStrength.STRONG,
                ".NET assembly directory detected"
            ))

        sub_techs: dict[str, str] = {}
        if any(_has_package(packages, p) for p in ["microsoft.maui", "Microsoft.Maui"]):
            sub_techs["framework"] = ".NET MAUI"
        elif any(_has_package(packages, p) for p in ["com.xamarin", "Xamarin.Forms"]):
            sub_techs["framework"] = "Xamarin.Forms"
        if any(_has_so(libs, l) for l in cls.STRONG_LIBS):
            sub_techs["runtime"] = "Mono"

        confidence = _to_confidence(_score(evidence))
        return FrameworkDetection(
            name=cls.NAME,
            confidence=confidence,
            evidence=evidence,
            sub_technologies=sub_techs,
        )


class JetpackComposeDetector:
    NAME = "Jetpack Compose"

    STRONG_PACKAGES = [
        "androidx.compose.runtime",
        "androidx.compose.ui",
        "androidx.compose.foundation",
    ]
    MEDIUM_PACKAGES = [
        "androidx.compose.material",
        "androidx.compose.material3",
        "androidx.compose.animation",
        "androidx.compose",
    ]

    @classmethod
    def detect(
        cls,
        extract_dir: str,
        packages: list[str],
        libs: list[NativeLibrary],
        activities: list[str],
    ) -> FrameworkDetection:
        evidence: list[Evidence] = []

        for pkg in cls.STRONG_PACKAGES:
            if _has_package(packages, pkg):
                evidence.append(_package_evidence(
                    pkg, EvidenceStrength.STRONG,
                    f"Jetpack Compose package detected"
                ))

        for pkg in cls.MEDIUM_PACKAGES:
            if _has_package(packages, pkg):
                evidence.append(_package_evidence(
                    pkg, EvidenceStrength.MEDIUM,
                    f"Jetpack Compose package detected"
                ))

        # ComponentActivity is required for Compose
        for act in activities:
            if "ComponentActivity" in act or "AppCompatActivity" in act:
                evidence.append(_component_evidence(
                    act, EvidenceStrength.WEAK,
                    "Compose-compatible activity base class"
                ))
                break

        confidence = _to_confidence(_score(evidence))
        return FrameworkDetection(
            name=cls.NAME,
            confidence=confidence,
            evidence=evidence,
            sub_technologies={"role": "UI Toolkit"},
        )


class KotlinDetector:
    NAME = "Kotlin"

    STRONG_PACKAGES = ["kotlin", "kotlinx"]
    MEDIUM_PACKAGES = ["kotlin.coroutines", "kotlinx.coroutines"]

    @classmethod
    def detect(
        cls,
        extract_dir: str,
        packages: list[str],
        libs: list[NativeLibrary],
        activities: list[str],
    ) -> FrameworkDetection:
        evidence: list[Evidence] = []

        for pkg in cls.STRONG_PACKAGES:
            if _has_package(packages, pkg):
                evidence.append(_package_evidence(
                    pkg, EvidenceStrength.STRONG,
                    f"{pkg} stdlib detected"
                ))

        for pkg in cls.MEDIUM_PACKAGES:
            if _has_package(packages, pkg):
                evidence.append(_package_evidence(
                    pkg, EvidenceStrength.MEDIUM,
                    f"{pkg} detected"
                ))

        confidence = _to_confidence(_score(evidence))
        return FrameworkDetection(
            name=cls.NAME,
            confidence=confidence,
            evidence=evidence,
            sub_technologies={"role": "Language / Runtime"},
        )


class NativeAndroidDetector:
    """
    Native Android is a fallback classification.
    It should NOT win if any strong cross-platform framework is detected.
    """
    NAME = "Native Android"

    STRONG_PACKAGES = ["androidx", "android.app"]
    MEDIUM_PACKAGES = [
        "androidx.appcompat",
        "androidx.fragment",
        "com.google.android.material",
    ]
    NATIVE_ACTIVITIES = ["AppCompatActivity", "FragmentActivity", "ComponentActivity", "Activity"]

    @classmethod
    def detect(
        cls,
        extract_dir: str,
        packages: list[str],
        libs: list[NativeLibrary],
        activities: list[str],
    ) -> FrameworkDetection:
        evidence: list[Evidence] = []

        for pkg in cls.STRONG_PACKAGES:
            if _has_package(packages, pkg):
                evidence.append(_package_evidence(
                    pkg, EvidenceStrength.MEDIUM,   # MEDIUM because cross-platform also has these
                    f"{pkg} Android platform package detected"
                ))

        for pkg in cls.MEDIUM_PACKAGES:
            if _has_package(packages, pkg):
                evidence.append(_package_evidence(
                    pkg, EvidenceStrength.WEAK,
                    f"{pkg} Android support library detected"
                ))

        for act in activities:
            for base in cls.NATIVE_ACTIVITIES:
                if base in act:
                    evidence.append(_component_evidence(
                        act, EvidenceStrength.WEAK,
                        f"Native Android activity ({base})"
                    ))
                    break

        confidence = _to_confidence(_score(evidence))
        return FrameworkDetection(
            name=cls.NAME,
            confidence=confidence,
            evidence=evidence,
        )


# ---------------------------------------------------------------------------
# Orchestration — run all detectors + classify
# ---------------------------------------------------------------------------

_CROSS_PLATFORM_DETECTORS = [
    ReactNativeDetector,
    FlutterDetector,
    UnityDetector,
    UnrealDetector,
    CordovaDetector,
    IonicDetector,
    CapacitorDetector,
    XamarinMauiDetector,
]

_SUPPLEMENTARY_DETECTORS = [
    JetpackComposeDetector,
    KotlinDetector,
]

# Minimum confidence to count a cross-platform framework as "detected"
_CROSS_PLATFORM_MIN_SCORE = 3  # at least LOW confidence


def run_fingerprint_engine(
    extract_dir: str,
    packages: list[str],
    libs: list[NativeLibrary],
    activities: list[str],
) -> tuple[list[FrameworkDetection], Optional[FrameworkDetection], bool]:
    """
    Run all detectors.

    Returns:
        (all_detections, primary_framework, is_hybrid)

    all_detections includes every non-UNKNOWN result.
    primary_framework is the strongest cross-platform framework, or Native Android.
    is_hybrid is True if ≥2 cross-platform frameworks detected at MEDIUM+ confidence.
    """
    all_results: list[FrameworkDetection] = []

    # Run cross-platform detectors
    cross_platform_detected: list[FrameworkDetection] = []
    for detector in _CROSS_PLATFORM_DETECTORS:
        result = detector.detect(extract_dir, packages, libs, activities)
        if result.confidence != Confidence.UNKNOWN:
            all_results.append(result)
        if _score(result.evidence) >= _CROSS_PLATFORM_MIN_SCORE:
            cross_platform_detected.append(result)

    # Run supplementary detectors
    for detector in _SUPPLEMENTARY_DETECTORS:
        result = detector.detect(extract_dir, packages, libs, activities)
        if result.confidence != Confidence.UNKNOWN:
            all_results.append(result)

    # If no cross-platform framework, run native Android detector
    native_result: Optional[FrameworkDetection] = None
    if not cross_platform_detected:
        native_result = NativeAndroidDetector.detect(extract_dir, packages, libs, activities)
        if native_result.confidence != Confidence.UNKNOWN:
            all_results.append(native_result)

    # Determine primary
    is_hybrid = False
    primary: Optional[FrameworkDetection] = None

    if len(cross_platform_detected) >= 2:
        is_hybrid = True
        # Pick the one with highest score as "primary" but label as hybrid
        primary = max(cross_platform_detected, key=lambda d: _score(d.evidence))
    elif len(cross_platform_detected) == 1:
        primary = cross_platform_detected[0]
    elif native_result and native_result.confidence != Confidence.UNKNOWN:
        primary = native_result

    # Attach Compose and Kotlin as sub_technologies to the primary if applicable
    if primary:
        compose_result = next((r for r in all_results if r.name == "Jetpack Compose"), None)
        kotlin_result = next((r for r in all_results if r.name == "Kotlin"), None)

        if compose_result and compose_result.confidence != Confidence.UNKNOWN:
            primary.sub_technologies["ui_toolkit"] = "Jetpack Compose"
        if kotlin_result and kotlin_result.confidence != Confidence.UNKNOWN:
            primary.sub_technologies["language"] = "Kotlin"

    return all_results, primary, is_hybrid
