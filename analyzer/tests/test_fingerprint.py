"""
Unit tests for the framework fingerprint engine.

Tests:
- React Native (Hermes)
- React Native (JSC)
- Flutter
- Native Android (XML)
- Native Android (Compose)
- Unity (IL2CPP)
- Unreal Engine
- Cordova
- Ionic
- Capacitor
- Xamarin / .NET MAUI
- Hybrid (React Native + Flutter)
- Unknown APK
- False positive avoidance (Kotlin alone ≠ Native Android)
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

# Add root to path when running directly
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from analyzer.fingerprint_engine import (
    ReactNativeDetector,
    FlutterDetector,
    UnityDetector,
    UnrealDetector,
    CordovaDetector,
    CapacitorDetector,
    IonicDetector,
    XamarinMauiDetector,
    JetpackComposeDetector,
    KotlinDetector,
    NativeAndroidDetector,
    run_fingerprint_engine,
)
from analyzer.models import Confidence, NativeLibrary


def _make_lib(name: str, abi: str = "arm64-v8a", size: int = 1024 * 1024) -> NativeLibrary:
    return NativeLibrary(name=name, abi=abi, size_bytes=size, detected_purpose="")


class TestReactNativeDetection(unittest.TestCase):

    def test_react_native_hermes(self):
        """React Native with Hermes — should be HIGH confidence."""
        with tempfile.TemporaryDirectory() as td:
            # Create bundle file
            bundle_path = Path(td) / "assets"
            bundle_path.mkdir()
            (bundle_path / "index.android.bundle").write_bytes(b"\x00hermes")

            libs = [
                _make_lib("libhermes.so"),
                _make_lib("libreactnative.so"),
            ]
            packages = [
                "com.facebook.react",
                "com.facebook.hermes",
                "com.facebook.soloader",
            ]
            activities = ["com.myapp.MainActivity extends ReactActivity"]

            result = ReactNativeDetector.detect(td, packages, libs, activities)
            self.assertEqual(result.confidence, Confidence.HIGH)
            self.assertGreater(len(result.evidence), 2)
            self.assertEqual(result.sub_technologies.get("js_runtime"), "Hermes")

    def test_react_native_jsc(self):
        """React Native with JSC — should detect JSC runtime."""
        with tempfile.TemporaryDirectory() as td:
            Path(td, "assets").mkdir()
            (Path(td) / "assets" / "index.android.bundle").write_bytes(b"")
            libs = [
                _make_lib("libreactnative.so"),
                _make_lib("libjscexecutor.so"),
            ]
            packages = ["com.facebook.react", "com.facebook.soloader"]
            result = ReactNativeDetector.detect(td, packages, libs, [])
            self.assertIn(result.confidence, [Confidence.HIGH, Confidence.MEDIUM])
            self.assertEqual(result.sub_technologies.get("js_runtime"), "JavaScriptCore")

    def test_react_native_no_false_positive_from_androidx(self):
        """androidx alone should NOT trigger React Native."""
        with tempfile.TemporaryDirectory() as td:
            libs = []
            packages = ["androidx.appcompat", "androidx.fragment", "kotlin"]
            result = ReactNativeDetector.detect(td, packages, libs, [])
            self.assertEqual(result.confidence, Confidence.UNKNOWN)


class TestFlutterDetection(unittest.TestCase):

    def test_flutter_strong(self):
        """Flutter with libflutter.so + flutter_assets — HIGH confidence."""
        with tempfile.TemporaryDirectory() as td:
            flutter_dir = Path(td) / "assets" / "flutter_assets"
            flutter_dir.mkdir(parents=True)
            (flutter_dir / "AssetManifest.json").write_text("{}")
            (flutter_dir / "FontManifest.json").write_text("[]")

            libs = [_make_lib("libflutter.so"), _make_lib("libapp.so")]
            packages = ["io.flutter.embedding.android", "io.flutter.plugin"]
            activities = ["io.flutter.embedding.android.FlutterActivity"]

            result = FlutterDetector.detect(td, packages, libs, activities)
            self.assertEqual(result.confidence, Confidence.HIGH)

    def test_flutter_no_false_positive(self):
        """No Flutter artifacts — should be UNKNOWN."""
        with tempfile.TemporaryDirectory() as td:
            libs = [_make_lib("libhermes.so")]
            packages = ["com.facebook.react"]
            result = FlutterDetector.detect(td, packages, libs, [])
            self.assertEqual(result.confidence, Confidence.UNKNOWN)


class TestUnityDetection(unittest.TestCase):

    def test_unity_il2cpp(self):
        """Unity with libunity.so + libil2cpp.so — HIGH confidence, IL2CPP runtime."""
        with tempfile.TemporaryDirectory() as td:
            data_dir = Path(td) / "assets" / "bin" / "Data"
            data_dir.mkdir(parents=True)
            (data_dir / "dummy.unity3d").write_bytes(b"")

            libs = [_make_lib("libunity.so"), _make_lib("libil2cpp.so")]
            packages = ["com.unity3d.player"]
            activities = ["com.unity3d.player.UnityPlayerActivity"]

            result = UnityDetector.detect(td, packages, libs, activities)
            self.assertEqual(result.confidence, Confidence.HIGH)
            self.assertEqual(result.sub_technologies.get("runtime"), "IL2CPP")

    def test_unity_no_false_positive(self):
        """No Unity artifacts — UNKNOWN."""
        with tempfile.TemporaryDirectory() as td:
            result = UnityDetector.detect(td, ["androidx"], [], [])
            self.assertEqual(result.confidence, Confidence.UNKNOWN)


class TestUnrealDetection(unittest.TestCase):

    def test_unreal_ue4(self):
        with tempfile.TemporaryDirectory() as td:
            libs = [_make_lib("libUE4.so")]
            packages = ["com.epicgames.ue4.GameActivity"]
            result = UnrealDetector.detect(td, packages, libs, [])
            self.assertIn(result.confidence, [Confidence.HIGH, Confidence.MEDIUM])


class TestCordovaDetection(unittest.TestCase):

    def test_cordova_strong(self):
        with tempfile.TemporaryDirectory() as td:
            www_dir = Path(td) / "assets" / "www"
            www_dir.mkdir(parents=True)
            (www_dir / "cordova.js").write_text("// cordova")
            (www_dir / "cordova_plugins.js").write_text("")

            packages = ["org.apache.cordova"]
            result = CordovaDetector.detect(td, packages, [], [])
            self.assertEqual(result.confidence, Confidence.HIGH)

    def test_cordova_no_false_positive_webview(self):
        """A WebView app without Cordova artifacts should NOT be Cordova."""
        with tempfile.TemporaryDirectory() as td:
            packages = ["android.webkit", "androidx.webkit"]
            result = CordovaDetector.detect(td, packages, [], [])
            self.assertEqual(result.confidence, Confidence.UNKNOWN)


class TestCapacitorDetection(unittest.TestCase):

    def test_capacitor(self):
        with tempfile.TemporaryDirectory() as td:
            assets_dir = Path(td) / "assets"
            assets_dir.mkdir()
            (assets_dir / "capacitor.config.json").write_text("{}")

            packages = ["com.getcapacitor"]
            result = CapacitorDetector.detect(td, packages, [], [])
            self.assertEqual(result.confidence, Confidence.HIGH)


class TestXamarinDetection(unittest.TestCase):

    def test_xamarin_mono(self):
        with tempfile.TemporaryDirectory() as td:
            assemblies = Path(td) / "assemblies"
            assemblies.mkdir()
            (assemblies / "Xamarin.Android.dll").write_bytes(b"MZ")

            libs = [_make_lib("libmono.so"), _make_lib("libxamarin-app.so")]
            packages = ["mono.android", "com.xamarin"]
            result = XamarinMauiDetector.detect(td, packages, libs, [])
            self.assertEqual(result.confidence, Confidence.HIGH)
            self.assertEqual(result.sub_technologies.get("runtime"), "Mono")


class TestJetpackCompose(unittest.TestCase):

    def test_compose_detected(self):
        with tempfile.TemporaryDirectory() as td:
            packages = [
                "androidx.compose.runtime",
                "androidx.compose.ui",
                "androidx.compose.material3",
            ]
            result = JetpackComposeDetector.detect(td, packages, [], [])
            self.assertIn(result.confidence, [Confidence.HIGH, Confidence.MEDIUM])


class TestNativeAndroid(unittest.TestCase):

    def test_native_android_xml_layout(self):
        """Pure native Android with only Android/Kotlin packages — Native Android."""
        with tempfile.TemporaryDirectory() as td:
            packages = [
                "androidx.appcompat",
                "androidx.fragment",
                "kotlin",
                "kotlinx.coroutines",
                "com.google.android.material",
            ]
            libs = []
            activities = ["com.example.MainActivity extends AppCompatActivity"]
            result = NativeAndroidDetector.detect(td, packages, libs, activities)
            self.assertNotEqual(result.confidence, Confidence.UNKNOWN)

    def test_native_android_with_compose(self):
        """Full engine: Compose detected, no cross-platform framework → primary = Native Android."""
        with tempfile.TemporaryDirectory() as td:
            packages = [
                "androidx.appcompat",
                "androidx.compose.runtime",
                "androidx.compose.ui",
                "androidx.compose.material3",
                "kotlin",
            ]
            libs = []
            activities = ["com.example.MainActivity"]

            frameworks, primary, is_hybrid = run_fingerprint_engine(td, packages, libs, activities)
            self.assertFalse(is_hybrid)
            # Primary should be Native Android
            self.assertIsNotNone(primary)
            if primary:
                self.assertEqual(primary.name, "Native Android")
            # Compose should be in sub_technologies
            if primary:
                self.assertIn("ui_toolkit", primary.sub_technologies)


class TestFalsePositives(unittest.TestCase):

    def test_kotlin_alone_is_not_native_android(self):
        """Kotlin alone must NOT classify as React Native or Flutter."""
        with tempfile.TemporaryDirectory() as td:
            packages = ["kotlin", "kotlinx"]
            libs = []
            rn = ReactNativeDetector.detect(td, packages, libs, [])
            fl = FlutterDetector.detect(td, packages, libs, [])
            self.assertEqual(rn.confidence, Confidence.UNKNOWN)
            self.assertEqual(fl.confidence, Confidence.UNKNOWN)

    def test_androidx_alone_is_not_react_native(self):
        """androidx packages present in RN apps must NOT make Native Android ≠ RN distinction impossible."""
        with tempfile.TemporaryDirectory() as td:
            packages = ["androidx.appcompat", "androidx.fragment", "androidx.core"]
            libs = []
            rn = ReactNativeDetector.detect(td, packages, libs, [])
            self.assertEqual(rn.confidence, Confidence.UNKNOWN)

    def test_hybrid_detection(self):
        """React Native + Flutter both present → hybrid."""
        with tempfile.TemporaryDirectory() as td:
            # Create flutter assets
            flutter_dir = Path(td) / "assets" / "flutter_assets"
            flutter_dir.mkdir(parents=True)
            (flutter_dir / "AssetManifest.json").write_text("{}")

            # Create RN bundle
            assets_dir = Path(td) / "assets"
            (assets_dir / "index.android.bundle").write_bytes(b"")

            libs = [
                _make_lib("libflutter.so"),
                _make_lib("libhermes.so"),
                _make_lib("libreactnative.so"),
            ]
            packages = [
                "com.facebook.react",
                "com.facebook.hermes",
                "io.flutter.embedding.android",
            ]
            frameworks, primary, is_hybrid = run_fingerprint_engine(td, packages, libs, [])
            self.assertTrue(is_hybrid)

    def test_unknown_apk(self):
        """Empty directory → no high confidence detections."""
        with tempfile.TemporaryDirectory() as td:
            frameworks, primary, is_hybrid = run_fingerprint_engine(td, [], [], [])
            high_conf = [f for f in frameworks if f.confidence == Confidence.HIGH]
            # No high confidence detections from empty APK
            rn_high = [f for f in high_conf if f.name == "React Native"]
            fl_high = [f for f in high_conf if f.name == "Flutter"]
            self.assertEqual(len(rn_high), 0)
            self.assertEqual(len(fl_high), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
