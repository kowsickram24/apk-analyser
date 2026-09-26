"""
Native Library Analyzer.

Scans lib/ directory for .so files, reports ABIs, sizes, and maps
known library names to their detected purpose.
"""

from __future__ import annotations

import struct
from pathlib import Path

from .models import NativeLibrary


# ---------------------------------------------------------------------------
# Known library → purpose mapping
# ---------------------------------------------------------------------------

_LIBRARY_PURPOSES: dict[str, tuple[str, str]] = {
    # name (no lib prefix, no .so suffix) → (purpose, framework_hint)

    # React Native
    "reactnative":       ("React Native bridge", "React Native"),
    "react_native":      ("React Native bridge", "React Native"),
    "hermes":            ("Hermes JS engine", "React Native"),
    "jscexecutor":       ("JavaScriptCore executor", "React Native"),
    "jsi":               ("JSI runtime interface", "React Native"),
    "reactnativejni":    ("React Native JNI", "React Native"),
    "fabricjni":         ("React Native Fabric renderer", "React Native"),
    "rnscreens":         ("React Native Screens", "React Native"),
    "rnskiarender":      ("React Native Skia", "React Native"),
    "rnsvg":             ("React Native SVG", "React Native"),
    "reanimated":        ("React Native Reanimated", "React Native"),

    # Flutter
    "flutter":           ("Flutter engine", "Flutter"),
    "app":               ("Flutter compiled app", "Flutter"),   # only strong if flutter_assets present
    "flutter_runner":    ("Flutter runner", "Flutter"),

    # Unity
    "unity":             ("Unity engine", "Unity"),
    "il2cpp":            ("IL2CPP runtime", "Unity"),
    "unityplayer":       ("Unity player", "Unity"),

    # Unreal Engine
    "unreal":            ("Unreal Engine", "Unreal Engine"),
    "ue4":               ("Unreal Engine 4", "Unreal Engine"),
    "ue5":               ("Unreal Engine 5", "Unreal Engine"),
    "gamekit":           ("Unreal GameKit", "Unreal Engine"),

    # Mono / Xamarin
    "mono":              ("Mono runtime", "Xamarin/.NET MAUI"),
    "monosgen-2.0":      ("Mono SGen GC", "Xamarin/.NET MAUI"),
    "xamarin":           ("Xamarin runtime", "Xamarin/.NET MAUI"),

    # Common system / media
    "c":                 ("C standard library", ""),
    "c++_shared":        ("C++ shared runtime", ""),
    "c++_static":        ("C++ static runtime", ""),
    "stdc++":            ("C++ standard library", ""),
    "log":               ("Android logging", ""),
    "z":                 ("zlib compression", ""),
    "dl":                ("Dynamic linking", ""),
    "m":                 ("Math library", ""),
    "openssl":           ("OpenSSL", ""),
    "ssl":               ("SSL library", ""),
    "crypto":            ("Crypto library", ""),
    "curl":              ("libcurl HTTP", ""),
    "sqlite":            ("SQLite database", ""),
    "sqlite3":           ("SQLite 3", ""),
    "sqlcipher":         ("SQLCipher encrypted DB", ""),

    # Audio/Video
    "avcodec":           ("FFmpeg video codec", ""),
    "avformat":          ("FFmpeg format handler", ""),
    "avutil":            ("FFmpeg utilities", ""),
    "swresample":        ("FFmpeg audio resampler", ""),
    "swscale":           ("FFmpeg video scaler", ""),

    # ML / AI
    "tensorflow_lite":   ("TensorFlow Lite", ""),
    "tflite":            ("TensorFlow Lite", ""),
    "onnxruntime":       ("ONNX Runtime", ""),

    # Ads
    "facebook_ads":      ("Meta Audience Network", ""),
    "admob":             ("Google AdMob", ""),

    # Crash reporting
    "sentry":            ("Sentry crash reporting", ""),
    "bugsnag":           ("Bugsnag crash reporting", ""),
    "crashlytics":       ("Firebase Crashlytics", ""),

    # Profiling / Analytics
    "datadog":           ("Datadog monitoring", ""),

    # Webkit / WebView
    "webviewchromium":   ("Chromium WebView", ""),
    "awv_interface":     ("Amazon WebView interface", ""),

    # Graphics
    "opengl":            ("OpenGL ES", ""),
    "vulkan":            ("Vulkan graphics", ""),
    "skia":              ("Skia graphics engine", ""),

    # Game engines
    "godot":             ("Godot engine", "Godot"),
    "cocos2d":           ("Cocos2d engine", "Cocos2d"),
    "sdl":               ("SDL2 multimedia", ""),

    # Maps
    "googlemaps":        ("Google Maps SDK", ""),

    # Encryption
    "mbedtls":           ("mbed TLS", ""),
    "boringssl":         ("BoringSSL", ""),
}


def _so_name_to_key(so_name: str) -> str:
    """Extract base name from libFoo.so → foo"""
    name = so_name.lower()
    if name.startswith("lib"):
        name = name[3:]
    if name.endswith(".so"):
        name = name[:-3]
    # Strip version suffix like .so.1
    while name.endswith(".so"):
        name = name[:-3]
    return name


def _detect_purpose(so_name: str) -> tuple[str, str]:
    """Return (purpose, framework_hint) for a library filename."""
    key = _so_name_to_key(so_name)
    if key in _LIBRARY_PURPOSES:
        return _LIBRARY_PURPOSES[key]
    # Partial match
    for lib_key, (purpose, hint) in _LIBRARY_PURPOSES.items():
        if lib_key in key or key in lib_key:
            return purpose, hint
    return "", ""


# ---------------------------------------------------------------------------
# ELF header inspection (light)
# ---------------------------------------------------------------------------

ELF_MAGIC = b"\x7fELF"
ELF_ARCH_MAP: dict[int, str] = {
    0x28: "ARM (32-bit)",
    0xB7: "AArch64 (64-bit)",
    0x03: "x86 (32-bit)",
    0x3E: "x86-64",
    0x08: "MIPS",
}


def _read_elf_arch(path: Path) -> str:
    """Read ELF e_machine field to get architecture string."""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            if magic != ELF_MAGIC:
                return ""
            f.seek(18)
            e_machine = struct.unpack_from("<H", f.read(2))[0]
            return ELF_ARCH_MAP.get(e_machine, f"unknown (0x{e_machine:04x})")
    except (OSError, struct.error):
        return ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_KNOWN_ABIS = {"arm64-v8a", "armeabi-v7a", "x86", "x86_64", "armeabi", "mips", "mips64"}


def analyze_native_libraries(extract_dir: str) -> tuple[list[NativeLibrary], list[str]]:
    """
    Scan the lib/ directory of an extracted APK.

    Returns:
        (native_libraries, detected_abis)
    """
    lib_dir = Path(extract_dir) / "lib"
    libraries: list[NativeLibrary] = []
    abis_found: set[str] = set()

    if not lib_dir.exists():
        return libraries, []

    for abi_dir in sorted(lib_dir.iterdir()):
        if not abi_dir.is_dir():
            continue
        abi = abi_dir.name
        if abi not in _KNOWN_ABIS:
            # Still process but mark as unknown ABI
            pass
        abis_found.add(abi)

        for so_file in sorted(abi_dir.glob("*.so")):
            purpose, framework_hint = _detect_purpose(so_file.name)
            lib = NativeLibrary(
                name=so_file.name,
                abi=abi,
                size_bytes=so_file.stat().st_size,
                detected_purpose=purpose,
                framework_hint=framework_hint,
            )
            libraries.append(lib)

    return libraries, sorted(abis_found)
