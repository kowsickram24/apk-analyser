"""
DEX File Analyzer.

Extracts class names and package names from .dex files using:
1. androguard (preferred)
2. Manual DEX header parsing (fallback)

Produces a list of packages that the fingerprint engine uses.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Optional

from .models import DexAnalysis


# DEX magic bytes
_DEX_MAGIC_PREFIX = b"dex\n"


def _is_dex_file(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == _DEX_MAGIC_PREFIX
    except OSError:
        return False


# ---------------------------------------------------------------------------
# androguard-based parser (preferred)
# ---------------------------------------------------------------------------

def _parse_dex_androguard(dex_paths: list[Path]) -> tuple[list[str], int, int]:
    """
    Returns (class_names, total_classes, total_methods).
    class_names are in JVM descriptor format like Lcom/example/Foo;
    """
    try:
        from androguard.core.bytecodes.dvm import DalvikVMFormat  # type: ignore
        classes: list[str] = []
        methods_count = 0
        for dex_path in dex_paths:
            data = dex_path.read_bytes()
            dvm = DalvikVMFormat(data)
            for cls in dvm.get_classes():
                classes.append(cls.get_name())
            for m in dvm.get_methods():
                methods_count += 1
        return classes, len(classes), methods_count
    except ImportError:
        pass
    except Exception:
        pass
    return [], 0, 0


def _parse_dex_androguard_v2(dex_paths: list[Path]) -> tuple[list[str], int, int]:
    """Try newer androguard API."""
    try:
        from androguard.core.dex import DEX  # type: ignore
        classes: list[str] = []
        methods_count = 0
        for dex_path in dex_paths:
            data = dex_path.read_bytes()
            dex = DEX(data)
            for cls in dex.get_classes():
                classes.append(cls.get_name())
            for m in dex.get_methods():
                methods_count += 1
        return classes, len(classes), methods_count
    except ImportError:
        pass
    except Exception:
        pass
    return [], 0, 0


# ---------------------------------------------------------------------------
# Manual DEX header parser (fallback)
# ---------------------------------------------------------------------------
# DEX format reference: https://source.android.com/docs/core/runtime/dex-format

def _read_u32_le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _parse_dex_manual(dex_path: Path) -> list[str]:
    """
    Parse DEX string_ids and type_ids to extract class type descriptors.
    This is a minimal parser — it reads strings referenced by type_ids.
    """
    try:
        data = dex_path.read_bytes()
        if not data.startswith(_DEX_MAGIC_PREFIX):
            return []

        # Header fields (all little-endian u32 unless noted)
        # offset 8:  checksum (4)
        # offset 12: SHA-1 (20)
        # offset 32: file_size
        # offset 36: header_size
        # offset 40: endian_tag
        # offset 56: string_ids_size, string_ids_off
        # offset 64: type_ids_size, type_ids_off

        string_ids_size = _read_u32_le(data, 56)
        string_ids_off  = _read_u32_le(data, 60)
        type_ids_size   = _read_u32_le(data, 64)
        type_ids_off    = _read_u32_le(data, 68)

        # Build string table
        strings: list[str] = []
        for i in range(min(string_ids_size, 500000)):  # cap for safety
            string_data_off = _read_u32_le(data, string_ids_off + i * 4)
            # ULEB128 length prefix
            length, shift = 0, 0
            j = string_data_off
            while j < len(data):
                byte = data[j]
                j += 1
                length |= (byte & 0x7F) << shift
                if not (byte & 0x80):
                    break
                shift += 7
            # Read UTF-8 string
            try:
                s = data[j: j + length].decode("mutf-8", errors="replace")
            except Exception:
                s = data[j: j + length].decode("latin-1", errors="replace")
            strings.append(s)

        # Read type descriptors
        classes: list[str] = []
        for i in range(min(type_ids_size, 500000)):
            idx = _read_u32_le(data, type_ids_off + i * 4)
            if idx < len(strings):
                s = strings[idx]
                if s.startswith("L") and s.endswith(";"):
                    classes.append(s)

        return classes
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Package extraction
# ---------------------------------------------------------------------------

def _descriptor_to_package(descriptor: str) -> str:
    """Convert Ljava/lang/String; → java.lang"""
    inner = descriptor[1:-1]  # strip L and ;
    parts = inner.replace("/", ".").split(".")
    return ".".join(parts[:-1]) if len(parts) > 1 else inner


def _extract_packages(class_names: list[str]) -> list[str]:
    """Return sorted unique top-level packages (depth ≤ 3)."""
    seen: set[str] = set()
    for name in class_names:
        if not (name.startswith("L") and name.endswith(";")):
            continue
        pkg = _descriptor_to_package(name)
        if not pkg:
            continue
        # Top-level (up to 3 levels)
        parts = pkg.split(".")
        for depth in range(1, min(4, len(parts) + 1)):
            seen.add(".".join(parts[:depth]))
    return sorted(seen)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_dex(extract_dir: str) -> DexAnalysis:
    """Analyze all DEX files found in the extracted APK directory."""
    root = Path(extract_dir)
    dex_paths = sorted(root.glob("*.dex"))

    result = DexAnalysis(dex_files=[p.name for p in dex_paths])

    if not dex_paths:
        return result

    # Try androguard first
    class_names, total_classes, total_methods = _parse_dex_androguard(dex_paths)

    if not class_names:
        class_names, total_classes, total_methods = _parse_dex_androguard_v2(dex_paths)

    if not class_names:
        # Manual fallback for each dex file
        all_classes: list[str] = []
        for dex_path in dex_paths:
            all_classes.extend(_parse_dex_manual(dex_path))
        class_names = all_classes
        total_classes = len(class_names)
        total_methods = 0

    result.total_classes = total_classes
    result.total_methods = total_methods

    packages = _extract_packages(class_names)
    result.packages = packages

    # Filter to framework/library relevant packages
    framework_keywords = [
        "com.facebook", "com.reactnative", "io.flutter",
        "com.unity3d", "com.epicgames", "org.cocos2d",
        "org.apache.cordova", "io.ionic", "com.capacitorjs",
        "mono.android", "com.xamarin", "microsoft.maui",
        "kotlin", "kotlinx", "androidx.compose",
        "com.google.firebase", "com.google.android",
        "com.squareup.okhttp", "retrofit2", "io.sentry",
        "com.onesignal", "com.amplitude", "com.mixpanel",
        "io.reactivex", "io.realm", "com.facebook.ads",
        "com.stripe", "com.revenuecat", "com.adjust",
        "com.appsflyer", "net.sqlcipher", "com.airbnb",
    ]
    result.framework_packages = [
        p for p in packages
        if any(p.startswith(kw) or kw in p for kw in framework_keywords)
    ]

    return result


def search_dex_classes(extract_dir: str, prefix: str) -> list[str]:
    """
    Return all class descriptors whose package matches a given prefix.
    Used by fingerprint engine for targeted lookups.
    """
    root = Path(extract_dir)
    dex_paths = sorted(root.glob("*.dex"))
    if not dex_paths:
        return []

    class_names, _, _ = _parse_dex_androguard(dex_paths)
    if not class_names:
        class_names, _, _ = _parse_dex_androguard_v2(dex_paths)
    if not class_names:
        all_classes: list[str] = []
        for p in dex_paths:
            all_classes.extend(_parse_dex_manual(p))
        class_names = all_classes

    prefix_desc = "L" + prefix.replace(".", "/")
    return [c for c in class_names if c.startswith(prefix_desc)]
