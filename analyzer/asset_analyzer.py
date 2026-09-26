"""
Asset Analyzer.

Scans assets/, res/, and META-INF/ for notable files.
Categorizes files and extracts URLs from text-based resources.
"""

from __future__ import annotations

import re
from pathlib import Path

from .models import AssetEntry, DetectedURL


# ---------------------------------------------------------------------------
# Category detection
# ---------------------------------------------------------------------------

_CATEGORY_RULES: list[tuple[str, str, str]] = [
    # (glob pattern substring, category, description)
    ("flutter_assets/AssetManifest", "flutter_asset", "Flutter asset manifest"),
    ("flutter_assets/FontManifest", "flutter_asset", "Flutter font manifest"),
    ("flutter_assets/", "flutter_asset", "Flutter asset"),
    ("index.android.bundle", "js_bundle", "React Native JS bundle"),
    ("main.jsbundle", "js_bundle", "React Native JS bundle"),
    ("index.android.js", "js_bundle", "React Native JS source"),
    (".hermes", "js_bundle", "Hermes bytecode bundle"),
    ("assets/www/", "web_asset", "Hybrid web asset"),
    ("assets/bin/Data/", "unity_asset", "Unity data file"),
    (".ttf", "font", "TrueType font"),
    (".otf", "font", "OpenType font"),
    (".woff", "font", "Web font"),
    (".json", "config", "JSON configuration"),
    (".yaml", "config", "YAML configuration"),
    (".yml", "config", "YAML configuration"),
    (".xml", "config", "XML configuration"),
    (".properties", "config", "Properties file"),
    (".pem", "certificate", "PEM certificate"),
    (".cer", "certificate", "Certificate"),
    (".crt", "certificate", "Certificate"),
    (".der", "certificate", "DER certificate"),
    (".p12", "certificate", "PKCS12 certificate"),
    (".tflite", "ml_model", "TensorFlow Lite model"),
    (".onnx", "ml_model", "ONNX ML model"),
    (".pb", "ml_model", "Protocol Buffer / ML model"),
    (".strings", "localization", "String localization"),
    (".lproj", "localization", "Localization"),
    ("values/strings", "localization", "Android string resources"),
    ("META-INF/", "meta_inf", "APK signing metadata"),
    (".png", "image", "PNG image"),
    (".jpg", "image", "JPEG image"),
    (".jpeg", "image", "JPEG image"),
    (".webp", "image", "WebP image"),
    (".svg", "image", "SVG vector image"),
    (".mp3", "audio", "MP3 audio"),
    (".ogg", "audio", "OGG audio"),
    (".wav", "audio", "WAV audio"),
    (".mp4", "video", "MP4 video"),
    (".webm", "video", "WebM video"),
]


def _categorize(path_str: str) -> tuple[str, str]:
    """Return (category, description) for a file path."""
    path_lower = path_str.lower()
    for pattern, category, description in _CATEGORY_RULES:
        if pattern.lower() in path_lower:
            return category, description
    return "other", "Other file"


# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------

# Matches http/https URLs (conservative — avoids matching code templates)
_URL_RE = re.compile(
    r"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{10,}",
    re.IGNORECASE,
)

_URL_CATEGORY_RULES: list[tuple[list[str], str]] = [
    (["api.", "api/", "/api", "backend", "service", "endpoint", "graphql", "rest"], "api"),
    (["auth", "login", "oauth", "sso", "token", "identity", "accounts."], "authentication"),
    (["analytics", "amplitude", "mixpanel", "segment", "posthog", "heap", "firebase", "firebaseapp",
      "googletagmanager", "clarity", "hotjar"], "analytics"),
    (["cdn.", "static.", "assets.", "media.", "images.", "storage.", "cloudfront", "cloudflare",
      "akamai", "fastly", "s3.amazonaws"], "cdn"),
    (["play.google.com", "developer.android.com", "apple.com", "microsoft.com"], "web"),
    (["crashlytics", "sentry", "bugsnag", "datadog", "newrelic", "appdynamics"], "monitoring"),
]


def _categorize_url(url: str) -> str:
    url_lower = url.lower()
    for keywords, category in _URL_CATEGORY_RULES:
        if any(kw in url_lower for kw in keywords):
            return category
    return "unknown"


def _extract_urls_from_file(path: Path) -> list[str]:
    """Extract URLs from a text file (limit to first 2 MB to avoid OOM)."""
    try:
        content = path.read_bytes()[:2 * 1024 * 1024].decode("utf-8", errors="replace")
        return _URL_RE.findall(content)
    except OSError:
        return []


# ---------------------------------------------------------------------------
# Key directories / file patterns to highlight
# ---------------------------------------------------------------------------

_IMPORTANT_ASSET_PATTERNS = [
    "assets/",
    "META-INF/",
    "res/raw/",
    "res/xml/",
]

_TEXT_EXTENSIONS = {
    ".json", ".xml", ".txt", ".yaml", ".yml", ".js", ".html",
    ".htm", ".css", ".properties", ".conf", ".ini", ".cfg",
    ".pem", ".cer", ".crt",
}

_BINARY_ASSET_SIZE_LIMIT = 10 * 1024 * 1024  # only show assets >10 MB separately


def analyze_assets(extract_dir: str) -> tuple[list[AssetEntry], list[DetectedURL]]:
    """
    Analyze assets and extract interesting file entries + URLs.

    Returns:
        (asset_entries, detected_urls)
    """
    root = Path(extract_dir)
    asset_entries: list[AssetEntry] = []
    all_urls: dict[str, set[str]] = {}  # url → set of source files

    scan_dirs = ["assets", "res", "META-INF"]

    for scan_dir in scan_dirs:
        dir_path = root / scan_dir
        if not dir_path.exists():
            continue

        for file_path in dir_path.rglob("*"):
            if not file_path.is_file():
                continue

            rel = str(file_path.relative_to(root)).replace("\\", "/")
            size = file_path.stat().st_size
            category, description = _categorize(rel)

            # Include notable files
            ext = file_path.suffix.lower()
            is_notable = (
                category not in ("image", "other")
                or size > _BINARY_ASSET_SIZE_LIMIT
                or ext in _TEXT_EXTENSIONS
            )

            if is_notable:
                asset_entries.append(AssetEntry(
                    path=rel,
                    size_bytes=size,
                    category=category,
                    description=description,
                ))

            # Extract URLs from text files
            if ext in _TEXT_EXTENSIONS and size < 5 * 1024 * 1024:
                urls = _extract_urls_from_file(file_path)
                for url in urls:
                    if url not in all_urls:
                        all_urls[url] = set()
                    all_urls[url].add(rel)

    # Also scan classes.dex string content? — too expensive; skip here.
    # The DEX-level URL scan is optional and done via androguard if available.

    # Deduplicate URLs
    detected_urls: list[DetectedURL] = []
    seen: set[str] = set()
    for url, sources in sorted(all_urls.items()):
        # Filter out common non-informative URLs
        if any(skip in url.lower() for skip in ["schemas.android.com", "www.w3.org", "www.opengl.org"]):
            continue
        if url in seen:
            continue
        seen.add(url)
        source = next(iter(sources))
        detected_urls.append(DetectedURL(
            url=url,
            category=_categorize_url(url),
            source_file=source,
        ))

    # Limit output
    detected_urls = detected_urls[:200]
    asset_entries = asset_entries[:500]

    return asset_entries, detected_urls
