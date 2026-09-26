"""
APK Extractor — Handles APK validation, extraction, and basic metadata.
APKs are ZIP files; this module unpacks them safely into a temp directory.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Callable, Optional

from .models import APKMetadata, FileTreeNode


# Allowed extensions for file extraction (safety allowlist).
_ALLOWED_SUFFIXES: set[str] = {
    ".dex", ".so", ".xml", ".json", ".js", ".html", ".css",
    ".txt", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg",
    ".ttf", ".otf", ".woff", ".woff2", ".properties",
    ".yaml", ".yml", ".conf", ".cfg", ".ini",
    ".pb", ".bin", ".dat", ".tflite", ".onnx",
    ".arsc", ".apk",  # resource/binary files
    "",               # files with no extension
}

# Maximum individual file size to extract (100 MB safety limit)
_MAX_EXTRACT_BYTES = 100 * 1024 * 1024

# Maximum total uncompressed size (1 GB bomb protection)
_MAX_TOTAL_BYTES = 1 * 1024 * 1024 * 1024


class APKValidationError(Exception):
    pass


def _sanitize_path(raw: str) -> Optional[str]:
    """Return a safe relative path, or None if the path should be skipped."""
    # Normalize separators
    normalized = raw.replace("\\", "/").strip("/")
    # Reject path traversal
    parts = normalized.split("/")
    if ".." in parts or any(p.startswith("/") for p in parts):
        return None
    # Reject null bytes
    if "\x00" in normalized:
        return None
    return normalized


def calculate_sha256(path: str | Path) -> str:
    """Return hex SHA-256 of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_apk(path: str | Path) -> None:
    """
    Validate that a file is a valid APK (ZIP-based with AndroidManifest.xml).
    Raises APKValidationError on failure.
    """
    path = Path(path)
    if not path.exists():
        raise APKValidationError(f"File not found: {path}")
    if path.stat().st_size == 0:
        raise APKValidationError("File is empty.")
    if not zipfile.is_zipfile(path):
        raise APKValidationError("File is not a valid ZIP/APK archive.")
    with zipfile.ZipFile(path, "r") as zf:
        names = zf.namelist()
        if "AndroidManifest.xml" not in names:
            raise APKValidationError("AndroidManifest.xml not found — not a valid APK.")


def extract_apk(
    apk_path: str | Path,
    *,
    progress_callback: Optional[Callable[[str], None]] = None,
) -> tuple[str, APKMetadata]:
    """
    Extract APK contents to a temporary directory safely.

    Returns:
        (extract_dir, APKMetadata)

    The caller is responsible for cleaning up extract_dir.
    """
    apk_path = Path(apk_path)

    def _emit(msg: str) -> None:
        if progress_callback:
            progress_callback(msg)

    # Validate first
    validate_apk(apk_path)
    _emit("apk_validated")

    # SHA-256
    sha256 = calculate_sha256(apk_path)
    _emit("sha256_calculated")

    # Create temp dir
    extract_dir = tempfile.mkdtemp(prefix="apk_analyzer_")

    total_extracted = 0
    extracted_count = 0
    skipped_count = 0

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for zip_info in zf.infolist():
                raw_name = zip_info.filename
                safe_name = _sanitize_path(raw_name)
                if safe_name is None:
                    skipped_count += 1
                    continue

                # Size guard
                if zip_info.file_size > _MAX_EXTRACT_BYTES:
                    skipped_count += 1
                    continue

                total_extracted += zip_info.file_size
                if total_extracted > _MAX_TOTAL_BYTES:
                    raise APKValidationError("APK extraction exceeded total size limit (potential bomb).")

                dest = Path(extract_dir) / safe_name

                if raw_name.endswith("/") or zip_info.is_dir():
                    dest.mkdir(parents=True, exist_ok=True)
                    continue

                dest.parent.mkdir(parents=True, exist_ok=True)

                # Extension filter — still extract unknown extensions but be careful
                with zf.open(zip_info) as src, open(dest, "wb") as dst:
                    shutil.copyfileobj(src, dst)

                extracted_count += 1

    except zipfile.BadZipFile as e:
        shutil.rmtree(extract_dir, ignore_errors=True)
        raise APKValidationError(f"Corrupted APK: {e}") from e
    except Exception:
        shutil.rmtree(extract_dir, ignore_errors=True)
        raise

    _emit("apk_extracted")

    metadata = APKMetadata(
        filename=apk_path.name,
        file_size_bytes=apk_path.stat().st_size,
        sha256=sha256,
        apk_path=str(apk_path),
    )

    return extract_dir, metadata


def build_file_tree(root_dir: str | Path, max_depth: int = 8, max_files_per_dir: int = 200) -> FileTreeNode:
    """Build a FileTreeNode tree from a directory, suitable for UI display."""
    root = Path(root_dir)
    root_node = FileTreeNode(name=root.name, path="", is_dir=True)
    _build_node(root, root_node, root, depth=0, max_depth=max_depth, max_files_per_dir=max_files_per_dir)
    return root_node


def _build_node(
    base: Path,
    node: FileTreeNode,
    current: Path,
    depth: int,
    max_depth: int,
    max_files_per_dir: int,
) -> None:
    if depth >= max_depth:
        return

    try:
        entries = sorted(current.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
    except PermissionError:
        return

    file_count = 0
    for entry in entries:
        if file_count >= max_files_per_dir:
            node.children.append(FileTreeNode(
                name=f"... ({len(list(current.iterdir())) - max_files_per_dir} more files)",
                path="",
                is_dir=False,
                size_bytes=0,
            ))
            break

        rel = entry.relative_to(base)
        child = FileTreeNode(
            name=entry.name,
            path=str(rel).replace("\\", "/"),
            is_dir=entry.is_dir(),
            size_bytes=entry.stat().st_size if entry.is_file() else 0,
        )
        node.children.append(child)

        if entry.is_dir():
            _build_node(base, child, entry, depth + 1, max_depth, max_files_per_dir)

        file_count += 1
