"""
AndroidManifest.xml Analyzer.

APKs ship AndroidManifest.xml in binary XML format (AXML).
We attempt to decode it using androguard (preferred) or axmldec / raw parsing.
Falls back to a best-effort text scan if decoding is unavailable.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from .models import (
    AndroidComponent,
    ManifestAnalysis,
    Permission,
    PermissionGroup,
)

# ---------------------------------------------------------------------------
# Known sensitive permissions
# ---------------------------------------------------------------------------

_DANGEROUS_PERMISSIONS: set[str] = {
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.BODY_SENSORS",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.POST_NOTIFICATIONS",
}

_SPECIAL_PERMISSIONS: set[str] = {
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.WRITE_SETTINGS",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.INSTALL_PACKAGES",
    "android.permission.DELETE_PACKAGES",
    "android.permission.REBOOT",
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
    "android.permission.CHANGE_COMPONENT_ENABLED_STATE",
    "android.permission.CHANGE_CONFIGURATION",
}

_HIGHLY_SENSITIVE: set[str] = (
    _DANGEROUS_PERMISSIONS | _SPECIAL_PERMISSIONS
)


def _classify_permission(perm_name: str) -> PermissionGroup:
    if perm_name in _SPECIAL_PERMISSIONS:
        return PermissionGroup.SPECIAL
    if perm_name in _DANGEROUS_PERMISSIONS:
        return PermissionGroup.DANGEROUS
    if perm_name.startswith("android.") or perm_name.startswith("com.android."):
        return PermissionGroup.NORMAL
    return PermissionGroup.CUSTOM


# ---------------------------------------------------------------------------
# AXML → text decoder using androguard
# ---------------------------------------------------------------------------

def _decode_manifest_androguard(manifest_bytes: bytes) -> Optional[str]:
    """Decode binary AXML using androguard. Returns plain XML text or None."""
    try:
        from androguard.core.axml import AXMLPrinter  # type: ignore
        printer = AXMLPrinter(manifest_bytes)
        return printer.get_xml_obj().toprettyxml(indent="  ")
    except Exception:
        pass

    # Older androguard API
    try:
        from androguard.core.bytecodes.axml import AXMLPrinter  # type: ignore
        printer = AXMLPrinter(manifest_bytes)
        return printer.get_xml()
    except Exception:
        pass

    return None


def _decode_manifest_axmldec(manifest_path: str) -> Optional[str]:
    """Try axmldec CLI tool if available."""
    import subprocess
    import shutil
    if not shutil.which("axmldec"):
        return None
    try:
        result = subprocess.run(
            ["axmldec", manifest_path],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return result.stdout
    except Exception:
        pass
    return None


def _decode_manifest_apktool(extract_dir: str) -> Optional[str]:
    """
    If the caller already ran APKTool, the decoded manifest lives at
    extract_dir/AndroidManifest.xml as plain text.
    Try to detect whether it's already text-decoded.
    """
    path = Path(extract_dir) / "AndroidManifest.xml"
    if not path.exists():
        return None
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        # A decoded manifest starts with <?xml
        if "<?xml" in content or "<manifest" in content:
            return content
    except Exception:
        pass
    return None


def _raw_best_effort(manifest_bytes: bytes) -> str:
    """
    Very crude binary AXML string extraction.
    Picks out readable ASCII sequences — not a real parser.
    Used only as last resort so we can still surface some data.
    """
    text_chunks: list[str] = []
    current: list[str] = []
    for byte in manifest_bytes:
        if 32 <= byte < 127:
            current.append(chr(byte))
        else:
            if len(current) >= 4:
                text_chunks.append("".join(current))
            current = []
    if len(current) >= 4:
        text_chunks.append("".join(current))
    return "\n".join(text_chunks)


# ---------------------------------------------------------------------------
# XML parser helpers
# ---------------------------------------------------------------------------

def _parse_xml_manifest(xml_text: str) -> ManifestAnalysis:
    """Parse a text AndroidManifest.xml into ManifestAnalysis."""
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        # Try stripping the XML declaration and retry
        cleaned = re.sub(r"<\?xml[^>]*\?>", "", xml_text, count=1).strip()
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(cleaned)
        except ET.ParseError:
            return _parse_manifest_regex(xml_text)

    ns_android = "http://schemas.android.com/apk/res/android"

    def attr(element, name: str, default: str = "") -> str:
        val = element.get(f"{{{ns_android}}}{name}") or element.get(name) or default
        return val

    def attr_bool(element, name: str, default: bool = False) -> bool:
        v = attr(element, name, "")
        if v.lower() in ("true", "1"):
            return True
        if v.lower() in ("false", "0"):
            return False
        return default

    manifest = ManifestAnalysis()
    manifest.package_name = root.get("package", "")
    manifest.version_name = attr(root, "versionName")
    manifest.version_code = attr(root, "versionCode")

    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        try:
            manifest.min_sdk = int(attr(uses_sdk, "minSdkVersion", "0")) or None
        except ValueError:
            pass
        try:
            manifest.target_sdk = int(attr(uses_sdk, "targetSdkVersion", "0")) or None
        except ValueError:
            pass
        try:
            manifest.compile_sdk = int(attr(uses_sdk, "compileSdkVersion", "0")) or None
        except ValueError:
            pass

    application = root.find("application")
    if application is not None:
        manifest.debuggable = attr_bool(application, "debuggable", False)
        manifest.allow_backup = attr_bool(application, "allowBackup", True)
        manifest.application_label = attr(application, "label")
        manifest.application_icon = attr(application, "icon")

        network_config = attr(application, "networkSecurityConfig")
        manifest.network_security_config = bool(network_config)

        cleartext = application.get(f"{{{ns_android}}}usesCleartextTraffic")
        if cleartext is not None:
            manifest.uses_cleartext_traffic = cleartext.lower() in ("true", "1")

        # Parse components
        for tag, comp_type in [
            ("activity", "activity"),
            ("activity-alias", "activity"),
            ("service", "service"),
            ("receiver", "receiver"),
            ("provider", "provider"),
        ]:
            for elem in application.iter(tag):
                name = attr(elem, "name")
                if not name:
                    continue
                exported_str = attr(elem, "exported", "")
                exported = None
                if exported_str.lower() == "true":
                    exported = True
                elif exported_str.lower() == "false":
                    exported = False

                intent_filters: list[str] = []
                for ifilter in elem.iter("intent-filter"):
                    for action in ifilter.iter("action"):
                        aname = attr(action, "name")
                        if aname:
                            intent_filters.append(aname)

                comp = AndroidComponent(
                    name=name,
                    component_type=comp_type,
                    exported=exported,
                    intent_filters=intent_filters,
                )
                if comp_type == "activity":
                    manifest.activities.append(comp)
                elif comp_type == "service":
                    manifest.services.append(comp)
                elif comp_type == "receiver":
                    manifest.receivers.append(comp)
                elif comp_type == "provider":
                    manifest.providers.append(comp)

    # Permissions used
    for perm_elem in root.iter("uses-permission"):
        perm_name = attr(perm_elem, "name")
        if perm_name:
            manifest.uses_permissions.append(perm_name)
            group = _classify_permission(perm_name)
            p = Permission(
                name=perm_name,
                group=group,
                is_sensitive=perm_name in _HIGHLY_SENSITIVE,
            )
            manifest.permissions.append(p)

    # Also catch uses-permission-sdk-23
    for perm_elem in root.iter("uses-permission-sdk-23"):
        perm_name = attr(perm_elem, "name")
        if perm_name and perm_name not in manifest.uses_permissions:
            manifest.uses_permissions.append(perm_name)
            group = _classify_permission(perm_name)
            p = Permission(
                name=perm_name,
                group=group,
                is_sensitive=perm_name in _HIGHLY_SENSITIVE,
            )
            manifest.permissions.append(p)

    return manifest


def _parse_manifest_regex(text: str) -> ManifestAnalysis:
    """Best-effort extraction from raw text/strings when XML parsing fails."""
    manifest = ManifestAnalysis()

    m = re.search(r'package="([^"]+)"', text)
    if m:
        manifest.package_name = m.group(1)

    m = re.search(r'android:versionName="([^"]+)"', text)
    if m:
        manifest.version_name = m.group(1)

    m = re.search(r'android:versionCode="([^"]+)"', text)
    if m:
        manifest.version_code = m.group(1)

    m = re.search(r'android:minSdkVersion="(\d+)"', text)
    if m:
        try:
            manifest.min_sdk = int(m.group(1))
        except ValueError:
            pass

    m = re.search(r'android:targetSdkVersion="(\d+)"', text)
    if m:
        try:
            manifest.target_sdk = int(m.group(1))
        except ValueError:
            pass

    if "android:debuggable" in text and 'android:debuggable="true"' in text:
        manifest.debuggable = True

    perms = re.findall(r'uses-permission[^>]*android:name="([^"]+)"', text)
    for perm in perms:
        if perm not in manifest.uses_permissions:
            manifest.uses_permissions.append(perm)
            group = _classify_permission(perm)
            manifest.permissions.append(Permission(
                name=perm,
                group=group,
                is_sensitive=perm in _HIGHLY_SENSITIVE,
            ))

    return manifest


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_manifest(extract_dir: str) -> ManifestAnalysis:
    """
    Load and analyze AndroidManifest.xml from an extracted APK directory.
    Tries multiple decoding strategies in order of preference.
    """
    manifest_path = Path(extract_dir) / "AndroidManifest.xml"
    if not manifest_path.exists():
        return ManifestAnalysis()

    raw_bytes = manifest_path.read_bytes()

    # Strategy 1: Already text (e.g. after APKTool decode)
    try:
        text = raw_bytes.decode("utf-8", errors="strict")
        if "<?xml" in text or "<manifest" in text:
            return _parse_xml_manifest(text)
    except UnicodeDecodeError:
        pass

    # Strategy 2: androguard binary AXML decode
    xml_text = _decode_manifest_androguard(raw_bytes)
    if xml_text:
        return _parse_xml_manifest(xml_text)

    # Strategy 3: axmldec CLI
    xml_text = _decode_manifest_axmldec(str(manifest_path))
    if xml_text:
        return _parse_xml_manifest(xml_text)

    # Strategy 4: best-effort string extraction from binary
    raw_text = _raw_best_effort(raw_bytes)
    return _parse_manifest_regex(raw_text)
