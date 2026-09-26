"""
Security Heuristics Analyzer.

Performs static security analysis without making any network calls.
All findings are labeled as 'potential' and require manual verification.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from .models import ManifestAnalysis, SecurityFinding, SecuritySeverity


# ---------------------------------------------------------------------------
# Hardcoded secret patterns
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'AIza[0-9A-Za-z\-_]{35}', re.I), "Google API Key"),
    (re.compile(r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}', re.I), "Firebase Cloud Messaging key"),
    (re.compile(r'sk_live_[0-9a-zA-Z]{24,}', re.I), "Stripe Live Secret Key"),
    (re.compile(r'sk_test_[0-9a-zA-Z]{24,}', re.I), "Stripe Test Key"),
    (re.compile(r'rk_live_[0-9a-zA-Z]{24,}', re.I), "Stripe Restricted Key"),
    (re.compile(r'pk_live_[0-9a-zA-Z]{24,}', re.I), "Stripe Publishable Key"),
    (re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', re.I), "Embedded Private Key"),
    (re.compile(r'aws_access_key_id\s*=\s*[A-Z0-9]{20}', re.I), "AWS Access Key ID"),
    (re.compile(r'AKID[A-Z0-9]{16}', re.I), "AWS Access Key"),
    (re.compile(r'github_pat_[A-Za-z0-9_]{36,}', re.I), "GitHub PAT"),
    (re.compile(r'ghp_[A-Za-z0-9]{36}', re.I), "GitHub Token"),
    (re.compile(r'xox[baprs]-[0-9A-Za-z\-]{10,}', re.I), "Slack Token"),
    (re.compile(r'EAAAAAAAAAAAAAAAAAAAAAtq[A-Za-z0-9]{35}', re.I), "Discord Bot Token"),
    (re.compile(r'sq0atp-[0-9A-Za-z\-_]{22}', re.I), "Square Access Token"),
    (re.compile(r'supabase\.co', re.I), "Supabase reference"),
    (re.compile(r'accountSid\s*=\s*AC[a-f0-9]{32}', re.I), "Twilio Account SID"),
]

_TEXT_EXTENSIONS = {
    ".json", ".xml", ".txt", ".yaml", ".yml", ".js",
    ".html", ".properties", ".conf", ".gradle",
}


def _scan_for_secrets(extract_dir: str) -> list[SecurityFinding]:
    """Scan text files for known secret patterns."""
    findings: list[SecurityFinding] = []
    root = Path(extract_dir)
    found_types: set[str] = set()   # deduplicate by secret type

    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue
        if file_path.stat().st_size > 2 * 1024 * 1024:
            continue
        ext = file_path.suffix.lower()
        if ext not in _TEXT_EXTENSIONS and ext != "":
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        for pattern, label in _SECRET_PATTERNS:
            if label in found_types:
                continue
            if pattern.search(content):
                rel = str(file_path.relative_to(root)).replace("\\", "/")
                findings.append(SecurityFinding(
                    title=f"Potential {label} detected",
                    severity=SecuritySeverity.HIGH,
                    description=f"Pattern matching a {label} was found in {rel}.",
                    recommendation="Rotate the secret immediately if confirmed. Do not ship credentials in APKs.",
                    requires_manual_verification=True,
                    source=rel,
                ))
                found_types.add(label)

    return findings


# ---------------------------------------------------------------------------
# Manifest-based heuristics
# ---------------------------------------------------------------------------

def _analyze_manifest_security(manifest: ManifestAnalysis) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []

    if manifest.debuggable:
        findings.append(SecurityFinding(
            title="Application is Debuggable",
            severity=SecuritySeverity.HIGH,
            description="android:debuggable=true allows debugging via ADB. Must be false in production builds.",
            recommendation="Set android:debuggable=false in release builds.",
            requires_manual_verification=False,
            source="AndroidManifest.xml",
        ))

    if manifest.allow_backup:
        findings.append(SecurityFinding(
            title="Application Backup Enabled",
            severity=SecuritySeverity.LOW,
            description="android:allowBackup=true allows data backup via ADB, which may expose sensitive data.",
            recommendation="Disable backup or configure backup rules to exclude sensitive data.",
            requires_manual_verification=True,
            source="AndroidManifest.xml",
        ))

    if manifest.uses_cleartext_traffic is True:
        findings.append(SecurityFinding(
            title="Cleartext Traffic Allowed",
            severity=SecuritySeverity.MEDIUM,
            description="android:usesCleartextTraffic=true allows HTTP connections, which are unencrypted.",
            recommendation="Use HTTPS for all network communication. Define a Network Security Config.",
            requires_manual_verification=True,
            source="AndroidManifest.xml",
        ))

    # Exported components
    exported_activities = [
        a for a in manifest.activities
        if a.exported is True and not any(
            "LAUNCHER" in f or "MAIN" in f for f in a.intent_filters
        )
    ]
    if exported_activities:
        names = [a.name.split(".")[-1] for a in exported_activities[:3]]
        findings.append(SecurityFinding(
            title=f"Exported Activities Without Launcher Intent ({len(exported_activities)})",
            severity=SecuritySeverity.MEDIUM,
            description=f"Activities {', '.join(names)} are exported and may be accessible to other applications.",
            recommendation="Review whether these activities need to be exported. Add permission restrictions if necessary.",
            requires_manual_verification=True,
            source="AndroidManifest.xml",
        ))

    exported_providers = [p for p in manifest.providers if p.exported is True]
    if exported_providers:
        findings.append(SecurityFinding(
            title=f"Exported Content Providers ({len(exported_providers)})",
            severity=SecuritySeverity.MEDIUM,
            description="Exported ContentProviders may expose data to other applications.",
            recommendation="Restrict access using readPermission and writePermission.",
            requires_manual_verification=True,
            source="AndroidManifest.xml",
        ))

    # Dangerous permissions
    dangerous_perms = [p for p in manifest.permissions if p.is_sensitive]
    if dangerous_perms:
        perm_names = [p.name.split(".")[-1] for p in dangerous_perms[:5]]
        findings.append(SecurityFinding(
            title=f"Sensitive Permissions Requested ({len(dangerous_perms)})",
            severity=SecuritySeverity.INFO,
            description=f"App requests potentially sensitive permissions: {', '.join(perm_names)}{'...' if len(dangerous_perms) > 5 else ''}.",
            recommendation="Verify that all requested permissions are necessary and declared in the store listing.",
            requires_manual_verification=True,
            source="AndroidManifest.xml",
        ))

    if not manifest.network_security_config:
        findings.append(SecurityFinding(
            title="No Network Security Config",
            severity=SecuritySeverity.LOW,
            description="No android:networkSecurityConfig attribute found. Using Android defaults.",
            recommendation="Define a network security configuration to restrict cleartext and pin certificates.",
            requires_manual_verification=True,
            source="AndroidManifest.xml",
        ))

    return findings


# ---------------------------------------------------------------------------
# Network Security Config analysis
# ---------------------------------------------------------------------------

def _analyze_network_security(extract_dir: str) -> list[SecurityFinding]:
    """Parse res/xml/network_security_config.xml if present."""
    findings: list[SecurityFinding] = []
    nsc_path = Path(extract_dir) / "res" / "xml" / "network_security_config.xml"
    if not nsc_path.exists():
        return findings

    try:
        content = nsc_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    if "cleartextTrafficPermitted" in content and "true" in content:
        findings.append(SecurityFinding(
            title="Network Security Config Permits Cleartext Traffic",
            severity=SecuritySeverity.MEDIUM,
            description="network_security_config.xml allows cleartext (HTTP) traffic.",
            recommendation="Remove cleartextTrafficPermitted=true or restrict it to specific domains.",
            requires_manual_verification=True,
            source="res/xml/network_security_config.xml",
        ))

    if "trust-anchors" in content and "certificates" in content and "user" in content:
        findings.append(SecurityFinding(
            title="User-Installed Certificates Trusted",
            severity=SecuritySeverity.MEDIUM,
            description="Network security config trusts user-installed certificates, enabling interception.",
            recommendation="Remove user certificate trust in release builds. Use certificate pinning.",
            requires_manual_verification=True,
            source="res/xml/network_security_config.xml",
        ))

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_security(
    extract_dir: str,
    manifest: ManifestAnalysis,
) -> list[SecurityFinding]:
    """
    Run all security heuristics.
    Returns a list of SecurityFinding objects.
    """
    findings: list[SecurityFinding] = []

    # Manifest-level checks
    findings.extend(_analyze_manifest_security(manifest))

    # Network security config
    findings.extend(_analyze_network_security(extract_dir))

    # Secret scanning (limited files)
    findings.extend(_scan_for_secrets(extract_dir))

    # Sort by severity
    severity_order = {
        SecuritySeverity.HIGH: 0,
        SecuritySeverity.MEDIUM: 1,
        SecuritySeverity.LOW: 2,
        SecuritySeverity.INFO: 3,
    }
    findings.sort(key=lambda f: severity_order.get(f.severity, 99))

    return findings
