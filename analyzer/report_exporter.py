"""
Report exporters — JSON and Markdown.
"""

from __future__ import annotations

import json
from .models import AnalysisResult, Confidence


def export_json(result: AnalysisResult, indent: int = 2) -> str:
    return result.to_json(indent=indent)


def _fmt_size(size_bytes: int) -> str:
    if size_bytes >= 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    if size_bytes >= 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes} B"


def _confidence_badge(c: Confidence) -> str:
    return {"high": "🟢 HIGH", "medium": "🟡 MEDIUM", "low": "🔴 LOW", "unknown": "⚪ UNKNOWN"}.get(c.value, c.value.upper())


def export_markdown(result: AnalysisResult) -> str:
    lines: list[str] = []
    m = result.manifest
    meta = result.metadata

    lines.append("# APK Stack Analysis Report")
    lines.append("")
    lines.append("## Application")
    lines.append("")
    lines.append(f"| Field | Value |")
    lines.append(f"|-------|-------|")
    lines.append(f"| Package | `{m.package_name or 'Unknown'}` |")
    lines.append(f"| Version | {m.version_name or 'Unknown'} |")
    lines.append(f"| Version Code | {m.version_code or 'Unknown'} |")
    lines.append(f"| Min SDK | {m.min_sdk or 'Unknown'} |")
    lines.append(f"| Target SDK | {m.target_sdk or 'Unknown'} |")
    lines.append(f"| File Size | {_fmt_size(meta.file_size_bytes)} |")
    lines.append(f"| SHA-256 | `{meta.sha256}` |")
    lines.append(f"| Filename | {meta.filename} |")
    lines.append("")

    # Primary Framework
    lines.append("## Primary Stack")
    lines.append("")
    if result.is_hybrid:
        lines.append("**⚠️ Hybrid / Multi-Framework Application**")
        lines.append("")
    if result.primary_framework:
        pf = result.primary_framework
        lines.append(f"**{pf.name}** — {_confidence_badge(pf.confidence)}")
        lines.append("")
        if pf.sub_technologies:
            for k, v in pf.sub_technologies.items():
                lines.append(f"- {k.replace('_', ' ').title()}: **{v}**")
        lines.append("")
    else:
        lines.append("_Framework not identified_")
        lines.append("")

    # All detected frameworks
    if result.frameworks:
        lines.append("## Detected Technologies")
        lines.append("")
        for fw in result.frameworks:
            lines.append(f"### {fw.name} — {_confidence_badge(fw.confidence)}")
            lines.append("")
            if fw.evidence:
                lines.append("**Evidence:**")
                for ev in fw.evidence:
                    lines.append(f"- ✓ `{ev.artifact}` ({ev.strength.value}) — {ev.description}")
            if fw.negative_evidence:
                lines.append("")
                lines.append("**Not detected:**")
                for neg in fw.negative_evidence:
                    lines.append(f"- ✗ `{neg.artifact}`")
            lines.append("")

    # Architectures
    lines.append("## CPU Architectures")
    lines.append("")
    if result.architectures:
        for abi in result.architectures:
            lines.append(f"- ✓ `{abi}`")
    else:
        lines.append("_No native libraries detected_")
    lines.append("")

    # Native Libraries
    if result.native_libraries:
        lines.append("## Native Libraries")
        lines.append("")
        lines.append("| Library | ABI | Size | Purpose |")
        lines.append("|---------|-----|------|---------|")
        for lib in result.native_libraries:
            lines.append(
                f"| `{lib.name}` | {lib.abi} | {_fmt_size(lib.size_bytes)} | {lib.detected_purpose or '—'} |"
            )
        lines.append("")

    # Android Manifest
    lines.append("## Android Manifest")
    lines.append("")
    lines.append(f"- Debuggable: {'⚠️ YES' if m.debuggable else 'No'}")
    lines.append(f"- Allow Backup: {'Yes' if m.allow_backup else 'No'}")
    lines.append(f"- Network Security Config: {'Yes' if m.network_security_config else 'No'}")
    lines.append(f"- Cleartext Traffic: {'⚠️ Permitted' if m.uses_cleartext_traffic else 'Not explicitly permitted'}")
    lines.append("")
    lines.append(f"### Components")
    lines.append(f"- Activities: {len(m.activities)}")
    lines.append(f"- Services: {len(m.services)}")
    lines.append(f"- Broadcast Receivers: {len(m.receivers)}")
    lines.append(f"- Content Providers: {len(m.providers)}")
    lines.append("")

    # Permissions
    if m.permissions:
        lines.append("### Permissions")
        lines.append("")
        dangerous = [p for p in m.permissions if p.is_sensitive]
        normal = [p for p in m.permissions if not p.is_sensitive]
        if dangerous:
            lines.append("**Sensitive:**")
            for p in dangerous:
                lines.append(f"- ⚠️ `{p.name}`")
        if normal:
            lines.append("")
            lines.append("**Normal / Custom:**")
            for p in normal[:20]:
                lines.append(f"- `{p.name}`")
            if len(normal) > 20:
                lines.append(f"- _...and {len(normal) - 20} more_")
        lines.append("")

    # Dependencies
    if result.dependencies:
        lines.append("## Dependencies")
        lines.append("")
        lines.append("| Library | Evidence | Confidence |")
        lines.append("|---------|----------|------------|")
        for dep in result.dependencies:
            lines.append(
                f"| {dep.name} | {dep.evidence_type} | {_confidence_badge(dep.confidence)} |"
            )
        lines.append("")

    # Security
    if result.security_findings:
        lines.append("## Security Findings")
        lines.append("")
        lines.append("> [!NOTE]")
        lines.append("> All findings are indicators only and require manual verification.")
        lines.append("")
        severity_icon = {"high": "🔴", "medium": "🟡", "low": "🔵", "info": "ℹ️"}
        for finding in result.security_findings:
            icon = severity_icon.get(finding.severity.value, "•")
            lines.append(f"### {icon} {finding.title}")
            lines.append("")
            lines.append(finding.description)
            if finding.recommendation:
                lines.append("")
                lines.append(f"**Recommendation:** {finding.recommendation}")
            lines.append("")

    # URLs
    if result.urls:
        lines.append("## Detected URLs")
        lines.append("")
        lines.append("| URL | Category | Source |")
        lines.append("|-----|----------|--------|")
        for url in result.urls[:50]:
            lines.append(f"| `{url.url[:80]}` | {url.category} | {url.source_file} |")
        if len(result.urls) > 50:
            lines.append(f"| _...{len(result.urls) - 50} more_ | | |")
        lines.append("")

    # Warnings
    if result.warnings:
        lines.append("## Analysis Warnings")
        lines.append("")
        for w in result.warnings:
            lines.append(f"- ⚠️ {w}")
        lines.append("")

    lines.append("---")
    lines.append("_Generated by APK Stack Analyzer_")

    return "\n".join(lines)
