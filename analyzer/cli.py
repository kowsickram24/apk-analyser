#!/usr/bin/env python3
"""
APK Stack Analyzer — CLI

Usage:
    python -m analyzer.cli app.apk
    python -m analyzer.cli app.apk --output report.json
    python -m analyzer.cli app.apk --output report.md
    python -m analyzer.cli app.apk --json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .models import Confidence
from .orchestrator import AnalysisStep, analyze_apk
from .report_exporter import export_json, export_markdown


# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------

RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
DIM = "\033[2m"


def _c(text: str, color: str) -> str:
    return f"{color}{text}{RESET}"


def _fmt_size(size_bytes: int) -> str:
    if size_bytes >= 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    if size_bytes >= 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes} B"


def _confidence_str(c: Confidence) -> str:
    return {
        Confidence.HIGH: _c("HIGH", GREEN),
        Confidence.MEDIUM: _c("MEDIUM", YELLOW),
        Confidence.LOW: _c("LOW", RED),
        Confidence.UNKNOWN: _c("UNKNOWN", DIM),
    }.get(c, c.value.upper())


_STEP_LABELS = {
    AnalysisStep.VALIDATING: "Validating APK",
    AnalysisStep.SHA256: "Calculating SHA-256",
    AnalysisStep.EXTRACTING: "Extracting APK",
    AnalysisStep.MANIFEST: "Analyzing manifest",
    AnalysisStep.DEX: "Analyzing DEX files",
    AnalysisStep.NATIVE: "Scanning native libraries",
    AnalysisStep.ASSETS: "Scanning assets",
    AnalysisStep.FINGERPRINTING: "Fingerprinting frameworks",
    AnalysisStep.DEPENDENCIES: "Detecting dependencies",
    AnalysisStep.SECURITY: "Running security checks",
    AnalysisStep.REPORT: "Building report",
    AnalysisStep.DONE: "Analysis complete",
    AnalysisStep.ERROR: "ERROR",
}

_completed_steps: set[str] = set()


def _make_progress(verbose: bool):
    def _cb(step: str, msg: str) -> None:
        if step == AnalysisStep.ERROR:
            print(_c(f"\n✗ {msg}", RED), file=sys.stderr)
            return
        if step == AnalysisStep.DONE:
            print(_c("\n✓ Analysis complete", GREEN))
            return
        if step not in _completed_steps:
            label = _STEP_LABELS.get(step, step)
            if verbose:
                print(f"  → {label}...", end="\r")
        if msg and step not in _completed_steps:
            label = _STEP_LABELS.get(step, step)
            print(f"  {_c('✓', GREEN)} {label}           ")
            _completed_steps.add(step)
    return _cb


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="apk-analyzer",
        description="APK Stack Analyzer — identify Android application technology stacks",
    )
    parser.add_argument("apk", help="Path to the APK file")
    parser.add_argument("--output", "-o", help="Write report to file (.json or .md)")
    parser.add_argument("--json", action="store_true", help="Print JSON report to stdout")
    parser.add_argument("--markdown", action="store_true", help="Print Markdown report to stdout")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose progress output")
    parser.add_argument("--jadx", help="Path to JADX binary")
    parser.add_argument("--apktool", help="Path to APKTool binary")

    args = parser.parse_args()
    apk_path = Path(args.apk)

    if not apk_path.exists():
        print(_c(f"Error: file not found: {apk_path}", RED), file=sys.stderr)
        sys.exit(1)

    print(_c(f"\nAPK Stack Analyzer", BOLD))
    print("─" * 50)
    print(f"File: {apk_path.name}")
    print()

    progress_cb = _make_progress(args.verbose)

    result = analyze_apk(
        str(apk_path),
        progress_callback=progress_cb,
        jadx_path=args.jadx,
        apktool_path=args.apktool,
    )

    if result.errors:
        print(_c("\nAnalysis failed:", RED), file=sys.stderr)
        for err in result.errors:
            print(err, file=sys.stderr)
        sys.exit(1)

    # ----------------------------------------------------------------
    # Human-readable output
    # ----------------------------------------------------------------
    if not args.json and not args.markdown:
        m = result.manifest
        meta = result.metadata

        print()
        print(_c("APPLICATION", BOLD))
        print(f"  Package      : {m.package_name or _c('Unknown', DIM)}")
        print(f"  Version      : {m.version_name or _c('Unknown', DIM)}")
        print(f"  Version Code : {m.version_code or _c('Unknown', DIM)}")
        print(f"  Min SDK      : {m.min_sdk or _c('Unknown', DIM)}")
        print(f"  Target SDK   : {m.target_sdk or _c('Unknown', DIM)}")
        print(f"  File Size    : {_fmt_size(meta.file_size_bytes)}")
        print(f"  SHA-256      : {_c(meta.sha256[:16] + '...', DIM)}")

        print()
        print(_c("PRIMARY FRAMEWORK", BOLD))
        if result.is_hybrid:
            print(_c("  ⚠ Hybrid / Multi-Framework Application", YELLOW))
        if result.primary_framework:
            pf = result.primary_framework
            print(f"  {_c(pf.name, CYAN)}")
            print(f"  Confidence: {_confidence_str(pf.confidence)}")
            if pf.sub_technologies:
                for k, v in pf.sub_technologies.items():
                    print(f"  {k.replace('_', ' ').title()}: {_c(v, CYAN)}")
        else:
            print(_c("  Unknown", DIM))

        print()
        print(_c("ALL DETECTED FRAMEWORKS", BOLD))
        for fw in result.frameworks:
            if fw.name in ("Kotlin", "Jetpack Compose"):
                continue
            print(f"  {fw.name:<30} {_confidence_str(fw.confidence)}")

        print()
        print(_c("ARCHITECTURES", BOLD))
        if result.architectures:
            for abi in result.architectures:
                print(f"  ✓ {abi}")
        else:
            print(_c("  No native libraries", DIM))

        print()
        print(_c("EVIDENCE", BOLD))
        shown = set()
        for ev in result.all_evidence:
            if ev.artifact not in shown:
                strength_icon = {"strong": "●", "medium": "◑", "weak": "○"}.get(ev.strength.value, "·")
                print(f"  {strength_icon} {ev.artifact}")
                shown.add(ev.artifact)
            if len(shown) >= 20:
                remaining = len(result.all_evidence) - len(shown)
                if remaining > 0:
                    print(_c(f"  ... and {remaining} more evidence items", DIM))
                break

        print()
        print(_c("NATIVE LIBRARIES", BOLD))
        if result.native_libraries:
            # Show first 15 unique library names
            shown_libs: set[str] = set()
            for lib in result.native_libraries:
                if lib.name not in shown_libs:
                    purpose = f" — {lib.detected_purpose}" if lib.detected_purpose else ""
                    print(f"  ✓ {lib.name:<35} {_fmt_size(lib.size_bytes)}{purpose}")
                    shown_libs.add(lib.name)
                if len(shown_libs) >= 15:
                    remaining = len({l.name for l in result.native_libraries}) - 15
                    if remaining > 0:
                        print(_c(f"  ... and {remaining} more", DIM))
                    break
        else:
            print(_c("  None detected", DIM))

        print()
        print(_c("DEPENDENCIES", BOLD))
        if result.dependencies:
            for dep in result.dependencies[:20]:
                print(f"  ✓ {dep.name}")
            if len(result.dependencies) > 20:
                print(_c(f"  ... and {len(result.dependencies) - 20} more", DIM))
        else:
            print(_c("  None detected", DIM))

        print()
        print(_c("SECURITY INDICATORS", BOLD))
        if result.security_findings:
            for finding in result.security_findings[:10]:
                sev_icon = {
                    "high": _c("!", RED),
                    "medium": _c("!", YELLOW),
                    "low": _c("·", CYAN),
                    "info": _c("·", DIM),
                }.get(finding.severity.value, "·")
                print(f"  {sev_icon} {finding.title}")
        else:
            print(_c("  No indicators found", DIM))

        if result.warnings:
            print()
            print(_c("WARNINGS", YELLOW))
            for w in result.warnings:
                print(f"  ⚠ {w}")

        print()
        print("─" * 50)
        print(_c("Analysis completed.", GREEN))
        print()

    # ----------------------------------------------------------------
    # File / stdout output
    # ----------------------------------------------------------------
    if args.output:
        out_path = Path(args.output)
        if out_path.suffix.lower() == ".json":
            out_path.write_text(export_json(result), encoding="utf-8")
            print(f"JSON report written to: {out_path}")
        elif out_path.suffix.lower() == ".md":
            out_path.write_text(export_markdown(result), encoding="utf-8")
            print(f"Markdown report written to: {out_path}")
        else:
            print(f"Unknown output format: {out_path.suffix}. Use .json or .md", file=sys.stderr)

    if args.json:
        print(export_json(result))

    if args.markdown:
        print(export_markdown(result))


if __name__ == "__main__":
    main()
