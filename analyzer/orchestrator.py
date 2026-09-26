"""
APK Analysis Orchestrator.

Drives the complete analysis pipeline and emits progress events.
This module is the single entry-point for both the API backend and CLI.
"""

from __future__ import annotations

import shutil
import traceback
from typing import Callable, Optional

from .asset_analyzer import analyze_assets
from .dependency_detector import detect_dependencies
from .dex_analyzer import analyze_dex
from .extractor import extract_apk, build_file_tree
from .fingerprint_engine import run_fingerprint_engine
from .manifest_analyzer import analyze_manifest
from .models import AnalysisResult, APKMetadata
from .native_analyzer import analyze_native_libraries
from .security_analyzer import analyze_security


ProgressCallback = Callable[[str, str], None]


class AnalysisStep:
    VALIDATING = "validating"
    SHA256 = "sha256"
    EXTRACTING = "extracting"
    MANIFEST = "manifest"
    DEX = "dex"
    NATIVE = "native_libraries"
    ASSETS = "assets"
    FINGERPRINTING = "fingerprinting"
    DEPENDENCIES = "dependencies"
    SECURITY = "security"
    REPORT = "report"
    DONE = "done"
    ERROR = "error"


def analyze_apk(
    apk_path: str,
    *,
    progress_callback: Optional[ProgressCallback] = None,
    keep_extract_dir: bool = False,
    jadx_path: Optional[str] = None,
    apktool_path: Optional[str] = None,
) -> AnalysisResult:
    """
    Run the full APK analysis pipeline.

    Args:
        apk_path: Path to the APK file.
        progress_callback: Called with (step_name, message) at each stage.
        keep_extract_dir: If True, do not delete the extraction directory (for debugging).
        jadx_path: Optional path to JADX binary.
        apktool_path: Optional path to APKTool binary.

    Returns:
        AnalysisResult with all findings.
    """
    result = AnalysisResult()
    extract_dir: Optional[str] = None

    def emit(step: str, msg: str = "") -> None:
        if progress_callback:
            progress_callback(step, msg)

    try:
        # ----------------------------------------------------------------
        # Step 1 + 2: Validate + SHA256 + Extract
        # ----------------------------------------------------------------
        emit(AnalysisStep.VALIDATING, "Validating APK...")

        def _extract_progress(event: str) -> None:
            if event == "apk_validated":
                emit(AnalysisStep.VALIDATING, "APK validated")
            elif event == "sha256_calculated":
                emit(AnalysisStep.SHA256, "SHA-256 calculated")
            elif event == "apk_extracted":
                emit(AnalysisStep.EXTRACTING, "APK extracted")

        extract_dir, metadata = extract_apk(apk_path, progress_callback=_extract_progress)

        # Check for optional tools
        metadata.jadx_available = bool(jadx_path and shutil.which(jadx_path))
        metadata.apktool_available = bool(apktool_path and shutil.which(apktool_path))
        result.metadata = metadata

        # ----------------------------------------------------------------
        # Step 3: Manifest Analysis
        # ----------------------------------------------------------------
        emit(AnalysisStep.MANIFEST, "Analyzing AndroidManifest.xml...")
        try:
            result.manifest = analyze_manifest(extract_dir)
        except Exception as e:
            result.warnings.append(f"Manifest analysis error: {e}")
        emit(AnalysisStep.MANIFEST, "Manifest analyzed")

        # ----------------------------------------------------------------
        # Step 4: DEX Analysis
        # ----------------------------------------------------------------
        emit(AnalysisStep.DEX, "Analyzing DEX files...")
        try:
            result.dex_analysis = analyze_dex(extract_dir)
        except Exception as e:
            result.warnings.append(f"DEX analysis error: {e}")
        emit(AnalysisStep.DEX, "DEX files analyzed")

        # ----------------------------------------------------------------
        # Step 5: Native Library Analysis
        # ----------------------------------------------------------------
        emit(AnalysisStep.NATIVE, "Analyzing native libraries...")
        try:
            result.native_libraries, result.architectures = analyze_native_libraries(extract_dir)
        except Exception as e:
            result.warnings.append(f"Native library analysis error: {e}")
        emit(AnalysisStep.NATIVE, "Native libraries analyzed")

        # ----------------------------------------------------------------
        # Step 6: Asset Analysis
        # ----------------------------------------------------------------
        emit(AnalysisStep.ASSETS, "Analyzing assets...")
        try:
            result.assets, result.urls = analyze_assets(extract_dir)
        except Exception as e:
            result.warnings.append(f"Asset analysis error: {e}")
        emit(AnalysisStep.ASSETS, "Assets analyzed")

        # ----------------------------------------------------------------
        # Step 7: Framework Fingerprinting
        # ----------------------------------------------------------------
        emit(AnalysisStep.FINGERPRINTING, "Detecting frameworks...")
        try:
            activity_names = [a.name for a in result.manifest.activities]
            all_frameworks, primary, is_hybrid = run_fingerprint_engine(
                extract_dir=extract_dir,
                packages=result.dex_analysis.packages,
                libs=result.native_libraries,
                activities=activity_names,
            )
            result.frameworks = all_frameworks
            result.primary_framework = primary
            result.is_hybrid = is_hybrid

            # Collect all evidence into top-level list
            for fw in all_frameworks:
                result.all_evidence.extend(fw.evidence)
        except Exception as e:
            result.warnings.append(f"Framework fingerprinting error: {e}")
        emit(AnalysisStep.FINGERPRINTING, "Frameworks detected")

        # ----------------------------------------------------------------
        # Step 8: Dependency Detection
        # ----------------------------------------------------------------
        emit(AnalysisStep.DEPENDENCIES, "Detecting dependencies...")
        try:
            result.dependencies = detect_dependencies(result.dex_analysis.packages)
        except Exception as e:
            result.warnings.append(f"Dependency detection error: {e}")
        emit(AnalysisStep.DEPENDENCIES, "Dependencies detected")

        # ----------------------------------------------------------------
        # Step 9: Security Analysis
        # ----------------------------------------------------------------
        emit(AnalysisStep.SECURITY, "Running security checks...")
        try:
            result.security_findings = analyze_security(extract_dir, result.manifest)
        except Exception as e:
            result.warnings.append(f"Security analysis error: {e}")
        emit(AnalysisStep.SECURITY, "Security checks complete")

        # ----------------------------------------------------------------
        # Step 10: File Tree
        # ----------------------------------------------------------------
        emit(AnalysisStep.REPORT, "Building file tree...")
        try:
            result.file_tree = build_file_tree(extract_dir)
        except Exception as e:
            result.warnings.append(f"File tree error: {e}")

        emit(AnalysisStep.DONE, "Analysis complete")

    except Exception as e:
        result.errors.append(str(e))
        result.errors.append(traceback.format_exc())
        emit(AnalysisStep.ERROR, str(e))

    finally:
        if extract_dir and not keep_extract_dir:
            try:
                shutil.rmtree(extract_dir, ignore_errors=True)
            except Exception:
                pass

    return result
