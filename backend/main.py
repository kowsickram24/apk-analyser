"""
FastAPI Backend — APK Stack Analyzer

Endpoints:
    POST /api/analyze             → Upload APK, start analysis job
    GET  /api/analysis/{id}       → Get analysis status + result
    GET  /api/analysis/{id}/export/json
    GET  /api/analysis/{id}/export/markdown
    GET  /api/health
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Optional

import aiofiles
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse

# Add project root to path so backend can import analyzer
sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzer.models import AnalysisStatus
from analyzer.orchestrator import AnalysisStep, analyze_apk
from analyzer.report_exporter import export_json, export_markdown

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "/tmp/apk_analyzer_uploads"))
MAX_UPLOAD_SIZE = int(os.getenv("MAX_UPLOAD_MB", "500")) * 1024 * 1024
JADX_PATH = os.getenv("JADX_PATH", "")
APKTOOL_PATH = os.getenv("APKTOOL_PATH", "")
WORKERS = int(os.getenv("ANALYSIS_WORKERS", "2"))

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# In-memory job store (MVP; replace with SQLite/Redis for production)
# ---------------------------------------------------------------------------

_jobs: dict[str, dict] = {}
_executor = ThreadPoolExecutor(max_workers=WORKERS)

app = FastAPI(
    title="APK Stack Analyzer API",
    version="1.0.0",
    description="Analyze Android APKs to identify technology stacks.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _init_job(analysis_id: str, filename: str) -> dict:
    job = {
        "analysis_id": analysis_id,
        "filename": filename,
        "status": AnalysisStatus.QUEUED.value,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
        "progress_steps": [],
        "current_step": None,
        "result": None,
        "error": None,
    }
    _jobs[analysis_id] = job
    return job


def _update_job_progress(job: dict, step: str, msg: str) -> None:
    job["status"] = AnalysisStatus.RUNNING.value
    job["current_step"] = step
    job["updated_at"] = datetime.utcnow().isoformat()
    if step == AnalysisStep.ERROR:
        job["status"] = AnalysisStatus.FAILED.value
        job["error"] = msg
    elif step == AnalysisStep.DONE:
        job["status"] = AnalysisStatus.COMPLETED.value
    # Append step to history
    if msg:
        job["progress_steps"].append({
            "step": step,
            "message": msg,
            "timestamp": datetime.utcnow().isoformat(),
        })


def _run_analysis(analysis_id: str, apk_path: str) -> None:
    """Run analysis synchronously in thread pool."""
    job = _jobs.get(analysis_id)
    if not job:
        return

    def progress_cb(step: str, msg: str) -> None:
        _update_job_progress(job, step, msg)

    try:
        result = analyze_apk(
            apk_path,
            progress_callback=progress_cb,
            jadx_path=JADX_PATH or None,
            apktool_path=APKTOOL_PATH or None,
        )
        job["result"] = result.to_dict()
        if result.errors:
            job["status"] = AnalysisStatus.FAILED.value
            job["error"] = "; ".join(result.errors[:3])
        else:
            job["status"] = AnalysisStatus.COMPLETED.value
    except Exception as e:
        job["status"] = AnalysisStatus.FAILED.value
        job["error"] = str(e)
    finally:
        # Clean up uploaded file
        try:
            os.unlink(apk_path)
        except OSError:
            pass
        job["updated_at"] = datetime.utcnow().isoformat()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/api/health")
async def health():
    """Health check endpoint."""
    jadx_available = bool(JADX_PATH and shutil.which(JADX_PATH))
    apktool_available = bool(APKTOOL_PATH and shutil.which(APKTOOL_PATH))
    return {
        "status": "ok",
        "version": "1.0.0",
        "jadx_available": jadx_available,
        "apktool_available": apktool_available,
    }


@app.post("/api/analyze")
async def analyze_endpoint(file: UploadFile = File(...)):
    """
    Upload an APK and start analysis.
    Returns analysis_id immediately; poll /api/analysis/{id} for status.
    """
    if not file.filename or not file.filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="Only .apk files are accepted.")

    # Generate unique ID
    analysis_id = str(uuid.uuid4())

    # Sanitize filename
    safe_name = Path(file.filename).name
    safe_name = "".join(c for c in safe_name if c.isalnum() or c in "._-")
    if not safe_name:
        safe_name = "uploaded.apk"

    # Save to disk
    dest_path = UPLOAD_DIR / f"{analysis_id}_{safe_name}"
    total_bytes = 0

    try:
        async with aiofiles.open(dest_path, "wb") as out:
            while True:
                chunk = await file.read(65536)
                if not chunk:
                    break
                total_bytes += len(chunk)
                if total_bytes > MAX_UPLOAD_SIZE:
                    await out.close()
                    dest_path.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=413,
                        detail=f"File exceeds maximum size limit ({MAX_UPLOAD_SIZE // 1024 // 1024} MB).",
                    )
                await out.write(chunk)
    except HTTPException:
        raise
    except Exception as e:
        dest_path.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail=f"Upload failed: {e}")

    # Initialize job
    job = _init_job(analysis_id, safe_name)
    job["file_size"] = total_bytes

    # Submit to thread pool
    loop = asyncio.get_event_loop()
    loop.run_in_executor(_executor, _run_analysis, analysis_id, str(dest_path))

    return {
        "analysis_id": analysis_id,
        "status": AnalysisStatus.QUEUED.value,
        "filename": safe_name,
        "file_size": total_bytes,
    }


@app.get("/api/analysis/{analysis_id}")
async def get_analysis(analysis_id: str):
    """Get the current status and result of an analysis."""
    job = _jobs.get(analysis_id)
    if not job:
        raise HTTPException(status_code=404, detail="Analysis not found.")

    response: dict = {
        "analysis_id": analysis_id,
        "status": job["status"],
        "filename": job["filename"],
        "created_at": job["created_at"],
        "updated_at": job["updated_at"],
        "current_step": job.get("current_step"),
        "progress_steps": job.get("progress_steps", []),
        "error": job.get("error"),
    }

    if job["status"] == AnalysisStatus.COMPLETED.value and job.get("result"):
        response["result"] = job["result"]

    return response


@app.get("/api/analysis/{analysis_id}/report")
async def get_report(analysis_id: str):
    """Get just the analysis result (no job metadata)."""
    job = _jobs.get(analysis_id)
    if not job:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    if job["status"] != AnalysisStatus.COMPLETED.value:
        raise HTTPException(status_code=202, detail="Analysis not yet complete.")
    return job["result"]


@app.get("/api/analysis/{analysis_id}/export/json")
async def export_json_endpoint(analysis_id: str):
    """Export the analysis result as JSON."""
    job = _jobs.get(analysis_id)
    if not job:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    if job["status"] != AnalysisStatus.COMPLETED.value:
        raise HTTPException(status_code=202, detail="Analysis not yet complete.")

    import json
    json_str = json.dumps(job["result"], indent=2)

    return StreamingResponse(
        iter([json_str]),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="apk-analysis-{analysis_id[:8]}.json"'
        },
    )


@app.get("/api/analysis/{analysis_id}/export/markdown")
async def export_markdown_endpoint(analysis_id: str):
    """Export the analysis result as Markdown."""
    from analyzer.models import AnalysisResult

    job = _jobs.get(analysis_id)
    if not job:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    if job["status"] != AnalysisStatus.COMPLETED.value:
        raise HTTPException(status_code=202, detail="Analysis not yet complete.")

    # Reconstruct AnalysisResult from dict for the exporter
    # For the API, we export from the dict directly via our report_exporter
    result_dict = job["result"]
    markdown = _dict_to_markdown(result_dict)

    return PlainTextResponse(
        content=markdown,
        headers={
            "Content-Disposition": f'attachment; filename="apk-analysis-{analysis_id[:8]}.md"',
            "Content-Type": "text/markdown; charset=utf-8",
        },
    )


@app.get("/api/analyses")
async def list_analyses():
    """List all known analyses (most recent first)."""
    return [
        {
            "analysis_id": jid,
            "filename": job.get("filename"),
            "status": job.get("status"),
            "created_at": job.get("created_at"),
        }
        for jid, job in sorted(
            _jobs.items(),
            key=lambda kv: kv[1].get("created_at", ""),
            reverse=True,
        )
    ]


# ---------------------------------------------------------------------------
# Inline markdown generator from dict (avoids re-instantiating models)
# ---------------------------------------------------------------------------

def _dict_to_markdown(result: dict) -> str:
    """Quick markdown export from raw result dict."""
    lines: list[str] = []
    m = result.get("manifest", {})
    meta = result.get("metadata", {})

    lines.append("# APK Stack Analysis Report")
    lines.append("")
    lines.append("## Application")
    lines.append("")
    lines.append(f"| Field | Value |")
    lines.append(f"|-------|-------|")
    lines.append(f"| Package | `{m.get('package_name', 'Unknown')}` |")
    lines.append(f"| Version | {m.get('version_name', 'Unknown')} |")
    lines.append(f"| Version Code | {m.get('version_code', 'Unknown')} |")
    lines.append(f"| Min SDK | {m.get('min_sdk', 'Unknown')} |")
    lines.append(f"| Target SDK | {m.get('target_sdk', 'Unknown')} |")

    size = meta.get("file_size_bytes", 0)
    if size >= 1024 * 1024:
        size_str = f"{size / (1024*1024):.1f} MB"
    elif size >= 1024:
        size_str = f"{size / 1024:.1f} KB"
    else:
        size_str = f"{size} B"

    lines.append(f"| File Size | {size_str} |")
    lines.append(f"| SHA-256 | `{meta.get('sha256', '')}` |")
    lines.append("")

    pf = result.get("primary_framework")
    lines.append("## Primary Stack")
    lines.append("")
    if result.get("is_hybrid"):
        lines.append("**⚠️ Hybrid / Multi-Framework Application**")
        lines.append("")
    if pf:
        conf = pf.get("confidence", "unknown").upper()
        lines.append(f"**{pf.get('name')}** — {conf} CONFIDENCE")
        lines.append("")
        for k, v in pf.get("sub_technologies", {}).items():
            lines.append(f"- {k.replace('_', ' ').title()}: **{v}**")
        lines.append("")

    frameworks = result.get("frameworks", [])
    if frameworks:
        lines.append("## All Detected Frameworks")
        lines.append("")
        for fw in frameworks:
            conf = fw.get("confidence", "unknown").upper()
            lines.append(f"### {fw.get('name')} — {conf}")
            lines.append("")
            for ev in fw.get("evidence", []):
                lines.append(f"- ✓ `{ev.get('artifact')}` ({ev.get('strength')}) — {ev.get('description', '')}")
            lines.append("")

    archs = result.get("architectures", [])
    lines.append("## CPU Architectures")
    lines.append("")
    for a in archs:
        lines.append(f"- ✓ `{a}`")
    if not archs:
        lines.append("_No native libraries_")
    lines.append("")

    native_libs = result.get("native_libraries", [])
    if native_libs:
        lines.append("## Native Libraries")
        lines.append("")
        lines.append("| Library | ABI | Size | Purpose |")
        lines.append("|---------|-----|------|---------|")
        for lib in native_libs:
            sz = lib.get("size_bytes", 0)
            sz_str = f"{sz / (1024*1024):.1f} MB" if sz >= 1024*1024 else f"{sz // 1024} KB"
            lines.append(
                f"| `{lib.get('name')}` | {lib.get('abi')} | {sz_str} | {lib.get('detected_purpose') or '—'} |"
            )
        lines.append("")

    deps = result.get("dependencies", [])
    if deps:
        lines.append("## Dependencies")
        lines.append("")
        lines.append("| Library | Evidence | Confidence |")
        lines.append("|---------|----------|------------|")
        for dep in deps:
            lines.append(f"| {dep.get('name')} | {dep.get('evidence_type')} | {dep.get('confidence', '').upper()} |")
        lines.append("")

    security = result.get("security_findings", [])
    if security:
        lines.append("## Security Findings")
        lines.append("")
        for finding in security:
            sev = finding.get("severity", "info").upper()
            lines.append(f"### [{sev}] {finding.get('title')}")
            lines.append("")
            lines.append(finding.get("description", ""))
            rec = finding.get("recommendation", "")
            if rec:
                lines.append("")
                lines.append(f"**Recommendation:** {rec}")
            lines.append("")

    lines.append("---")
    lines.append("_Generated by APK Stack Analyzer_")
    return "\n".join(lines)
