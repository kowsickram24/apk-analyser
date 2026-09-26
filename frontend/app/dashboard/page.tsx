"use client";

import { useState, useRef, useCallback, useEffect } from "react";
import { useRouter } from "next/navigation";
import {
  Upload, FileText, Hash, Zap, X, Loader2,
  CheckCircle2, XCircle, AlertCircle, RotateCcw,
  Clock, ChevronRight, Search, Lock, Cpu
} from "lucide-react";
import { Navbar } from "@/components/Navbar";
import {
  uploadAndAnalyze, formatBytes, listAnalyses, getAnalysis,
  ANALYSIS_STEP_LABELS, ORDERED_STEPS
} from "@/lib/api";
import type { AnalysisJob } from "@/lib/api";

const MAX_SIZE = 500 * 1024 * 1024;

async function sha256Browser(file: File): Promise<string> {
  const buf = await file.arrayBuffer();
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}

export default function DashboardPage() {
  const router = useRouter();
  const [dragOver, setDragOver]   = useState(false);
  const [file, setFile]           = useState<File | null>(null);
  const [hash, setHash]           = useState("");
  const [hashLoading, setHL]      = useState(false);
  const [stage, setStage]         = useState<"idle"|"uploading"|"analyzing"|"done"|"error">("idle");
  const [error, setError]         = useState("");
  const [job, setJob]             = useState<AnalysisJob | null>(null);
  const [recent, setRecent]       = useState<{ analysis_id:string; filename:string; status:string; created_at:string }[]>([]);
  const fileRef = useRef<HTMLInputElement>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    listAnalyses().then(setRecent).catch(() => {});
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, []);

  const handleFile = useCallback(async (f: File) => {
    setError(""); setHash(""); setJob(null);
    if (!f.name.toLowerCase().endsWith(".apk")) { setError("Please upload a valid .apk file."); return; }
    if (f.size > MAX_SIZE) { setError(`File too large (${formatBytes(f.size)}). Max 500 MB.`); return; }
    setFile(f); setStage("idle");
    setHL(true);
    try { setHash(await sha256Browser(f)); } catch { setHash("(failed)"); } finally { setHL(false); }
  }, []);

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault(); setDragOver(false);
    const f = e.dataTransfer.files[0];
    if (f) handleFile(f);
  }, [handleFile]);

  const startAnalysis = useCallback(async () => {
    if (!file) return;
    setStage("uploading"); setError("");
    try {
      const { analysis_id } = await uploadAndAnalyze(file);
      setStage("analyzing");
      pollRef.current = setInterval(async () => {
        try {
          const j = await getAnalysis(analysis_id);
          setJob(j);
          if (j.status === "completed") {
            clearInterval(pollRef.current!);
            setStage("done");
            listAnalyses().then(setRecent).catch(() => {});
            setTimeout(() => router.push(`/analysis/${analysis_id}`), 700);
          } else if (j.status === "failed") {
            clearInterval(pollRef.current!);
            setStage("error");
            setError(j.error || "Analysis failed.");
          }
        } catch { /* transient */ }
      }, 1500);
    } catch (err: unknown) {
      setStage("error");
      setError(err instanceof Error ? err.message : "Upload failed.");
    }
  }, [file, router]);

  const completedSteps = new Set(job?.progress_steps.map(s => s.step) ?? []);
  const currentStep    = job?.current_step ?? null;
  const showDropzone   = stage === "idle" && !file;
  const showFileCard   = !!file && stage === "idle";

  return (
    <div className="page-shell">
      <Navbar />
      <main className="page-main" style={{ flex: 1 }}>
        <div className="content-wrap">

          {/* ── Header ── */}
          <div className="page-header anim-up">
            <div className="page-tag">
              <Cpu size={11} />
              Static Analysis Tool
            </div>
            <h1 className="page-title">APK Stack Analyzer</h1>
            <p className="page-sub">
              Upload an Android APK to identify its technology stack, frameworks,
              native libraries, dependencies, and security indicators — instantly.
            </p>
          </div>

          {/* ── Upload area ── */}
          <div className="anim-up anim-delay-1">

            {/* ── Drop zone ── */}
            {showDropzone && (
              <div
                className={`drop-zone${dragOver ? " drag-over" : ""}`}
                onDragOver={e => { e.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                onDrop={onDrop}
                onClick={() => fileRef.current?.click()}
                role="button"
                tabIndex={0}
                aria-label="Upload APK"
                onKeyDown={e => e.key === "Enter" && fileRef.current?.click()}
              >
                <input
                  ref={fileRef}
                  type="file"
                  accept=".apk"
                  style={{ display: "none" }}
                  onChange={e => e.target.files?.[0] && handleFile(e.target.files[0])}
                  id="apk-file-input"
                />
                <div className="drop-icon-wrap">
                  <Upload size={28} color="#60a5fa" strokeWidth={1.5} />
                </div>
                <div className="drop-title">Drop your APK here</div>
                <div className="drop-sub">Drag & drop or click to browse</div>
                <div className="drop-or">— or —</div>
                <button
                  className="btn btn-primary"
                  onClick={e => { e.stopPropagation(); fileRef.current?.click(); }}
                  style={{ margin: "0 auto" }}
                >
                  <Upload size={15} />
                  Browse Files
                </button>
                <div className="drop-footer">Android APK · Max 500 MB · Static analysis only</div>
              </div>
            )}

            {/* ── File selected card ── */}
            {showFileCard && (
              <div className="file-card anim-up">
                <div className="file-card-header">
                  <div className="file-icon-box">
                    <FileText size={20} color="#60a5fa" strokeWidth={1.5} />
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div className="file-name" style={{ whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                      {file!.name}
                    </div>
                    <div className="file-size">{formatBytes(file!.size)}</div>
                  </div>
                  <button className="btn btn-ghost btn-sm"
                    onClick={() => { setFile(null); setHash(""); setError(""); setStage("idle"); }}>
                    <X size={13} /> Remove
                  </button>
                </div>

                <div className="file-card-body">
                  <div className="hash-box">
                    <div className="hash-label">
                      <Hash size={10} />
                      SHA-256
                    </div>
                    {hashLoading
                      ? <div className="skeleton" style={{ height: 16, width: "100%", borderRadius: 6 }} />
                      : <div className="hash-value">{hash}</div>
                    }
                  </div>

                  <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
                    <button
                      className="btn btn-primary"
                      onClick={startAnalysis}
                      disabled={hashLoading}
                      id="analyze-button"
                    >
                      <Zap size={15} />
                      Analyze APK
                      <ChevronRight size={15} />
                    </button>
                    <span style={{ fontSize: "0.8rem", color: "var(--text-3)" }}>
                      Usually takes 15–60 seconds
                    </span>
                  </div>
                </div>
              </div>
            )}

            {/* ── Uploading ── */}
            {stage === "uploading" && (
              <div className="status-card loading anim-up">
                <div className="status-icon" style={{ background: "rgba(59,130,246,0.1)" }}>
                  <Loader2 size={22} color="#60a5fa" className="anim-spin" />
                </div>
                <div>
                  <div style={{ fontWeight: 600, fontSize: "0.9375rem", color: "var(--text)", marginBottom: 4 }}>
                    Uploading APK…
                  </div>
                  <div style={{ fontSize: "0.85rem", color: "var(--text-2)" }}>Transferring to analysis server</div>
                </div>
              </div>
            )}

            {/* ── Analyzing: step list ── */}
            {stage === "analyzing" && (
              <div className="progress-card anim-up">
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 20 }}>
                  <Loader2 size={17} color="#60a5fa" className="anim-spin" />
                  <span style={{ fontWeight: 600, fontSize: "0.9375rem", color: "var(--text)" }}>Analyzing APK…</span>
                </div>
                <div>
                  {ORDERED_STEPS.map(step => {
                    const done   = completedSteps.has(step);
                    const active = currentStep === step && !done;
                    const cls    = done ? "done" : active ? "active" : "idle";
                    return (
                      <div className="progress-row" key={step}>
                        <div className={`step-dot ${cls}`}>
                          {done
                            ? <Check size={11} />
                            : active
                            ? <Loader2 size={11} className="anim-spin" />
                            : <span style={{ fontSize: 8, opacity: 0.4 }}>●</span>
                          }
                        </div>
                        <span className={`step-label ${cls}`}>{ANALYSIS_STEP_LABELS[step]}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* ── Done ── */}
            {stage === "done" && (
              <div className="status-card success anim-up">
                <div className="status-icon" style={{ background: "rgba(16,185,129,0.12)" }}>
                  <CheckCircle2 size={24} color="#34d399" />
                </div>
                <div>
                  <div style={{ fontWeight: 600, color: "#34d399", marginBottom: 4 }}>Analysis complete!</div>
                  <div style={{ fontSize: "0.85rem", color: "var(--text-2)" }}>Redirecting to results…</div>
                </div>
              </div>
            )}

            {/* ── Error ── */}
            {stage === "error" && (
              <div>
                <div className="status-card error anim-up">
                  <div className="status-icon" style={{ background: "rgba(244,63,94,0.1)" }}>
                    <XCircle size={24} color="#f87171" />
                  </div>
                  <div>
                    <div style={{ fontWeight: 600, color: "#f87171", marginBottom: 4 }}>Analysis failed</div>
                    <div style={{ fontSize: "0.85rem", color: "var(--text-2)" }}>{error}</div>
                  </div>
                </div>
                <button className="btn btn-ghost" style={{ marginTop: 12 }}
                  onClick={() => { setStage("idle"); setFile(null); setError(""); }}>
                  <RotateCcw size={14} /> Try again
                </button>
              </div>
            )}

            {/* ── Validation error ── */}
            {error && stage === "idle" && (
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 12,
                color: "#f87171", fontSize: "0.875rem" }}>
                <AlertCircle size={15} />
                {error}
              </div>
            )}
          </div>

          {/* ── Feature callouts ── */}
          {showDropzone && (
            <div className="feature-grid anim-up anim-delay-2">
              {[
                {
                  icon: <Zap size={20} color="#fbbf24" />,
                  bg: "rgba(245,158,11,0.08)",
                  title: "Framework Detection",
                  desc: "React Native, Flutter, Unity, Xamarin, Cordova, and more — with evidence"
                },
                {
                  icon: <Search size={20} color="#60a5fa" />,
                  bg: "rgba(59,130,246,0.08)",
                  title: "Evidence-Based Results",
                  desc: "Every detection backed by explicit DEX classes, .so libraries, and asset paths"
                },
                {
                  icon: <Lock size={20} color="#34d399" />,
                  bg: "rgba(16,185,129,0.08)",
                  title: "100% Static Analysis",
                  desc: "No code execution. No network calls. APKs never leave your server."
                },
              ].map(f => (
                <div className="feature-card" key={f.title}>
                  <div className="feature-emoji" style={{
                    width: 40, height: 40, borderRadius: 11,
                    background: f.bg, display: "flex", alignItems: "center", justifyContent: "center",
                    marginBottom: 14
                  }}>
                    {f.icon}
                  </div>
                  <div className="feature-title">{f.title}</div>
                  <div className="feature-desc">{f.desc}</div>
                </div>
              ))}
            </div>
          )}

          {/* ── Recent analyses ── */}
          {recent.length > 0 && showDropzone && (
            <div className="recent-section anim-up anim-delay-3">
              <div className="section-eyebrow">Recent Analyses</div>
              <div className="recent-card">
                {recent.slice(0, 6).map(a => (
                  <button key={a.analysis_id} className="recent-row"
                    onClick={() => router.push(`/analysis/${a.analysis_id}`)}>
                    <FileText size={15} color="var(--text-3)" className="recent-file-icon" style={{ flexShrink: 0 }} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div className="recent-name">{a.filename}</div>
                      <div className="recent-date">
                        <Clock size={10} />
                        {new Date(a.created_at).toLocaleString()}
                      </div>
                    </div>
                    <span className={`badge badge-${
                      a.status === "completed" ? "high" : a.status === "failed" ? "low" : "medium"
                    }`}>{a.status}</span>
                    <ChevronRight size={14} color="var(--text-3)" className="recent-arrow" />
                  </button>
                ))}
              </div>
            </div>
          )}

        </div>
      </main>
    </div>
  );
}
