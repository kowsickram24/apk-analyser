"use client";

import { useState, useEffect } from "react";
import { Navbar } from "@/components/Navbar";
import { getHealth } from "@/lib/api";

export default function SettingsPage() {
  const [health, setHealth] = useState<{
    status: string; jadx_available: boolean; apktool_available: boolean;
  } | null>(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState("");

  const fetchHealth = async () => {
    setLoading(true); setErr("");
    try { setHealth(await getHealth()); }
    catch { setErr("Backend unreachable. Make sure the server is running on port 8000."); }
    finally { setLoading(false); }
  };

  useEffect(() => { fetchHealth(); }, []);

  return (
    <div className="page-shell">
      <Navbar />
      <main className="page-main">
        <div className="content-wrap" style={{ maxWidth: 720 }}>

          {/* Header */}
          <div className="page-header anim-up">
            <h1 className="page-title" style={{ fontSize: "1.75rem" }}>Settings</h1>
            <p className="page-sub">Backend configuration and tool availability status.</p>
          </div>

          {/* Backend status */}
          <div className="a-card anim-up" style={{ padding: "24px 28px", marginBottom: 16 }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
              <div style={{ fontWeight: 700, fontSize: "0.9375rem", color: "var(--text)" }}>
                🖥 Backend Status
              </div>
              <button className="btn btn-ghost btn-sm" onClick={fetchHealth} disabled={loading}>
                {loading ? <span className="anim-spin" style={{ display: "inline-block" }}>◌</span> : "↺"} Refresh
              </button>
            </div>

            {loading && (
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {[1, 2, 3].map(i => <div key={i} className="skeleton" style={{ height: 44, borderRadius: 10 }} />)}
              </div>
            )}

            {!loading && err && (
              <div style={{ display: "flex", gap: 12, alignItems: "flex-start", padding: "14px 18px", borderRadius: 12,
                background: "rgba(244,63,94,0.06)", border: "1px solid rgba(244,63,94,0.2)" }}>
                <span style={{ fontSize: 20 }}>❌</span>
                <span style={{ fontSize: "0.875rem", color: "#f87171" }}>{err}</span>
              </div>
            )}

            {!loading && health && (
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                <StatusRow label="API Server" ok={health.status === "ok"} detail="http://localhost:8000" />
                <StatusRow label="JADX"
                  ok={health.jadx_available}
                  detail={health.jadx_available ? "Available" : "Not found — set JADX_PATH env variable"} />
                <StatusRow label="APKTool"
                  ok={health.apktool_available}
                  detail={health.apktool_available ? "Available" : "Not found — set APKTOOL_PATH env variable"} />
              </div>
            )}
          </div>

          {/* Env vars */}
          <div className="a-card anim-up" style={{ padding: "24px 28px", marginBottom: 16 }}>
            <div style={{ fontWeight: 700, fontSize: "0.9375rem", color: "var(--text)", marginBottom: 18 }}>
              🔧 Environment Variables
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {[
                ["JADX_PATH",         "Path to JADX binary (optional)"],
                ["APKTOOL_PATH",       "Path to APKTool JAR/binary (optional)"],
                ["UPLOAD_DIR",         "Temporary upload directory (default: /tmp/...)"],
                ["MAX_UPLOAD_MB",      "Max APK file size in MB (default: 500)"],
                ["ANALYSIS_WORKERS",   "Concurrent analysis workers (default: 2)"],
              ].map(([k, v]) => (
                <div key={k} style={{ display: "flex", alignItems: "flex-start", gap: 12 }}>
                  <code style={{
                    fontFamily: "monospace", fontSize: "0.78rem", padding: "3px 10px",
                    borderRadius: 6, flexShrink: 0,
                    background: "rgba(59,130,246,0.1)", color: "#60a5fa", border: "1px solid rgba(59,130,246,0.2)"
                  }}>{k}</code>
                  <span style={{ fontSize: "0.8rem", color: "var(--text-3)", paddingTop: 4 }}>{v}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Start commands */}
          <div className="a-card anim-up" style={{ padding: "24px 28px" }}>
            <div style={{ fontWeight: 700, fontSize: "0.9375rem", color: "var(--text)", marginBottom: 18 }}>
              ▶ Start Commands
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
              {[
                { label: "Backend (from project root)",
                  cmd: ".\\venv\\Scripts\\python.exe -m uvicorn backend.main:app --reload --port 8000" },
                { label: "Frontend dev server",
                  cmd: "cd frontend && npm run dev" },
                { label: "Analyze APK via CLI",
                  cmd: ".\\venv\\Scripts\\python.exe -m analyzer.cli path\\to\\app.apk" },
                { label: "Run unit tests",
                  cmd: ".\\venv\\Scripts\\python.exe -m pytest analyzer\\tests\\ -v" },
              ].map(({ label, cmd }) => (
                <div key={label}>
                  <div style={{ fontSize: "0.75rem", color: "var(--text-3)", marginBottom: 5, fontWeight: 500 }}>{label}</div>
                  <code style={{
                    display: "block", fontFamily: "monospace", fontSize: "0.78rem",
                    padding: "12px 16px", borderRadius: 10, overflowX: "auto", whiteSpace: "nowrap",
                    background: "var(--bg-input)", color: "var(--text-2)", border: "1px solid var(--border)"
                  }}>{cmd}</code>
                </div>
              ))}
            </div>
          </div>

        </div>
      </main>
    </div>
  );
}

function StatusRow({ label, ok, detail }: { label: string; ok: boolean; detail: string }) {
  return (
    <div style={{
      display: "flex", alignItems: "center", gap: 12, padding: "11px 16px", borderRadius: 10,
      background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)"
    }}>
      <span style={{ fontSize: 18 }}>{ok ? "✅" : "❌"}</span>
      <span style={{ fontWeight: 600, fontSize: "0.875rem", color: "var(--text)", width: 100, flexShrink: 0 }}>{label}</span>
      <span style={{ fontSize: "0.8rem", color: "var(--text-3)" }}>{detail}</span>
    </div>
  );
}
