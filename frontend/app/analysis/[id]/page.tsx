"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  BarChart3, Cpu, FileText, Package, Settings, Shield, Globe, FolderTree,
  Download, Loader2, CheckCircle2, XCircle, AlertCircle, AlertTriangle,
  Info, ChevronRight, ChevronDown, Check, Star, Layers, RefreshCw,
  Inbox, Circle
} from "lucide-react";
import { Navbar } from "@/components/Navbar";
import { getAnalysis, formatBytes, getExportUrl } from "@/lib/api";
import type {
  AnalysisJob, AnalysisResult, FrameworkDetection, Evidence,
  NativeLibrary, Dependency, SecurityFinding, FileTreeNode,
  AndroidComponent, DetectedURL
} from "@/lib/api";

const TABS = [
  { id: "overview",     label: "Overview",     Icon: BarChart3  },
  { id: "framework",    label: "Framework",    Icon: Cpu        },
  { id: "manifest",     label: "Manifest",     Icon: FileText   },
  { id: "dependencies", label: "Dependencies", Icon: Package    },
  { id: "native",       label: "Native Libs",  Icon: Layers     },
  { id: "security",     label: "Security",     Icon: Shield     },
  { id: "urls",         label: "URLs",         Icon: Globe      },
  { id: "structure",    label: "File Tree",    Icon: FolderTree },
];

export default function AnalysisPage() {
  const params = useParams();
  const router = useRouter();
  const id = params.id as string;
  const [job, setJob]     = useState<AnalysisJob | null>(null);
  const [loading, setL]   = useState(true);
  const [tab, setTab]     = useState("overview");
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetch_ = useCallback(async () => {
    try {
      const j = await getAnalysis(id);
      setJob(j);
      if (j.status === "completed" || j.status === "failed") {
        if (pollRef.current) clearInterval(pollRef.current);
      }
    } catch { /* ignore */ }
    finally { setL(false); }
  }, [id]);

  useEffect(() => {
    fetch_();
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [fetch_]);

  useEffect(() => {
    if (job && (job.status === "queued" || job.status === "running")) {
      pollRef.current = setInterval(fetch_, 2000);
      return () => { if (pollRef.current) clearInterval(pollRef.current); };
    }
  }, [job?.status, fetch_]);

  if (loading) return <Shell />;
  if (!job)    return <NotFound onBack={() => router.push("/dashboard")} />;

  const result  = job.result as AnalysisResult | undefined;
  const running = job.status === "queued" || job.status === "running";

  return (
    <div className="page-shell">
      <Navbar />
      <main className="page-main">
        <div className="content-wrap-wide">

          {/* ── Breadcrumb + header ── */}
          <div className="anim-up">
            <div className="breadcrumb">
              <span onClick={() => router.push("/dashboard")} style={{ cursor: "pointer" }}>Dashboard</span>
              <ChevronRight size={10} className="breadcrumb-sep" />
              <span>Analysis</span>
              <ChevronRight size={10} className="breadcrumb-sep" />
              <span style={{ fontFamily: "monospace" }}>{id.slice(0, 8)}</span>
            </div>

            <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 16, marginBottom: 12 }}>
              <div>
                <h1 style={{ fontSize: "1.375rem", fontWeight: 700, letterSpacing: "-0.02em", color: "var(--text)", marginBottom: 4 }}>
                  {result?.manifest?.package_name || job.filename}
                </h1>
                {result?.manifest?.package_name && (
                  <p style={{ fontSize: "0.8rem", color: "var(--text-3)" }}>{job.filename}</p>
                )}
              </div>

              <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
                {running && (
                  <span style={{ display: "flex", alignItems: "center", gap: 6, fontSize: "0.78rem",
                    padding: "6px 12px", borderRadius: 8,
                    background: "rgba(59,130,246,0.1)", color: "#60a5fa", border: "1px solid rgba(59,130,246,0.2)" }}>
                    <Loader2 size={12} className="anim-spin" />
                    {job.status === "queued" ? "Queued" : "Analyzing…"}
                  </span>
                )}
                {result && (
                  <>
                    <a href={getExportUrl(id, "json")} download className="btn btn-ghost btn-sm">
                      <Download size={13} /> JSON
                    </a>
                    <a href={getExportUrl(id, "markdown")} download className="btn btn-ghost btn-sm">
                      <Download size={13} /> Markdown
                    </a>
                  </>
                )}
              </div>
            </div>

            {/* Meta strip */}
            {result && (
              <div className="meta-strip">
                <Pill label="Version"    val={result.manifest?.version_name || "—"} />
                <Pill label="Min SDK"    val={result.manifest?.min_sdk?.toString() || "—"} />
                <Pill label="Target SDK" val={result.manifest?.target_sdk?.toString() || "—"} />
                <Pill label="Size"       val={formatBytes(result.metadata?.file_size_bytes || 0)} />
                <Pill label="SHA-256"    val={(result.metadata?.sha256 || "").slice(0, 16) + "…"} mono />
              </div>
            )}
          </div>

          {/* ── Error state ── */}
          {job.status === "failed" && (
            <div className="error-block anim-up" style={{ marginTop: 20 }}>
              <XCircle size={22} color="#f87171" style={{ flexShrink: 0, marginTop: 2 }} />
              <div>
                <div style={{ fontWeight: 600, color: "#f87171", marginBottom: 4 }}>Analysis Failed</div>
                <div style={{ fontSize: "0.875rem", color: "var(--text-2)" }}>{job.error}</div>
              </div>
            </div>
          )}

          {/* ── Running progress ── */}
          {running && (
            <div className="a-card" style={{ padding: "20px 24px", marginTop: 20 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
                <Loader2 size={16} color="#60a5fa" className="anim-spin" />
                <span style={{ fontWeight: 600, color: "var(--text)" }}>Analysis in progress…</span>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {job.progress_steps.slice(-5).map((s, i) => (
                  <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: "0.8rem", color: "var(--text-2)" }}>
                    <Check size={12} color="#34d399" /> {s.message}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ── Tabs + content ── */}
          {result && (
            <div style={{ marginTop: 28 }}>
              <div className="tab-bar anim-up" style={{ marginBottom: 24, overflowX: "auto" }}>
                {TABS.map(({ id: tid, label, Icon }) => (
                  <button key={tid} className={`tab-btn${tab === tid ? " active" : ""}`}
                    onClick={() => setTab(tid)} id={`tab-${tid}`}>
                    <Icon size={13} />
                    {label}
                  </button>
                ))}
              </div>

              <div className="anim-up">
                {tab === "overview"     && <OverviewTab result={result} />}
                {tab === "framework"    && <FrameworkTab result={result} />}
                {tab === "manifest"     && <ManifestTab result={result} />}
                {tab === "dependencies" && <DepsTab deps={result.dependencies} />}
                {tab === "native"       && <NativeTab libs={result.native_libraries} archs={result.architectures} />}
                {tab === "security"     && <SecurityTab findings={result.security_findings} />}
                {tab === "urls"         && <URLsTab urls={result.urls} />}
                {tab === "structure"    && <TreeTab tree={result.file_tree} />}
              </div>
            </div>
          )}

        </div>
      </main>
    </div>
  );
}

// ─── Shared helpers ────────────────────────────────────────────────────────────

function Pill({ label, val, mono }: { label:string; val:string; mono?: boolean }) {
  return (
    <div className="meta-item">
      <span className="meta-label">{label}:</span>
      <span className="meta-val" style={mono ? { fontFamily: "monospace" } : {}}>{val}</span>
    </div>
  );
}

function SLabel({ children, count }: { children: React.ReactNode; count?: number }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14 }}>
      <span className="section-label">{children}</span>
      {count !== undefined && (
        <span style={{ fontSize: "0.65rem", padding: "2px 8px", borderRadius: 99,
          background: "var(--bg-hover)", color: "var(--text-3)", border: "1px solid var(--border)" }}>
          {count}
        </span>
      )}
    </div>
  );
}

function ConfBadge({ c }: { c: string }) {
  return <span className={`badge badge-${c}`}>{c.toUpperCase()}</span>;
}

// ─── Overview ──────────────────────────────────────────────────────────────────

function OverviewTab({ result }: { result: AnalysisResult }) {
  const pf = result.primary_framework;
  const highSec = result.security_findings.filter(f => f.severity === "high").length;
  const medSec  = result.security_findings.filter(f => f.severity === "medium").length;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>

      {/* Primary framework */}
      <div className={`a-card${pf?.confidence === "high" ? " a-card-accent" : ""}`}
        style={{ padding: "28px 32px" }}>
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 16 }}>
          <div>
            <div className="section-label" style={{ marginBottom: 10 }}>Primary Framework</div>
            {result.is_hybrid && (
              <div style={{ display: "flex", alignItems: "center", gap: 7, marginBottom: 10,
                fontSize: "0.875rem", color: "#fbbf24" }}>
                <AlertTriangle size={15} /> Hybrid / Multi-Framework Application
              </div>
            )}
            {pf ? (
              <>
                <div style={{ fontSize: "2rem", fontWeight: 800, letterSpacing: "-0.03em",
                  color: "var(--text)", lineHeight: 1, marginBottom: 12 }}>
                  {pf.name}
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                  <ConfBadge c={pf.confidence} />
                  {Object.entries(pf.sub_technologies).map(([k, v]) => (
                    <span key={k} className="badge badge-info">{v}</span>
                  ))}
                </div>
              </>
            ) : (
              <div style={{ fontSize: "1.25rem", color: "var(--text-2)" }}>Unknown</div>
            )}
          </div>
          <div style={{ width: 56, height: 56, borderRadius: 16, display: "flex",
            alignItems: "center", justifyContent: "center", flexShrink: 0,
            background: "rgba(59,130,246,0.08)", border: "1px solid rgba(59,130,246,0.15)" }}>
            <Cpu size={26} color="#60a5fa" strokeWidth={1.5} />
          </div>
        </div>
      </div>

      {/* Stats */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 12 }}>
        <StatCard Icon={Layers}   label="Native Libs"  val={result.native_libraries.length} color="#60a5fa" />
        <StatCard Icon={Cpu}      label="Architectures" val={result.architectures.length} color="#a78bfa" />
        <StatCard Icon={Package}  label="Dependencies"  val={result.dependencies.length} color="#34d399" />
        <StatCard Icon={Shield}   label="Permissions"   val={result.manifest?.uses_permissions?.length || 0}
          color="#fbbf24" warn={result.manifest?.permissions?.filter(p => p.is_sensitive).length > 0} />
      </div>

      {/* Security summary */}
      {(highSec > 0 || medSec > 0) && (
        <div className="a-card" style={{ padding: "20px 24px" }}>
          <SLabel>Security Summary</SLabel>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            {highSec > 0 && (
              <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 14px", borderRadius: 10,
                background: "rgba(244,63,94,0.08)", border: "1px solid rgba(244,63,94,0.2)", color: "#f87171", fontSize: "0.875rem" }}>
                <AlertCircle size={15} /> {highSec} High Severity
              </div>
            )}
            {medSec > 0 && (
              <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 14px", borderRadius: 10,
                background: "rgba(245,158,11,0.08)", border: "1px solid rgba(245,158,11,0.2)", color: "#fbbf24", fontSize: "0.875rem" }}>
                <AlertTriangle size={15} /> {medSec} Medium
              </div>
            )}
          </div>
        </div>
      )}

      {/* DEX */}
      {result.dex_analysis && (
        <div className="a-card" style={{ padding: "20px 24px" }}>
          <SLabel>DEX Analysis</SLabel>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 20 }}>
            <InfoR label="DEX Files"     val={result.dex_analysis.dex_files.join(", ") || "None"} />
            <InfoR label="Total Classes" val={result.dex_analysis.total_classes.toLocaleString()} />
            <InfoR label="Total Methods" val={result.dex_analysis.total_methods > 0 ? result.dex_analysis.total_methods.toLocaleString() : "N/A"} />
          </div>
        </div>
      )}

      {/* Architectures */}
      <div className="a-card" style={{ padding: "20px 24px" }}>
        <SLabel count={result.architectures.length}>CPU Architectures</SLabel>
        {result.architectures.length > 0 ? (
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            {result.architectures.map(abi => (
              <span key={abi} className="badge badge-info" style={{ padding: "6px 14px", fontSize: "0.8rem", gap: 6 }}>
                <Check size={11} /> {abi}
              </span>
            ))}
          </div>
        ) : (
          <div style={{ color: "var(--text-3)", fontSize: "0.875rem" }}>No native libraries detected</div>
        )}
      </div>
    </div>
  );
}

function StatCard({ Icon, label, val, color, warn }: { Icon: any; label:string; val:number; color:string; warn?:boolean }) {
  return (
    <div className="stat-card">
      <div className="stat-icon" style={{ background: warn ? "rgba(245,158,11,0.1)" : `${color}15` }}>
        <Icon size={18} color={warn ? "#fbbf24" : color} strokeWidth={1.5} />
      </div>
      <div>
        <div className="stat-value">{val}</div>
        <div className="stat-label">{label}</div>
      </div>
    </div>
  );
}

function InfoR({ label, val }: { label:string; val:string }) {
  return (
    <div>
      <div className="info-row-label">{label}</div>
      <div className="info-row-value">{val}</div>
    </div>
  );
}

// ─── Framework Tab ─────────────────────────────────────────────────────────────

function FrameworkTab({ result }: { result: AnalysisResult }) {
  const sorted = [...result.frameworks].sort((a, b) => {
    const o = { high: 0, medium: 1, low: 2, unknown: 3 };
    return (o[a.confidence as keyof typeof o] ?? 9) - (o[b.confidence as keyof typeof o] ?? 9);
  });
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      {sorted.map(fw => <FwCard key={fw.name} fw={fw} isPrimary={result.primary_framework?.name === fw.name} />)}
      {!sorted.length && <EmptyState Icon={Cpu} title="No frameworks detected" sub="Unknown or uncommon stack." />}
    </div>
  );
}

function FwCard({ fw, isPrimary }: { fw: FrameworkDetection; isPrimary: boolean }) {
  const [open, setOpen] = useState(isPrimary);
  return (
    <div className={`a-card${isPrimary ? " a-card-accent" : ""}`} style={{ overflow: "hidden" }}>
      {isPrimary && (
        <div style={{ padding: "6px 20px", fontSize: "0.7rem", fontWeight: 700, letterSpacing: "0.06em",
          textTransform: "uppercase", color: "#60a5fa",
          background: "rgba(59,130,246,0.08)", borderBottom: "1px solid rgba(59,130,246,0.15)",
          display: "flex", alignItems: "center", gap: 6 }}>
          <Star size={11} fill="#60a5fa" /> Primary Framework
        </div>
      )}
      <button style={{ width: "100%", display: "flex", alignItems: "center", justifyContent: "space-between",
        gap: 16, padding: "18px 20px", border: "none", background: "transparent",
        cursor: "pointer", textAlign: "left" }}
        onClick={() => setOpen(!open)} id={`fw-${fw.name.replace(/\s+/g, "-").toLowerCase()}`}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap", marginBottom: 6 }}>
            <span style={{ fontSize: "1rem", fontWeight: 700, color: "var(--text)" }}>{fw.name}</span>
            <ConfBadge c={fw.confidence} />
            {Object.entries(fw.sub_technologies).map(([k, v]) => (
              <span key={k} className="badge badge-purple">{v}</span>
            ))}
          </div>
          <div style={{ fontSize: "0.78rem", color: "var(--text-3)" }}>
            {fw.evidence.length} evidence item{fw.evidence.length !== 1 ? "s" : ""}
            {fw.negative_evidence.length > 0 ? ` · ${fw.negative_evidence.length} not detected` : ""}
          </div>
        </div>
        {open
          ? <ChevronDown size={16} color="var(--text-3)" style={{ flexShrink: 0 }} />
          : <ChevronRight size={16} color="var(--text-3)" style={{ flexShrink: 0 }} />
        }
      </button>
      {open && (
        <div style={{ padding: "0 20px 20px" }}>
          {fw.evidence.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <div className="section-label" style={{ marginBottom: 10 }}>Evidence</div>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {fw.evidence.map((ev, i) => <EvRow key={i} ev={ev} />)}
              </div>
            </div>
          )}
          {fw.negative_evidence.length > 0 && (
            <div>
              <div className="section-label" style={{ marginBottom: 10 }}>Not Detected</div>
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                {fw.negative_evidence.map((neg, i) => (
                  <div key={i} style={{ display: "flex", alignItems: "center", gap: 8,
                    fontSize: "0.8rem", color: "var(--text-3)" }}>
                    <XCircle size={12} color="var(--text-3)" />
                    <code style={{ fontFamily: "monospace" }}>{neg.artifact}</code>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function EvRow({ ev }: { ev: Evidence }) {
  const colors = { strong: "#34d399", medium: "#fbbf24", weak: "#8b9dc0" };
  const dotColor = colors[ev.strength as keyof typeof colors] ?? "#8b9dc0";
  const typeMap: Record<string, string> = {
    native_library: "native lib",
    dex_class: "dex class",
    dex_package: "dex pkg",
    asset_file: "asset",
    manifest_attribute: "manifest",
    manifest_component: "component",
  };
  return (
    <div className="evidence-row">
      <Circle size={8} fill={dotColor} color={dotColor} style={{ marginTop: 4, flexShrink: 0 }} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <code style={{ fontFamily: "monospace", fontSize: "0.8rem", color: "var(--text)",
          display: "block", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {ev.artifact}
        </code>
        {ev.description && (
          <div style={{ fontSize: "0.75rem", color: "var(--text-3)", marginTop: 2 }}>{ev.description}</div>
        )}
      </div>
      <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
        <span style={{ fontSize: "0.7rem", padding: "2px 8px", borderRadius: 5,
          background: "var(--bg-hover)", color: "var(--text-3)" }}>
          {typeMap[ev.type] ?? ev.type}
        </span>
        <span style={{ fontSize: "0.7rem", fontWeight: 700, color: dotColor }}>{ev.strength}</span>
      </div>
    </div>
  );
}

// ─── Manifest Tab ──────────────────────────────────────────────────────────────

function ManifestTab({ result }: { result: AnalysisResult }) {
  const m = result.manifest;
  const [sec, setSec] = useState("activities");

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div className="a-card" style={{ padding: "20px 24px" }}>
        <SLabel>Application Info</SLabel>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 18 }}>
          {[
            ["Package", m.package_name],
            ["Version Name", m.version_name],
            ["Version Code", m.version_code],
            ["Min SDK", m.min_sdk?.toString() ?? "Unknown"],
            ["Target SDK", m.target_sdk?.toString() ?? "Unknown"],
            ["Debuggable", m.debuggable ? "⚠ YES" : "No"],
            ["Allow Backup", m.allow_backup ? "Yes" : "No"],
            ["Net Security Config", m.network_security_config ? "Yes" : "No"],
            ["Cleartext Traffic", m.uses_cleartext_traffic === true ? "⚠ Permitted" : "No / Unset"],
          ].map(([k, v]) => <InfoR key={k as string} label={k as string} val={(v as string) || "—"} />)}
        </div>
      </div>

      {/* Components */}
      <div className="a-card" style={{ padding: "20px 24px" }}>
        <div style={{ display: "flex", gap: 6, marginBottom: 16, flexWrap: "wrap" }}>
          {[
            { id: "activities", label: `Activities (${m.activities.length})` },
            { id: "services",   label: `Services (${m.services.length})` },
            { id: "receivers",  label: `Receivers (${m.receivers.length})` },
            { id: "providers",  label: `Providers (${m.providers.length})` },
          ].map(s => (
            <button key={s.id} onClick={() => setSec(s.id)}
              style={{ padding: "6px 14px", borderRadius: 8, fontSize: "0.8rem", fontWeight: 500,
                cursor: "pointer", border: "1px solid",
                background: sec === s.id ? "var(--blue)" : "var(--bg-hover)",
                color: sec === s.id ? "#fff" : "var(--text-3)",
                borderColor: sec === s.id ? "var(--blue)" : "var(--border)" }}>
              {s.label}
            </button>
          ))}
        </div>
        <ComponentList components={
          sec === "activities" ? m.activities :
          sec === "services"   ? m.services   :
          sec === "receivers"  ? m.receivers  : m.providers
        } />
      </div>

      {/* Permissions */}
      <div className="a-card" style={{ padding: "20px 24px" }}>
        <SLabel count={m.uses_permissions.length}>Permissions</SLabel>
        {m.permissions.filter(p => p.is_sensitive).length > 0 && (
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: "0.72rem", fontWeight: 700, letterSpacing: "0.06em",
              textTransform: "uppercase", color: "#f87171", marginBottom: 8 }}>Sensitive</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              {m.permissions.filter(p => p.is_sensitive).map(p => (
                <div key={p.name} style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 12px",
                  borderRadius: 9, background: "rgba(244,63,94,0.05)", border: "1px solid rgba(244,63,94,0.15)", fontSize: "0.8rem" }}>
                  <AlertTriangle size={13} color="#f87171" />
                  <code style={{ flex: 1, fontFamily: "monospace", color: "var(--text)" }}>{p.name}</code>
                  <span className={`badge badge-${p.group}`}>{p.group}</span>
                </div>
              ))}
            </div>
          </div>
        )}
        {m.permissions.filter(p => !p.is_sensitive).length > 0 && (
          <div>
            <div style={{ fontSize: "0.72rem", fontWeight: 700, letterSpacing: "0.06em",
              textTransform: "uppercase", color: "var(--text-3)", marginBottom: 8 }}>Other</div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 4 }}>
              {m.permissions.filter(p => !p.is_sensitive).slice(0, 30).map(p => (
                <div key={p.name} style={{ display: "flex", alignItems: "center", gap: 6,
                  fontSize: "0.78rem", color: "var(--text-3)", padding: "3px 0" }}>
                  <ChevronRight size={10} />
                  <code style={{ fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {p.name}
                  </code>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function ComponentList({ components }: { components: AndroidComponent[] }) {
  if (!components.length)
    return <div style={{ color: "var(--text-3)", fontSize: "0.875rem" }}>None declared</div>;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 5, maxHeight: 280, overflowY: "auto" }}>
      {components.map((c, i) => (
        <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 12px",
          borderRadius: 9, background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)", fontSize: "0.8rem" }}>
          <code style={{ flex: 1, fontFamily: "monospace", color: "var(--text)",
            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {c.name}
          </code>
          {c.exported !== null && (
            <span className={`badge ${c.exported ? "badge-medium" : "badge-unknown"}`}>
              {c.exported ? "exported" : "private"}
            </span>
          )}
        </div>
      ))}
    </div>
  );
}

// ─── Dependencies Tab ──────────────────────────────────────────────────────────

function DepsTab({ deps }: { deps: Dependency[] }) {
  const [q, setQ] = useState("");
  const filtered = deps.filter(d => d.name.toLowerCase().includes(q.toLowerCase()));
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{ position: "relative", flex: 1 }}>
          <Search size={14} color="var(--text-3)" style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)" }} />
          <input className="search-input" style={{ paddingLeft: 36 }}
            placeholder="Search dependencies…" value={q} onChange={e => setQ(e.target.value)} />
        </div>
        <span style={{ color: "var(--text-3)", fontSize: "0.8rem", whiteSpace: "nowrap" }}>{filtered.length} found</span>
      </div>
      <div className="a-card" style={{ overflow: "hidden" }}>
        <table className="data-table">
          <thead><tr><th>Library</th><th>Evidence</th><th>Package</th><th>Confidence</th></tr></thead>
          <tbody>
            {filtered.map((d, i) => (
              <tr key={i}>
                <td style={{ color: "var(--text)", fontWeight: 500 }}>{d.name}</td>
                <td>{d.evidence_type}</td>
                <td><code style={{ fontFamily: "monospace", fontSize: "0.78rem" }}>{d.package_prefix}</code></td>
                <td><ConfBadge c={d.confidence} /></td>
              </tr>
            ))}
            {!filtered.length && (
              <tr><td colSpan={4} style={{ textAlign: "center", padding: "32px 0", color: "var(--text-3)" }}>No results</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Native Libs Tab ───────────────────────────────────────────────────────────

function NativeTab({ libs, archs }: { libs: NativeLibrary[]; archs: string[] }) {
  const [abi, setAbi] = useState("all");
  const filtered = abi === "all" ? libs : libs.filter(l => l.abi === abi);
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
        {["all", ...archs].map(a => (
          <button key={a} onClick={() => setAbi(a)}
            style={{ padding: "6px 14px", borderRadius: 8, fontSize: "0.8rem", fontWeight: 500,
              cursor: "pointer", border: "1px solid",
              background: abi === a ? "var(--blue)" : "var(--bg-card)",
              color: abi === a ? "#fff" : "var(--text-3)", borderColor: abi === a ? "var(--blue)" : "var(--border)" }}>
            {a}
          </button>
        ))}
        <span style={{ marginLeft: "auto", color: "var(--text-3)", fontSize: "0.78rem" }}>
          {filtered.length} libraries
        </span>
      </div>
      <div className="a-card" style={{ overflow: "hidden" }}>
        <table className="data-table">
          <thead><tr><th>Library</th><th>ABI</th><th>Size</th><th>Purpose</th><th>Framework</th></tr></thead>
          <tbody>
            {filtered.map((lib, i) => (
              <tr key={i}>
                <td><code style={{ fontFamily: "monospace", fontSize: "0.78rem", color: "var(--text)" }}>{lib.name}</code></td>
                <td><span className="badge badge-info">{lib.abi}</span></td>
                <td style={{ color: "var(--text-3)" }}>{formatBytes(lib.size_bytes)}</td>
                <td>{lib.detected_purpose || <span style={{ color: "var(--text-3)" }}>—</span>}</td>
                <td>{lib.framework_hint
                  ? <span className="badge badge-medium">{lib.framework_hint}</span>
                  : <span style={{ color: "var(--text-3)" }}>—</span>}
                </td>
              </tr>
            ))}
            {!filtered.length && (
              <tr><td colSpan={5} style={{ textAlign: "center", padding: "32px 0", color: "var(--text-3)" }}>No libraries</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Security Tab ──────────────────────────────────────────────────────────────

function SecurityTab({ findings }: { findings: SecurityFinding[] }) {
  if (!findings.length)
    return <EmptyState Icon={Shield} title="No security indicators" sub="Nothing notable was detected." />;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      <div className="info-banner">
        <Info size={14} style={{ flexShrink: 0, marginTop: 1 }} />
        All findings are indicators only and require manual verification before acting.
      </div>
      {findings.map((f, i) => <SecCard key={i} f={f} />)}
    </div>
  );
}

function SecCard({ f }: { f: SecurityFinding }) {
  const [open, setOpen] = useState(f.severity === "high");
  const SevIcon = f.severity === "high"   ? AlertCircle
                : f.severity === "medium" ? AlertTriangle
                : f.severity === "low"    ? Info
                : Info;
  const sevColor = f.severity === "high" ? "#f87171" : f.severity === "medium" ? "#fbbf24" : "#60a5fa";

  return (
    <div className="a-card" style={{ overflow: "hidden" }}>
      <button style={{ width: "100%", display: "flex", alignItems: "center", gap: 10,
        padding: "14px 18px", border: "none", background: "transparent", cursor: "pointer", textAlign: "left" }}
        onClick={() => setOpen(!open)}>
        <SevIcon size={16} color={sevColor} style={{ flexShrink: 0 }} />
        <span style={{ flex: 1, fontWeight: 500, fontSize: "0.875rem", color: "var(--text)" }}>{f.title}</span>
        <span className={`badge badge-${f.severity}`}>{f.severity}</span>
        {open
          ? <ChevronDown size={14} color="var(--text-3)" />
          : <ChevronRight size={14} color="var(--text-3)" />
        }
      </button>
      {open && (
        <div style={{ padding: "0 18px 16px", display: "flex", flexDirection: "column", gap: 10 }}>
          <p style={{ fontSize: "0.875rem", color: "var(--text-2)" }}>{f.description}</p>
          {f.recommendation && (
            <div style={{ padding: "10px 14px", borderRadius: 9, background: "rgba(255,255,255,0.02)",
              border: "1px solid var(--border)", fontSize: "0.8rem", color: "var(--text-2)" }}>
              <strong style={{ color: "var(--text-3)" }}>Recommendation: </strong>{f.recommendation}
            </div>
          )}
          {f.source && (
            <code style={{ fontSize: "0.75rem", fontFamily: "monospace", color: "var(--text-3)" }}>
              Source: {f.source}
            </code>
          )}
        </div>
      )}
    </div>
  );
}

// ─── URLs Tab ──────────────────────────────────────────────────────────────────

function URLsTab({ urls }: { urls: DetectedURL[] }) {
  const [cat, setCat] = useState("all");
  const cats = ["all", ...Array.from(new Set(urls.map(u => u.category)))];
  const filtered = cat === "all" ? urls : urls.filter(u => u.category === cat);

  if (!urls.length)
    return <EmptyState Icon={Globe} title="No URLs detected" sub="No HTTP/HTTPS URLs found in APK assets." />;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
        {cats.map(c => (
          <button key={c} onClick={() => setCat(c)}
            style={{ padding: "6px 14px", borderRadius: 8, fontSize: "0.8rem", fontWeight: 500,
              cursor: "pointer", border: "1px solid",
              background: cat === c ? "var(--blue)" : "var(--bg-card)",
              color: cat === c ? "#fff" : "var(--text-3)", borderColor: cat === c ? "var(--blue)" : "var(--border)" }}>
            {c}
          </button>
        ))}
      </div>
      <div className="a-card" style={{ overflow: "hidden" }}>
        <table className="data-table">
          <thead><tr><th>URL</th><th>Category</th><th>Source</th></tr></thead>
          <tbody>
            {filtered.map((u, i) => (
              <tr key={i}>
                <td><code style={{ fontFamily: "monospace", fontSize: "0.78rem", color: "var(--text)", wordBreak: "break-all" }}>
                  {u.url.length > 80 ? u.url.slice(0, 80) + "…" : u.url}
                </code></td>
                <td><span className="badge badge-info">{u.category}</span></td>
                <td style={{ fontFamily: "monospace", fontSize: "0.75rem", color: "var(--text-3)" }}>{u.source_file}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── File Tree Tab ─────────────────────────────────────────────────────────────

function TreeTab({ tree }: { tree: FileTreeNode | null }) {
  const [q, setQ] = useState("");
  if (!tree) return <EmptyState Icon={FolderTree} title="File tree not available" sub="" />;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      <div style={{ position: "relative" }}>
        <Search size={14} color="var(--text-3)"
          style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)" }} />
        <input className="search-input" style={{ paddingLeft: 36 }}
          placeholder="Search files…" value={q} onChange={e => setQ(e.target.value)} />
      </div>
      <div className="a-card" style={{ padding: 16, overflow: "auto", maxHeight: 640 }}>
        <TreeNode node={tree} depth={0} q={q} />
      </div>
    </div>
  );
}

function TreeNode({ node, depth, q }: { node: FileTreeNode; depth: number; q: string }) {
  const [open, setOpen] = useState(depth < 2);
  if (q && !node.name.toLowerCase().includes(q.toLowerCase()) && !node.is_dir) return null;
  return (
    <div style={{ paddingLeft: depth * 16 }}>
      <div className="tree-node" onClick={() => node.is_dir && setOpen(!open)}
        style={{ cursor: node.is_dir ? "pointer" : "default" }}>
        {node.is_dir
          ? open
            ? <ChevronDown size={12} color="var(--text-3)" style={{ flexShrink: 0 }} />
            : <ChevronRight size={12} color="var(--text-3)" style={{ flexShrink: 0 }} />
          : <span style={{ width: 12, flexShrink: 0 }} />
        }
        <span style={{ color: node.is_dir ? "#60a5fa" : "var(--text-2)" }}>{node.name}</span>
        {!node.is_dir && node.size_bytes > 0 && (
          <span style={{ marginLeft: "auto", color: "var(--text-3)", fontSize: "0.7rem" }}>
            {formatBytes(node.size_bytes)}
          </span>
        )}
      </div>
      {node.is_dir && open && node.children.map((c, i) => (
        <TreeNode key={i} node={c} depth={depth + 1} q={q} />
      ))}
    </div>
  );
}

// ─── Shells ────────────────────────────────────────────────────────────────────

function EmptyState({ Icon, title, sub }: { Icon: any; title: string; sub: string }) {
  return (
    <div className="a-card" style={{ padding: "56px 24px", textAlign: "center" }}>
      <div style={{ width: 52, height: 52, borderRadius: 14, background: "var(--bg-hover)",
        display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 16px" }}>
        <Icon size={26} color="var(--text-3)" strokeWidth={1.5} />
      </div>
      <div style={{ fontWeight: 600, fontSize: "0.9375rem", color: "var(--text)", marginBottom: 6 }}>{title}</div>
      {sub && <div style={{ fontSize: "0.875rem", color: "var(--text-3)" }}>{sub}</div>}
    </div>
  );
}

function Shell() {
  return (
    <div className="page-shell">
      <Navbar />
      <main className="page-main">
        <div className="content-wrap-wide" style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <div className="skeleton" style={{ height: 28, width: 280 }} />
          <div className="skeleton" style={{ height: 16, width: 180 }} />
          <div className="skeleton" style={{ height: 160, width: "100%", borderRadius: 14 }} />
        </div>
      </main>
    </div>
  );
}

function NotFound({ onBack }: { onBack: () => void }) {
  return (
    <div className="page-shell" style={{ alignItems: "center", justifyContent: "center" }}>
      <div style={{ textAlign: "center" }}>
        <div style={{ width: 64, height: 64, borderRadius: 18, background: "var(--bg-card)",
          display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 20px",
          border: "1px solid var(--border)" }}>
          <Inbox size={30} color="var(--text-3)" strokeWidth={1.5} />
        </div>
        <div style={{ fontWeight: 700, fontSize: "1.125rem", color: "var(--text)", marginBottom: 8 }}>
          Analysis not found
        </div>
        <button className="btn btn-primary" onClick={onBack} style={{ marginTop: 8 }}>
          <ChevronRight size={15} style={{ transform: "rotate(180deg)" }} />
          Back to Dashboard
        </button>
      </div>
    </div>
  );
}
