// API client for APK Stack Analyzer backend

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export interface AnalysisJob {
  analysis_id: string;
  status: "queued" | "running" | "completed" | "failed";
  filename: string;
  file_size?: number;
  created_at: string;
  updated_at: string;
  current_step?: string;
  progress_steps: { step: string; message: string; timestamp: string }[];
  error?: string;
  result?: AnalysisResult;
}

export interface Evidence {
  type: string;
  artifact: string;
  strength: "strong" | "medium" | "weak";
  description: string;
  location?: string;
}

export interface NegativeEvidence {
  artifact: string;
  description: string;
}

export interface FrameworkDetection {
  name: string;
  confidence: "high" | "medium" | "low" | "unknown";
  evidence: Evidence[];
  negative_evidence: NegativeEvidence[];
  sub_technologies: Record<string, string>;
}

export interface AndroidComponent {
  name: string;
  component_type: string;
  exported: boolean | null;
  intent_filters: string[];
  attributes: Record<string, string>;
}

export interface Permission {
  name: string;
  group: "normal" | "dangerous" | "special" | "custom";
  description: string;
  is_sensitive: boolean;
}

export interface ManifestAnalysis {
  package_name: string;
  version_name: string;
  version_code: string;
  min_sdk: number | null;
  target_sdk: number | null;
  compile_sdk: number | null;
  debuggable: boolean;
  allow_backup: boolean;
  network_security_config: boolean;
  uses_cleartext_traffic: boolean | null;
  application_label: string;
  application_icon: string;
  activities: AndroidComponent[];
  services: AndroidComponent[];
  receivers: AndroidComponent[];
  providers: AndroidComponent[];
  permissions: Permission[];
  uses_permissions: string[];
}

export interface NativeLibrary {
  name: string;
  abi: string;
  size_bytes: number;
  detected_purpose: string;
  framework_hint: string;
}

export interface Dependency {
  name: string;
  version: string;
  evidence_type: string;
  confidence: "high" | "medium" | "low" | "unknown";
  package_prefix: string;
}

export interface AssetEntry {
  path: string;
  size_bytes: number;
  category: string;
  description: string;
}

export interface DetectedURL {
  url: string;
  category: string;
  source_file: string;
}

export interface SecurityFinding {
  title: string;
  severity: "high" | "medium" | "low" | "info";
  description: string;
  recommendation: string;
  requires_manual_verification: boolean;
  source: string;
}

export interface FileTreeNode {
  name: string;
  path: string;
  is_dir: boolean;
  size_bytes: number;
  children: FileTreeNode[];
}

export interface DexAnalysis {
  dex_files: string[];
  total_classes: number;
  total_methods: number;
  packages: string[];
  framework_packages: string[];
}

export interface APKMetadata {
  filename: string;
  file_size_bytes: number;
  sha256: string;
  analysis_id: string;
  jadx_available: boolean;
  apktool_available: boolean;
}

export interface AnalysisResult {
  schema_version: string;
  metadata: APKMetadata;
  manifest: ManifestAnalysis;
  frameworks: FrameworkDetection[];
  primary_framework: FrameworkDetection | null;
  is_hybrid: boolean;
  architectures: string[];
  native_libraries: NativeLibrary[];
  dex_analysis: DexAnalysis;
  dependencies: Dependency[];
  assets: AssetEntry[];
  urls: DetectedURL[];
  security_findings: SecurityFinding[];
  file_tree: FileTreeNode | null;
  all_evidence: Evidence[];
  errors: string[];
  warnings: string[];
}

// ─── API functions ─────────────────────────────────────────────────────────

export async function uploadAndAnalyze(file: File): Promise<{ analysis_id: string; status: string }> {
  const formData = new FormData();
  formData.append("file", file);

  const res = await fetch(`${API_BASE}/api/analyze`, {
    method: "POST",
    body: formData,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Upload failed" }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }

  return res.json();
}

export async function getAnalysis(analysisId: string): Promise<AnalysisJob> {
  const res = await fetch(`${API_BASE}/api/analysis/${analysisId}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function getHealth(): Promise<{ status: string; jadx_available: boolean; apktool_available: boolean }> {
  const res = await fetch(`${API_BASE}/api/health`);
  if (!res.ok) throw new Error("Backend unreachable");
  return res.json();
}

export async function listAnalyses(): Promise<{ analysis_id: string; filename: string; status: string; created_at: string }[]> {
  const res = await fetch(`${API_BASE}/api/analyses`);
  if (!res.ok) return [];
  return res.json();
}

export function getExportUrl(analysisId: string, format: "json" | "markdown"): string {
  return `${API_BASE}/api/analysis/${analysisId}/export/${format}`;
}

// ─── Utilities ─────────────────────────────────────────────────────────────

export function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}

export function confidenceColor(confidence: string): string {
  switch (confidence) {
    case "high": return "text-emerald-400 bg-emerald-400/10 border-emerald-400/20";
    case "medium": return "text-amber-400 bg-amber-400/10 border-amber-400/20";
    case "low": return "text-rose-400 bg-rose-400/10 border-rose-400/20";
    default: return "text-slate-400 bg-slate-400/10 border-slate-400/20";
  }
}

export function severityColor(severity: string): string {
  switch (severity) {
    case "high": return "text-rose-400 bg-rose-400/10 border-rose-400/20";
    case "medium": return "text-amber-400 bg-amber-400/10 border-amber-400/20";
    case "low": return "text-sky-400 bg-sky-400/10 border-sky-400/20";
    default: return "text-slate-400 bg-slate-400/10 border-slate-400/20";
  }
}

export const ANALYSIS_STEP_LABELS: Record<string, string> = {
  validating: "Validating APK",
  sha256: "Calculating SHA-256",
  extracting: "Extracting APK",
  manifest: "Analyzing manifest",
  dex: "Analyzing DEX files",
  native_libraries: "Scanning native libraries",
  assets: "Scanning assets",
  fingerprinting: "Fingerprinting frameworks",
  dependencies: "Detecting dependencies",
  security: "Running security checks",
  report: "Building report",
  done: "Analysis complete",
};

export const ORDERED_STEPS = [
  "validating",
  "sha256",
  "extracting",
  "manifest",
  "dex",
  "native_libraries",
  "assets",
  "fingerprinting",
  "dependencies",
  "security",
  "report",
  "done",
];
