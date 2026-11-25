// Typed client for the local SENTRY engine API (127.0.0.1, bearer token per launch).

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Evidence {
  engine: string;
  rule: string;
  description: string;
  weight: number;
  verdict: string;
  source: string;
  attack: string[];
  provenance?: string;
  details?: Record<string, unknown>;
}

export interface Finding {
  id: string;
  scan_id: string;
  category: string;
  category_label: string;
  severity: Severity;
  confidence: number;
  confidence_label: string;
  title: string;
  target_type: string;
  target: string;
  path?: string | null;
  sha256?: string | null;
  evidence: Evidence[];
  attack: string[];
  attack_techniques: { id: string; name: string; tactic: string; url: string }[];
  explanation: string;
  potential_damage: string[];
  recommended_action: string;
  allowed_actions: string[];
  limitations: string[];
  detection_engines: string[];
  status: string;
  protected?: string | null;
  data: Record<string, any>;
  ai_notes?: { author: string; created_at: string; text: string }[];
}

export interface Progress {
  phase: string;
  files_seen: number;
  files_scanned: number;
  bytes_scanned: number;
  flagged: number;
  errors: number;
  active_workers: number;
  worker_limit: number;
  max_workers: number;
  cpu: number;
  ram: number;
  current: string;
  elapsed_s: number;
  files_per_s: number;
}

export interface ScanStatus {
  scan_id: string;
  kind: string;
  status: string;
  started_at: string;
  finished_at?: string;
  roots: string[];
  progress?: Progress | null;
  error?: string | null;
  summary?: Record<string, any>;
}

export interface ScanRow {
  scan_id: string;
  kind: string;
  status: string;
  started_at: string;
  finished_at?: string;
  roots: string[];
  files_scanned?: number;
  findings?: number;
  threats?: number;
  by_severity?: Record<string, number>;
}

export interface Metrics {
  files_scanned: number;
  drives_inspected: number;
  scan_progress: Progress | null;
  threats_detected: number;
  suspicious_activities: number;
  unverified: number;
  quarantined_files: number;
  vulnerabilities: number;
  active_workers: number;
  worker_limit: number;
  cpu_percent: number;
  ram_percent: number;
  last_scan: { id: string; kind: string; status: string; started_at: string } | null;
  alerts: { id: string; created_at: string; kind: string; severity: Severity; message: string }[];
  approver_configured: boolean;
}

export interface ApprovalItem {
  subject_type: "finding" | "quarantine_item" | "repair_step" | "recovery_record";
  subject_id: string;
  action: string;
  critical_ack?: boolean;
}

export interface ExecResult {
  approval_id: string;
  action?: string;
  status: string;
  code?: string;
  detail?: string;
  verification?: { verified: boolean; checks: { check: string; ok: boolean; detail: string }[] };
}

export interface Backend {
  url: string;
  token: string | null;
}

let backend: Backend | null = null;

export async function resolveBackend(): Promise<Backend> {
  const w = window as any;
  if (w.__TAURI_INTERNALS__) {
    const { invoke } = await import("@tauri-apps/api/core");
    backend = await invoke<Backend>("backend_info");
    return backend;
  }
  const m = location.hash.match(/token=([^&]+)/);
  if (m) {
    sessionStorage.setItem("sentry-token", decodeURIComponent(m[1]));
    history.replaceState(null, "", location.pathname + location.search);
  }
  const url = import.meta.env.DEV ? (import.meta.env.VITE_SENTRY_API as string) || "http://127.0.0.1:8765" : location.origin;
  backend = { url, token: sessionStorage.getItem("sentry-token") };
  return backend;
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  if (!backend) await resolveBackend();
  const res = await fetch(`${backend!.url}${path}`, {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(backend!.token ? { Authorization: `Bearer ${backend!.token}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) {
    let msg = text;
    try {
      msg = JSON.parse(text).detail ?? text;
    } catch {
      /* plain text */
    }
    throw new ApiError(res.status, typeof msg === "string" ? msg : JSON.stringify(msg));
  }
  const type = res.headers.get("content-type") || "";
  return (type.includes("json") ? JSON.parse(text) : text) as T;
}

export const api = {
  health: () => request<{ ok: boolean; version: string }>("GET", "/api/health"),
  status: () => request<any>("GET", "/api/status"),
  metrics: () => request<Metrics>("GET", "/api/metrics"),
  drives: () => request<any[]>("GET", "/api/drives"),
  scans: () => request<ScanRow[]>("GET", "/api/scans"),
  startScan: (body: { kind: string; paths?: string[]; online?: boolean; workers?: number; max_workers?: number }) =>
    request<{ scan_id: string; status: string }>("POST", "/api/scans", body),
  scan: (id: string) => request<ScanStatus>("GET", `/api/scans/${id}`),
  cancelScan: (id: string) => request<any>("POST", `/api/scans/${id}/cancel`),
  findings: (id: string) => request<{ findings: Finding[] }>("GET", `/api/scans/${id}/findings`),
  report: (id: string) => request<any>("GET", `/api/scans/${id}/report?format=json`),
  reportHtml: (id: string) => request<string>("GET", `/api/scans/${id}/report?format=html`),
  verify: (id: string) => request<any>("POST", `/api/scans/${id}/verify`),
  note: (fid: string, text: string) => request<any>("POST", `/api/findings/${fid}/notes`, { author: "user", text }),
  approvals: (scanId?: string) => request<any[]>("GET", `/api/approvals${scanId ? `?scan_id=${scanId}` : ""}`),
  approve: (items: ApprovalItem[], passphrase: string, execute = true) =>
    request<{ issued: any[]; executed?: ExecResult[]; verification?: Record<string, any> }>("POST", "/api/approvals", {
      items,
      passphrase,
      execute,
    }),
  remediate: (scanId?: string) => request<any>("POST", "/api/remediate", { scan_id: scanId }),
  quarantine: (all = false) => request<any[]>("GET", `/api/quarantine?all=${all}`),
  repairPlan: (scanId?: string) => request<{ steps: any[]; elevated: boolean }>("GET", `/api/repair/plan${scanId ? `?scan_id=${scanId}` : ""}`),
  recovery: () => request<any[]>("GET", "/api/recovery"),
  agents: (scanId?: string) => request<any>("GET", `/api/agents${scanId ? `?scan_id=${scanId}` : ""}`),
  alerts: () => request<any[]>("GET", "/api/alerts"),
  audit: (n = 100) => request<any[]>("GET", `/api/audit?n=${n}`),
  auditVerify: () => request<{ ok: boolean; records: number; reason?: string }>("GET", "/api/audit/verify"),
  settings: () => request<Record<string, any>>("GET", "/api/settings"),
  saveSettings: (s: Record<string, any>) => request<Record<string, any>>("PUT", "/api/settings", s),
};

export function bytes(n?: number): string {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i ? 1 : 0)} ${u[i]}`;
}

export function when(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString();
}
