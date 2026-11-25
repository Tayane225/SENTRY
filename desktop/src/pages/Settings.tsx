import { useEffect, useState } from "react";
import { api, when } from "../api";
import { Card, ErrorNote, usePoll } from "../components";

const NUMBER_FIELDS: [string, string][] = [
  ["initial_workers", "Initial workers"],
  ["max_workers", "Maximum workers (≤ 512)"],
  ["min_workers", "Minimum workers"],
  ["max_content_scan_size", "Content-scan size limit (bytes)"],
  ["max_hash_size", "Hashing size limit (bytes)"],
  ["max_clamav_size", "ClamAV size limit (bytes)"],
  ["monitor_interval_seconds", "Monitoring interval (s)"],
];
const BOOL_FIELDS: [string, string][] = [
  ["adaptive_concurrency", "Adaptive concurrency (scale with CPU/RAM)"],
  ["use_yara", "Use YARA"],
  ["use_clamav", "Use ClamAV"],
  ["use_defender", "Use Microsoft Defender corroboration (Windows)"],
  ["online_intel", "Online threat intelligence (hash lookups only)"],
  ["osv_online", "OSV dependency lookups"],
  ["include_removable_drives", "Include removable drives in full scans"],
  ["include_network_drives", "Include network drives in full scans"],
  ["store_full_inventory", "Store a full file inventory (larger database)"],
];

export default function Settings() {
  const { data: status } = usePoll(() => api.status(), 0);
  const [s, setS] = useState<Record<string, any> | null>(null);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [audit, setAudit] = useState<{ ok: boolean; records: number; reason?: string } | null>(null);
  const { data: events } = usePoll(() => api.audit(30), 0);

  useEffect(() => {
    api.settings().then(setS).catch(setError);
  }, []);

  const save = async () => {
    if (!s) return;
    const editable = [...NUMBER_FIELDS.map((f) => f[0]), ...BOOL_FIELDS.map((f) => f[0]), "exclude_globs", "clamd_address"];
    const body: Record<string, any> = {};
    editable.forEach((k) => (body[k] = s[k]));
    try {
      setS(await api.saveSettings(body));
      setSaved(true);
      setError(null);
      window.setTimeout(() => setSaved(false), 1500);
    } catch (e) {
      setError(e);
    }
  };

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Settings</h1>
          <p className="muted">
            Scanning and engine settings. Security-critical settings (approver key, approval lifetime, lockout) can only be changed from a
            terminal with <code>sentry init</code>.
          </p>
        </div>
        <button className="btn primary" onClick={save} disabled={!s}>
          {saved ? "Saved" : "Save settings"}
        </button>
      </header>
      <ErrorNote error={error} />
      <div className="grid-2">
        <Card title="Scanning">
          {s &&
            NUMBER_FIELDS.map(([k, label]) => (
              <label key={k} className="field">
                <span>{label}</span>
                <input inputMode="numeric" value={s[k] ?? ""} onChange={(e) => setS({ ...s, [k]: Number(e.target.value.replace(/\D/g, "")) })} />
              </label>
            ))}
          {s && (
            <label className="field">
              <span>Exclusions (glob patterns, one per line). They are shown in every scan report.</span>
              <textarea rows={4} value={(s.exclude_globs ?? []).join("\n")} onChange={(e) => setS({ ...s, exclude_globs: e.target.value.split(/\r?\n/).filter(Boolean) })} spellCheck={false} />
            </label>
          )}
          {s && (
            <label className="field">
              <span>clamd address (empty = auto-detect, e.g. tcp://127.0.0.1:3310)</span>
              <input value={s.clamd_address ?? ""} onChange={(e) => setS({ ...s, clamd_address: e.target.value || null })} />
            </label>
          )}
        </Card>
        <Card title="Engines & privacy">
          {s &&
            BOOL_FIELDS.map(([k, label]) => (
              <label key={k} className="check">
                <input type="checkbox" checked={Boolean(s[k])} onChange={(e) => setS({ ...s, [k]: e.target.checked })} />
                <span>{label}</span>
              </label>
            ))}
          <p className="small muted">
            API keys for VirusTotal and abuse.ch are read from the SENTRY_VT_API_KEY and SENTRY_ABUSECH_KEY environment variables. They are
            never shown here.
          </p>
        </Card>
      </div>
      <div className="grid-2">
        <Card title="Security">
          <dl className="kv">
            <dt>Approver</dt>
            <dd>{status?.approver_configured ? `configured · ${status.approver_fingerprint}` : "not configured — run `sentry init`"}</dd>
            <dt>Fingerprint pinned</dt>
            <dd>{status?.approver_pinned ? "yes" : "no"}</dd>
            <dt>Data directory</dt>
            <dd className="mono small">{status?.home}</dd>
            <dt>Elevated</dt>
            <dd>{status?.admin ? "yes" : "no"}</dd>
          </dl>
          <button className="btn ghost" onClick={() => api.auditVerify().then(setAudit).catch(setError)}>
            Verify audit log integrity
          </button>
          {audit && (
            <div className={`note ${audit.ok ? "ok" : "danger"}`}>
              {audit.ok ? `Audit chain intact (${audit.records} records).` : `Audit chain broken: ${audit.reason}`}
            </div>
          )}
        </Card>
        <Card title="Recent audit events">
          <ul className="audit-list">
            {(events ?? [])
              .slice()
              .reverse()
              .map((e: any) => (
                <li key={e.seq}>
                  <span className="mono small">#{e.seq}</span>
                  <span>{e.event}</span>
                  <span className="muted small">{e.actor}</span>
                  <span className="muted small">{when(e.ts)}</span>
                </li>
              ))}
          </ul>
        </Card>
      </div>
    </div>
  );
}
