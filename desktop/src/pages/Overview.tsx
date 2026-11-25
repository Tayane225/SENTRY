import type { Nav } from "../App";
import { api, when } from "../api";
import { Bar, Card, Empty, ErrorNote, Metric, SeverityBadge, usePoll } from "../components";
import { Icon } from "../icons";

const ENGINE_LABELS: Record<string, string> = {
  yara: "YARA",
  clamav: "ClamAV",
  defender: "Microsoft Defender",
  hash_intel: "Hash intelligence",
  osv_scanner: "OSV-Scanner",
  trivy: "Trivy",
  online_intel: "Online intelligence",
};

export default function Overview({ nav }: { nav: Nav }) {
  const { data: m, error } = usePoll(() => api.metrics(), 2000);
  const { data: status } = usePoll(() => api.status(), 0);
  const p = m?.scan_progress;
  const open = (m?.threats_detected ?? 0) + (m?.suspicious_activities ?? 0);
  const state = !m ? "…" : open > 0 ? "Threats need your review" : m.last_scan ? "No open threats" : "Not scanned yet";

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Overview</h1>
          <p className="muted">Real-time view of SENTRY's protection status and scan activity.</p>
        </div>
        <div className={`status-pill ${open > 0 ? "danger" : m?.last_scan ? "ok" : ""}`}>
          <Icon name={open > 0 ? "alert" : "shield"} /> {state}
        </div>
      </header>
      <ErrorNote error={error} />
      {m && !m.approver_configured && (
        <div className="note warn">
          <Icon name="lock" /> No approver is configured, so nothing can be quarantined or repaired yet. Open a terminal and run{" "}
          <code>sentry init</code> to choose your approver passphrase.
        </div>
      )}

      <div className="metric-grid">
        <Metric label="Files scanned" value={(m?.files_scanned ?? 0).toLocaleString()} sub={m?.last_scan ? `last scan ${m.last_scan.kind}` : "no scan yet"} />
        <Metric label="Drives inspected" value={m?.drives_inspected ?? 0} />
        <Metric label="Threats detected" value={m?.threats_detected ?? 0} tone={(m?.threats_detected ?? 0) > 0 ? "danger" : "ok"} sub="open, awaiting decision" />
        <Metric label="Suspicious activities" value={m?.suspicious_activities ?? 0} tone={(m?.suspicious_activities ?? 0) > 0 ? "warn" : undefined} />
        <Metric label="Quarantined files" value={m?.quarantined_files ?? 0} />
        <Metric label="Vulnerabilities" value={m?.vulnerabilities ?? 0} tone={(m?.vulnerabilities ?? 0) > 0 ? "warn" : undefined} sub="incl. configuration weaknesses" />
        <Metric label="Active workers" value={`${m?.active_workers ?? 0} / ${m?.worker_limit ?? 0}`} sub="adaptive pool" />
        <Metric label="CPU" value={`${Math.round(m?.cpu_percent ?? 0)}%`} sub={<Bar value={m?.cpu_percent ?? 0} />} />
        <Metric label="RAM" value={`${Math.round(m?.ram_percent ?? 0)}%`} sub={<Bar value={m?.ram_percent ?? 0} />} />
        <Metric
          label="Scan progress"
          value={p ? p.phase : m?.last_scan?.status ?? "idle"}
          sub={p ? `${p.files_scanned.toLocaleString()} files · ${p.files_per_s}/s` : m?.last_scan ? when(m.last_scan.started_at) : "—"}
        />
      </div>

      <div className="grid-2">
        <Card title="Start a scan">
          <div className="quick-actions">
            <button className="action-tile" onClick={() => nav.go("quick")}>
              <Icon name="bolt" size={22} />
              <b>Quick scan</b>
              <span className="muted small">High-risk locations, startup, processes, configuration · minutes</span>
            </button>
            <button className="action-tile" onClick={() => nav.go("full")}>
              <Icon name="disk" size={22} />
              <b>Full scan</b>
              <span className="muted small">Every authorised local drive · can take hours</span>
            </button>
            <button className="action-tile" onClick={() => nav.go("custom")}>
              <Icon name="folder" size={22} />
              <b>Custom scan</b>
              <span className="muted small">A folder, USB drive or project</span>
            </button>
          </div>
        </Card>
        <Card title="Detection engines">
          {status ? (
            <ul className="engine-list">
              {Object.entries(status.engines as Record<string, any>).map(([k, v]) => {
                const ok = v.available ?? v.enabled;
                return (
                  <li key={k}>
                    <span className={`dot ${ok ? "ok" : "off"}`} />
                    <span className="engine-name">{ENGINE_LABELS[k] ?? k}</span>
                    <span className="muted small">{ok ? v.backend ?? v.version ?? "available" : "not available"}</span>
                  </li>
                );
              })}
            </ul>
          ) : (
            <p className="muted">Loading…</p>
          )}
          {status?.advice?.length > 0 && (
            <ul className="advice">
              {status.advice.map((a: string) => (
                <li key={a} className="small muted">
                  {a}
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <Card title="Recent alerts" actions={open > 0 && <button className="btn primary" onClick={() => nav.go("threats")}>Review threats</button>}>
        {m?.alerts?.length ? (
          <ul className="alert-list">
            {m.alerts.map((a) => (
              <li key={a.id}>
                <SeverityBadge severity={a.severity} />
                <span>{a.message}</span>
                <span className="muted small">{when(a.created_at)}</span>
              </li>
            ))}
          </ul>
        ) : (
          <Empty title="No alerts">Continuous monitoring (`sentry monitor`) reports new threats here. It never removes anything on its own.</Empty>
        )}
      </Card>
    </div>
  );
}
