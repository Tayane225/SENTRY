import type { Nav } from "../App";
import { api, when } from "../api";
import { Card, ErrorNote, usePoll } from "../components";
import { Icon } from "../icons";

export default function Agents({ nav }: { nav: Nav }) {
  const { data, error } = usePoll(() => api.agents(nav.scanId), 4000, [nav.scanId]);
  const { data: settings } = usePoll(() => api.settings(), 0);
  const { data: m } = usePoll(() => api.metrics(), 2000);

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Agent Control Center</h1>
          <p className="muted">
            One master coordinator, ten specialised engine agents with restricted capabilities, and an adaptive pool of scan workers. No
            agent can modify your system: only the remediation executor can, and only with your signed approval.
          </p>
        </div>
      </header>
      <ErrorNote error={error} />
      <div className="metric-grid compact">
        <div className="metric">
          <div className="metric-label">Active workers</div>
          <div className="metric-value">
            {m?.active_workers ?? 0} / {m?.worker_limit ?? 0}
          </div>
        </div>
        <div className="metric">
          <div className="metric-label">Initial / max workers</div>
          <div className="metric-value">
            {settings?.initial_workers ?? "—"} / {settings?.max_workers ?? "—"}
          </div>
          <div className="metric-sub">change in Settings (up to 512)</div>
        </div>
        <div className="metric">
          <div className="metric-label">Adaptive scaling</div>
          <div className="metric-value">{settings?.adaptive_concurrency ? "on" : "off"}</div>
          <div className="metric-sub">CPU/RAM-aware</div>
        </div>
      </div>
      <Card title="Engine agents">
        <div className="agent-grid">
          {(data?.agents ?? []).map((a: any) => (
            <div key={a.name} className="agent-card">
              <div className="row">
                <Icon name="agents" />
                <b>{a.role}</b>
              </div>
              <p className="small muted">{a.responsibility}</p>
              <div className="tags">
                {a.capabilities.map((c: string) => (
                  <span key={c} className="tag">
                    {c}
                  </span>
                ))}
              </div>
              <div className="small ok-text">
                <Icon name="lock" size={14} /> cannot modify the system
              </div>
            </div>
          ))}
        </div>
        <p className="small muted">{data?.llm_layer}</p>
      </Card>
      <Card title="Execution history (audited)">
        <table className="table">
          <thead>
            <tr>
              <th>Agent</th>
              <th>Scan</th>
              <th>Started</th>
              <th>Status</th>
              <th>Tools used</th>
              <th>Denied</th>
            </tr>
          </thead>
          <tbody>
            {(data?.runs ?? []).map((r: any) => (
              <tr key={r.id}>
                <td>{r.agent}</td>
                <td className="mono small">{r.scan_id}</td>
                <td className="small">{when(r.started_at)}</td>
                <td>
                  <span className={`status status-${r.status}`}>{r.status}</span>
                  {r.summary?.duration_s !== undefined && <span className="small muted"> {r.summary.duration_s}s</span>}
                </td>
                <td className="small">{(r.tools_used ?? []).join(", ")}</td>
                <td className="small danger-text">{(r.denied ?? []).join(", ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}
