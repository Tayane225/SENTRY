import { useState } from "react";
import type { Nav } from "../App";
import { api, when } from "../api";
import { Card, Empty, ErrorNote, usePoll } from "../components";
import { Icon } from "../icons";

export default function History({ nav }: { nav: Nav }) {
  const { data, error } = usePoll(() => api.scans(), 5000);
  const [err, setErr] = useState<unknown>(null);

  const openReport = async (id: string) => {
    try {
      const html = await api.reportHtml(id);
      const url = URL.createObjectURL(new Blob([html], { type: "text/html" }));
      window.open(url, "_blank", "noopener");
    } catch (e) {
      setErr(e);
    }
  };

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Scan History</h1>
          <p className="muted">Every scan, its scope and results. Reports are also saved on disk in SENTRY's reports folder.</p>
        </div>
      </header>
      <ErrorNote error={error || err} />
      <Card>
        {!data?.length ? (
          <Empty title="No scans yet" />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Scan</th>
                <th>Type</th>
                <th>Started</th>
                <th>Status</th>
                <th>Files</th>
                <th>Findings</th>
                <th>Scope</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {data.map((s) => (
                <tr key={s.scan_id}>
                  <td className="mono">{s.scan_id}</td>
                  <td>{s.kind}</td>
                  <td className="small">{when(s.started_at)}</td>
                  <td>
                    <span className={`status status-${s.status}`}>{s.status}</span>
                  </td>
                  <td>{(s.files_scanned ?? 0).toLocaleString()}</td>
                  <td>
                    {s.findings ?? 0}
                    {s.threats ? <span className="danger-text"> ({s.threats} threats)</span> : null}
                  </td>
                  <td className="mono small ellipsis" title={s.roots.join("\n")}>
                    {s.roots.join(", ")}
                  </td>
                  <td className="row-actions">
                    <button className="btn ghost small" onClick={() => nav.go("threats", s.scan_id)}>
                      Findings
                    </button>
                    <button className="btn ghost small" onClick={() => openReport(s.scan_id)}>
                      <Icon name="external" size={14} /> Report
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
