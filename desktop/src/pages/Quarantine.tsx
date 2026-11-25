import { useState } from "react";
import { api, bytes, when } from "../api";
import { ApprovalDialog, Card, Empty, ErrorNote, usePoll, type ApprovalLine } from "../components";
import { Icon } from "../icons";

export default function Quarantine() {
  const [showAll, setShowAll] = useState(false);
  const { data, error, reload } = usePoll(() => api.quarantine(showAll), 0, [showAll]);
  const [dialog, setDialog] = useState<ApprovalLine[] | null>(null);

  const ask = (q: any, action: "restore" | "delete") =>
    setDialog([
      {
        subject_type: "quarantine_item",
        subject_id: q.id,
        action,
        label: `${action === "restore" ? "Restore" : "Permanently delete"} ${q.original_path.split(/[\\/]/).pop()}`,
        detail: q.original_path,
        irreversible: action === "delete",
      },
    ]);

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Quarantine</h1>
          <p className="muted">
            Quarantined files are encrypted with AES-256-GCM in a vault only your account can open, so they cannot run. SENTRY keeps the
            original path, hash and metadata. Restoring a file or permanently deleting it needs its own approval.
          </p>
        </div>
        <label className="check">
          <input type="checkbox" checked={showAll} onChange={(e) => setShowAll(e.target.checked)} /> Show restored/deleted
        </label>
      </header>
      <ErrorNote error={error} />
      <Card>
        {!data?.length ? (
          <Empty title="The vault is empty">Approved quarantine actions appear here.</Empty>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Item</th>
                <th>Original location</th>
                <th>Size</th>
                <th>Quarantined</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {data.map((q) => (
                <tr key={q.id}>
                  <td className="mono">{q.id}</td>
                  <td>
                    <div className="mono small ellipsis" title={q.original_path}>
                      {q.original_path}
                    </div>
                    <div className="mono small muted">{q.sha256.slice(0, 24)}…</div>
                    {q.protected && <div className="small danger-text">protected origin: {q.protected}</div>}
                  </td>
                  <td>{bytes(q.size)}</td>
                  <td>{when(q.quarantined_at)}</td>
                  <td>
                    <span className={`status status-${q.status}`}>{q.status}</span>
                  </td>
                  <td className="row-actions">
                    {q.status === "quarantined" && (
                      <>
                        <button className="btn ghost small" onClick={() => ask(q, "restore")}>
                          Restore
                        </button>
                        <button className="btn danger small" disabled={Boolean(q.protected)} onClick={() => ask(q, "delete")}>
                          <Icon name="x" /> Delete
                        </button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      {dialog && (
        <ApprovalDialog
          lines={dialog}
          onClose={() => {
            setDialog(null);
            reload();
          }}
          onDone={() => undefined}
        />
      )}
    </div>
  );
}
