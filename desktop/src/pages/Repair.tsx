import { useState } from "react";
import type { Nav } from "../App";
import { api, when } from "../api";
import { ApprovalDialog, Card, Empty, ErrorNote, usePoll, type ApprovalLine } from "../components";
import { Icon } from "../icons";

export default function Repair({ nav }: { nav: Nav }) {
  const { data: plan, error } = usePoll(() => api.repairPlan(nav.scanId), 0, [nav.scanId]);
  const { data: rec, reload } = usePoll(() => api.recovery(), 0);
  const [dialog, setDialog] = useState<ApprovalLine[] | null>(null);
  const steps = plan?.steps ?? [];
  const auto = steps.filter((s: any) => !s.manual);
  const manual = steps.filter((s: any) => s.manual);

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>System Repair</h1>
          <p className="muted">
            Repair steps for this platform. Each executable step is approved on its own, and the approval is bound to the exact command.
            Steps marked <b>admin</b> need SENTRY running elevated. SENTRY creates a recovery record before significant changes, and a
            Windows restore point when it can.
          </p>
        </div>
        <span className={`status-pill ${plan?.elevated ? "ok" : ""}`}>{plan?.elevated ? "Elevated" : "Not elevated"}</span>
      </header>
      <ErrorNote error={error} />
      <Card title="Automated repairs">
        {!auto.length ? (
          <Empty title="No automated repairs for this platform" />
        ) : (
          <ul className="step-list">
            {auto.map((s: any) => (
              <li key={s.id}>
                <div>
                  <b>{s.title}</b>
                  <div className="small muted">{s.description}</div>
                  <div className="mono small">{s.command}</div>
                  <div className="tags">
                    {s.requires_admin && <span className="tag">admin</span>}
                    {s.reboot_required && <span className="tag">reboot</span>}
                    <span className="tag">risk: {s.risk}</span>
                  </div>
                </div>
                <button
                  className="btn primary small"
                  disabled={s.requires_admin && !plan?.elevated}
                  title={s.requires_admin && !plan?.elevated ? "Start SENTRY from an administrator terminal to run this step" : ""}
                  onClick={() =>
                    setDialog([{ subject_type: "repair_step", subject_id: s.id, action: "repair", label: s.title, detail: s.command }])
                  }
                >
                  <Icon name="wrench" /> Approve &amp; run
                </button>
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Card title="Manual recovery guidance">
        <ul className="step-list">
          {manual.map((s: any) => (
            <li key={s.id}>
              <div>
                <b>{s.title}</b>
                {s.description && <div className="small muted">{s.description}</div>}
                <div className="small">{s.guidance}</div>
              </div>
              <span className="tag">risk: {s.risk}</span>
            </li>
          ))}
        </ul>
      </Card>
      <Card title="Recovery records (rollback)">
        {!rec?.length ? (
          <Empty title="No recovery records">Removing a startup entry creates one, so the change can be undone.</Empty>
        ) : (
          <table className="table">
            <tbody>
              {rec.map((r: any) => (
                <tr key={r.id}>
                  <td className="mono">{r.id}</td>
                  <td>{r.kind}</td>
                  <td className="small">{r.data?.entry?.name ?? r.data?.path ?? ""}</td>
                  <td>{when(r.created_at)}</td>
                  <td>
                    <span className={`status status-${r.status}`}>{r.status}</span>
                  </td>
                  <td>
                    {r.status === "active" && (
                      <button
                        className="btn ghost small"
                        onClick={() =>
                          setDialog([{ subject_type: "recovery_record", subject_id: r.id, action: "rollback", label: `Roll back ${r.kind}` }])
                        }
                      >
                        Roll back
                      </button>
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
