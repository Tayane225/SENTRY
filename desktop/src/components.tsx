import { useEffect, useRef, useState, type ReactNode } from "react";
import { api, type ApprovalItem, type ExecResult, type Severity } from "./api";
import { Icon } from "./icons";

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  return <span className={`sev sev-${severity}`}>{severity}</span>;
}

export function Metric({ label, value, sub, tone }: { label: string; value: ReactNode; sub?: ReactNode; tone?: "danger" | "warn" | "ok" }) {
  return (
    <div className={`metric ${tone ?? ""}`}>
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
      {sub !== undefined && <div className="metric-sub">{sub}</div>}
    </div>
  );
}

export function Bar({ value, max = 100, tone }: { value: number; max?: number; tone?: string }) {
  const pct = Math.max(0, Math.min(100, (value / (max || 1)) * 100));
  return (
    <div className="bar" role="progressbar" aria-valuenow={Math.round(pct)} aria-valuemin={0} aria-valuemax={100}>
      <div className={`bar-fill ${tone ?? ""}`} style={{ width: `${pct}%` }} />
    </div>
  );
}

export function Card({ title, actions, children, className }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`card ${className ?? ""}`}>
      {(title || actions) && (
        <header className="card-head">
          <h3>{title}</h3>
          <div className="card-actions">{actions}</div>
        </header>
      )}
      {children}
    </section>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <Icon name="shield" size={28} />
      <div className="empty-title">{title}</div>
      {children && <div className="empty-body">{children}</div>}
    </div>
  );
}

export function ErrorNote({ error }: { error: unknown }) {
  if (!error) return null;
  return (
    <div className="note danger">
      <Icon name="alert" /> {error instanceof Error ? error.message : String(error)}
    </div>
  );
}

export function usePoll<T>(fn: () => Promise<T>, ms: number, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const fnRef = useRef(fn);
  fnRef.current = fn;
  useEffect(() => {
    let alive = true;
    let timer: number | undefined;
    const tick = async () => {
      try {
        const d = await fnRef.current();
        if (alive) {
          setData(d);
          setError(null);
        }
      } catch (e) {
        if (alive) setError(e);
      }
      if (alive && ms > 0) timer = window.setTimeout(tick, ms);
    };
    tick();
    return () => {
      alive = false;
      if (timer) window.clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return { data, error, reload: () => fnRef.current().then(setData).catch(setError) };
}

export interface ApprovalLine extends ApprovalItem {
  label: string;
  detail?: string;
  protectedName?: string | null; // file name the user must type for protected targets
  irreversible?: boolean;
}

/** Human approval: the user reviews the exact actions and types their approver passphrase.
 *  The passphrase goes straight to the local engine, which signs single-use approvals. */
export function ApprovalDialog({ lines, onClose, onDone }: { lines: ApprovalLine[]; onClose: () => void; onDone: () => void }) {
  const [pass, setPass] = useState("");
  const [typed, setTyped] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [results, setResults] = useState<ExecResult[] | null>(null);
  const needsName = lines.filter((l) => l.protectedName);
  const ready = pass.length >= 10 && needsName.every((l) => typed[l.subject_id] === l.protectedName);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const items: ApprovalItem[] = lines.map(({ subject_type, subject_id, action, protectedName }) => ({
        subject_type,
        subject_id,
        action,
        critical_ack: Boolean(protectedName),
      }));
      const res = await api.approve(items, pass, true);
      setPass("");
      setResults(res.executed ?? []);
      onDone();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-label="Approve actions">
      <div className="modal">
        <header className="modal-head">
          <Icon name="lock" />
          <h2>{results ? "Results" : "Review and approve"}</h2>
          <button className="icon-btn" onClick={onClose} aria-label="Close">
            <Icon name="x" />
          </button>
        </header>
        {!results ? (
          <>
            <p className="muted">
              These actions run only after you sign them with your approver passphrase. Each approval is single-use, expires in 30
              minutes and is bound to the file's exact path and SHA-256. A file that changes in the meantime is refused.
            </p>
            <ul className="approve-list">
              {lines.map((l) => (
                <li key={l.subject_id + l.action}>
                  <span className={`action-chip ${l.irreversible ? "danger" : ""}`}>{l.action.replace("_", " ")}</span>
                  <div>
                    <div className="approve-label">{l.label}</div>
                    {l.detail && <div className="mono small muted">{l.detail}</div>}
                    {l.irreversible && <div className="small danger-text">Permanent: this cannot be undone.</div>}
                    {l.protectedName && (
                      <label className="field small">
                        <span className="danger-text">Protected system/security file. Type “{l.protectedName}” to confirm.</span>
                        <input
                          value={typed[l.subject_id] ?? ""}
                          onChange={(e) => setTyped({ ...typed, [l.subject_id]: e.target.value })}
                          spellCheck={false}
                        />
                      </label>
                    )}
                  </div>
                </li>
              ))}
            </ul>
            <label className="field">
              <span>Approver passphrase</span>
              <input
                type="password"
                autoFocus
                value={pass}
                onChange={(e) => setPass(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && ready && !busy && submit()}
                autoComplete="off"
              />
            </label>
            <p className="small muted">Never type this passphrase into an AI chat. AI agents cannot approve on your behalf.</p>
            <ErrorNote error={error} />
            <footer className="modal-foot">
              <button className="btn ghost" onClick={onClose}>
                Cancel
              </button>
              <button className="btn primary" disabled={!ready || busy} onClick={submit}>
                {busy ? "Signing and executing…" : `Approve ${lines.length} action${lines.length > 1 ? "s" : ""}`}
              </button>
            </footer>
          </>
        ) : (
          <>
            <ul className="result-list">
              {results.map((r) => (
                <li key={r.approval_id} className={r.status === "succeeded" ? "ok" : r.status === "needs_elevation" ? "warn" : "bad"}>
                  <div className="result-head">
                    <Icon name={r.status === "succeeded" ? "check" : "alert"} />
                    <b>{r.action}</b> — {r.status}
                    {r.code ? ` (${r.code})` : ""}
                  </div>
                  <div className="small">{r.detail}</div>
                  {r.verification?.checks?.map((c) => (
                    <div key={c.check} className={`small ${c.ok ? "ok-text" : "danger-text"}`}>
                      {c.ok ? "✔" : "✘"} {c.check}: {c.detail}
                    </div>
                  ))}
                </li>
              ))}
            </ul>
            <footer className="modal-foot">
              <button className="btn primary" onClick={onClose}>
                Done
              </button>
            </footer>
          </>
        )}
      </div>
    </div>
  );
}
