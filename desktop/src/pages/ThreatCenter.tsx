import { useEffect, useMemo, useState } from "react";
import type { Nav } from "../App";
import { api, when, type Finding, type ScanRow } from "../api";
import { ApprovalDialog, Card, Empty, ErrorNote, SeverityBadge, type ApprovalLine } from "../components";
import { Icon } from "../icons";

const CATEGORY_ORDER = ["confirmed_malware", "suspected_malware", "suspicious_behavior", "unverified", "vulnerability", "configuration_weakness", "false_positive"];
const ACTION_LABEL: Record<string, string> = {
  quarantine: "Quarantine (reversible)",
  remove_persistence: "Remove startup entry (reversible)",
  repair: "Run repair",
  allowlist: "Mark as false positive",
};
const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function defaultAction(f: Finding): string {
  if (f.allowed_actions.includes("remove_persistence")) return "remove_persistence";
  if (f.allowed_actions.includes("quarantine")) return "quarantine";
  return f.allowed_actions[0];
}

export default function ThreatCenter({ nav }: { nav: Nav }) {
  const [scans, setScans] = useState<ScanRow[]>([]);
  const [scanId, setScanId] = useState<string | undefined>(nav.scanId);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selected, setSelected] = useState<Record<string, string>>({});
  const [open, setOpen] = useState<string | null>(null);
  const [filter, setFilter] = useState<string>("actionable");
  const [error, setError] = useState<unknown>(null);
  const [dialog, setDialog] = useState<ApprovalLine[] | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    api.scans().then((s) => {
      setScans(s);
      if (!scanId && s.length) setScanId(s[0].scan_id);
    }).catch(setError);
  }, []);

  const load = async (id = scanId) => {
    if (!id) return;
    setLoading(true);
    try {
      const r = await api.findings(id);
      setFindings(r.findings);
      setError(null);
    } catch (e) {
      setError(e);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    setSelected({});
    load(scanId);
  }, [scanId]);

  const visible = useMemo(() => {
    let list = [...findings];
    if (filter === "actionable") list = list.filter((f) => f.allowed_actions.length && ["open", "failed"].includes(f.status));
    else if (filter !== "all") list = list.filter((f) => f.category === filter);
    return list.sort((a, b) => CATEGORY_ORDER.indexOf(a.category) - CATEGORY_ORDER.indexOf(b.category) || SEV_RANK[b.severity] - SEV_RANK[a.severity]);
  }, [findings, filter]);

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    findings.forEach((f) => (c[f.category] = (c[f.category] ?? 0) + 1));
    return c;
  }, [findings]);

  const toggle = (f: Finding) => {
    const next = { ...selected };
    if (next[f.id]) delete next[f.id];
    else next[f.id] = defaultAction(f);
    setSelected(next);
  };

  const review = () => {
    const lines: ApprovalLine[] = Object.entries(selected).map(([id, action]) => {
      const f = findings.find((x) => x.id === id)!;
      const protectedName = action === "quarantine" && f.protected ? (f.path ?? "").split(/[\\/]/).pop() ?? null : null;
      return { subject_type: "finding", subject_id: id, action, label: f.title, detail: f.path ?? f.target, protectedName };
    });
    setDialog(lines);
  };

  const nSel = Object.keys(selected).length;
  const scan = scans.find((s) => s.scan_id === scanId);

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Threat Center</h1>
          <p className="muted">
            Every finding comes with SENTRY's evidence, an explanation and the potential danger. Tick ✅ the ones to handle. Nothing is
            removed until you approve with your passphrase.
          </p>
        </div>
        <div className="row">
          <select value={scanId ?? ""} onChange={(e) => setScanId(e.target.value)} aria-label="Scan">
            {scans.map((s) => (
              <option key={s.scan_id} value={s.scan_id}>
                {s.scan_id} · {s.kind} · {when(s.started_at)}
              </option>
            ))}
          </select>
          <button className="btn ghost" onClick={() => load()}>
            Refresh
          </button>
        </div>
      </header>
      <ErrorNote error={error} />
      {scan && scan.status === "running" && <div className="note">This scan is still running. Findings appear when it completes.</div>}

      <div className="filters">
        {[["actionable", "Needs decision"], ["all", "All"], ...CATEGORY_ORDER.filter((c) => counts[c]).map((c) => [c, c.replace("_", " ")])].map(([id, label]) => (
          <button key={id} className={`chip ${filter === id ? "active" : ""}`} onClick={() => setFilter(id)}>
            {label}
            {id !== "actionable" && id !== "all" ? ` · ${counts[id]}` : ""}
          </button>
        ))}
      </div>

      <Card>
        {loading && <p className="muted">Loading…</p>}
        {!loading && !visible.length && <Empty title="Nothing to review">No findings match this filter for the selected scan.</Empty>}
        <ul className="finding-list">
          {visible.map((f) => {
            const selectable = f.allowed_actions.length > 0 && ["open", "failed"].includes(f.status);
            const isOpen = open === f.id;
            return (
              <li key={f.id} className={`finding ${selected[f.id] ? "selected" : ""} cat-${f.category}`}>
                <div className="finding-row">
                  <label className="tick" title={selectable ? "Select for remediation" : "No action available"}>
                    <input type="checkbox" disabled={!selectable} checked={Boolean(selected[f.id])} onChange={() => toggle(f)} />
                    <span className="tick-box">{selected[f.id] ? "✅" : ""}</span>
                  </label>
                  <SeverityBadge severity={f.severity} />
                  <button className="finding-main" onClick={() => setOpen(isOpen ? null : f.id)} aria-expanded={isOpen}>
                    <div className="finding-title">{f.title}</div>
                    <div className="finding-meta">
                      <span>{f.category_label}</span>
                      <span>confidence {f.confidence_label} ({f.confidence.toFixed(2)})</span>
                      <span>{f.detection_engines.join(", ") || "—"}</span>
                      <span className={`status status-${f.status}`}>{f.status}</span>
                    </div>
                    <div className="mono small muted ellipsis">{f.path ?? f.target}</div>
                  </button>
                  {selected[f.id] && f.allowed_actions.length > 1 && (
                    <select value={selected[f.id]} onChange={(e) => setSelected({ ...selected, [f.id]: e.target.value })} aria-label="Action">
                      {f.allowed_actions.map((a) => (
                        <option key={a} value={a}>
                          {ACTION_LABEL[a] ?? a}
                        </option>
                      ))}
                    </select>
                  )}
                  <Icon name="chevron" className={`chev ${isOpen ? "open" : ""}`} />
                </div>
                {isOpen && (
                  <div className="finding-detail">
                    <div className="detail-grid">
                      <div>
                        <h4>What it is</h4>
                        <p>{f.explanation}</p>
                        <h4>Potential danger</h4>
                        <ul>{f.potential_damage.map((d) => <li key={d}>{d}</li>)}</ul>
                        <h4>Recommended action</h4>
                        <p>{f.recommended_action}</p>
                        {f.limitations.length > 0 && (
                          <>
                            <h4>Confidence limitations</h4>
                            <ul className="warn-text">{f.limitations.map((l) => <li key={l}>{l}</li>)}</ul>
                          </>
                        )}
                        {f.protected && <div className="note danger small">Protected: {f.protected}</div>}
                      </div>
                      <div>
                        <h4>Evidence</h4>
                        <ul className="evidence">
                          {f.evidence.map((e, i) => (
                            <li key={i}>
                              <span className={`verdict v-${e.verdict}`}>{e.engine}</span> {e.description}
                              {e.provenance && <div className="small muted">{e.provenance}</div>}
                            </li>
                          ))}
                        </ul>
                        {f.attack_techniques.length > 0 && (
                          <>
                            <h4>MITRE ATT&CK</h4>
                            <div className="tags">
                              {f.attack_techniques.map((t) => (
                                <a key={t.id} className="tag" href={t.url} target="_blank" rel="noreferrer noopener">
                                  {t.id} · {t.name}
                                </a>
                              ))}
                            </div>
                          </>
                        )}
                        {f.sha256 && <div className="mono small muted">SHA-256 {f.sha256}</div>}
                        {f.ai_notes && f.ai_notes.length > 0 && (
                          <>
                            <h4>AI investigation notes</h4>
                            {f.ai_notes.map((n, i) => (
                              <blockquote key={i} className="ai-note">
                                <div className="small muted">
                                  {n.author} · {when(n.created_at)}
                                </div>
                                {n.text}
                              </blockquote>
                            ))}
                          </>
                        )}
                      </div>
                    </div>
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      </Card>

      {nSel > 0 && (
        <div className="action-bar">
          <span>
            <b>{nSel}</b> finding{nSel > 1 ? "s" : ""} selected
          </span>
          <button className="btn ghost" onClick={() => setSelected({})}>
            Clear
          </button>
          <button className="btn primary" onClick={review}>
            <Icon name="lock" /> Review &amp; approve
          </button>
        </div>
      )}
      {dialog && (
        <ApprovalDialog
          lines={dialog}
          onClose={() => {
            setDialog(null);
            load();
          }}
          onDone={() => setSelected({})}
        />
      )}
    </div>
  );
}
