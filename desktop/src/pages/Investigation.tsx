import { useEffect, useMemo, useState } from "react";
import type { Nav } from "../App";
import { api, when, type Finding, type ScanRow } from "../api";
import { Card, Empty, ErrorNote, SeverityBadge } from "../components";

export default function Investigation({ nav }: { nav: Nav }) {
  const [scans, setScans] = useState<ScanRow[]>([]);
  const [scanId, setScanId] = useState<string | undefined>(nav.scanId);
  const [report, setReport] = useState<any>(null);
  const [error, setError] = useState<unknown>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    api.scans().then((s) => {
      setScans(s);
      if (!scanId && s.length) setScanId(s[0].scan_id);
    }).catch(setError);
  }, []);
  useEffect(() => {
    if (scanId) api.report(scanId).then(setReport).catch(setError);
  }, [scanId]);

  const findings: Finding[] = report?.findings ?? [];
  const techniques = useMemo(() => {
    const m = new Map<string, { id: string; name: string; tactic: string; url: string; n: number }>();
    findings.filter((f) => f.category !== "false_positive").forEach((f) =>
      f.attack_techniques.forEach((t) => m.set(t.id, { ...t, n: (m.get(t.id)?.n ?? 0) + 1 })),
    );
    return [...m.values()].sort((a, b) => b.n - a.n);
  }, [findings]);
  const annotated = findings.filter((f) => f.ai_notes && f.ai_notes.length);

  const brief = scanId
    ? `Use the SENTRY skill to investigate scan ${scanId}. Fan out read-only sub-agents per finding category (agents/*.md role prompts), ` +
      `record each conclusion with sentry_annotate_finding, then show me every finding with a checkbox, explanation, potential danger and ` +
      `recommended action. Do not approve anything: I will approve in SENTRY myself.`
    : "";

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>AI Investigation</h1>
          <p className="muted">
            SENTRY's engine agents collect and correlate the evidence. Your AI coding agent (Claude Code, Codex, OpenCode, Gemini CLI…) runs
            specialised sub-agents that reason over it and record their conclusions here. Their notes are advisory: they cannot approve or
            change anything.
          </p>
        </div>
        <select value={scanId ?? ""} onChange={(e) => setScanId(e.target.value)} aria-label="Scan">
          {scans.map((s) => (
            <option key={s.scan_id} value={s.scan_id}>
              {s.scan_id} · {s.kind} · {when(s.started_at)}
            </option>
          ))}
        </select>
      </header>
      <ErrorNote error={error} />

      <Card
        title="Ask your AI agent to investigate"
        actions={
          <button
            className="btn ghost"
            onClick={() => {
              navigator.clipboard.writeText(brief);
              setCopied(true);
              window.setTimeout(() => setCopied(false), 1500);
            }}
            disabled={!brief}
          >
            {copied ? "Copied" : "Copy prompt"}
          </button>
        }
      >
        <p className="mono small">{brief || "Run a scan first."}</p>
      </Card>

      <div className="grid-2">
        <Card title={`AI conclusions (${annotated.length})`}>
          {!annotated.length ? (
            <Empty title="No AI notes yet">Notes written by your coding agent through `sentry_annotate_finding` appear here.</Empty>
          ) : (
            <ul className="note-list">
              {annotated.map((f) => (
                <li key={f.id}>
                  <div className="row">
                    <SeverityBadge severity={f.severity} />
                    <b>{f.title}</b>
                  </div>
                  {f.ai_notes!.map((n, i) => (
                    <blockquote key={i} className="ai-note">
                      <div className="small muted">
                        {n.author} · {when(n.created_at)}
                      </div>
                      {n.text}
                    </blockquote>
                  ))}
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card title="ATT&CK techniques observed">
          {!techniques.length ? (
            <Empty title="No techniques mapped" />
          ) : (
            <ul className="technique-list">
              {techniques.map((t) => (
                <li key={t.id}>
                  <a href={t.url} target="_blank" rel="noreferrer noopener" className="tag">
                    {t.id}
                  </a>
                  <span>{t.name}</span>
                  <span className="muted small">{t.tactic}</span>
                  <span className="count">{t.n}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <Card title="Forensic timeline">
        {!report?.timeline?.length ? (
          <Empty title="No timeline events" />
        ) : (
          <ol className="timeline">
            {report.timeline.map((t: any, i: number) => (
              <li key={i}>
                <span className="mono small">{when(t.time)}</span>
                <span className="muted small">{t.kind}</span>
                <span>{t.event}</span>
              </li>
            ))}
          </ol>
        )}
      </Card>
      {report?.recovery && (
        <Card title="Recovery assessment">
          <p>{report.recovery.advice}</p>
          <ul>
            {(report.recovery.backup_options ?? []).map((o: any) => (
              <li key={o.source}>
                {o.source}: {o.available === null ? "unknown (needs administrator)" : o.available ? "available" : "not found"}
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
}
