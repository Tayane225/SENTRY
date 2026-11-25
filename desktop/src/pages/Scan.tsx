import { useEffect, useState } from "react";
import type { Nav } from "../App";
import { api, bytes, type ScanStatus } from "../api";
import { Bar, Card, ErrorNote, Metric } from "../components";
import { Icon } from "../icons";

const COPY = {
  quick: {
    title: "Quick Scan",
    lead: "Checks the places malware usually lands and hides: Downloads, Desktop, temp folders, Startup folders and Public files, plus running processes, network connections, startup entries and security settings.",
  },
  full: {
    title: "Full Scan",
    lead: "Scans every authorised local drive file by file with YARA, ClamAV (when installed), hash intelligence and static analysis, then inspects behaviour, persistence and configuration. Expect roughly 1–3 hours per 500 GB.",
  },
  custom: {
    title: "Custom Scan",
    lead: "Scans exactly the folders, drives or files you choose, for example a USB stick, a download or a software project (including its dependencies).",
  },
};

export default function ScanPage({ kind, nav }: { kind: "quick" | "full" | "custom"; nav: Nav }) {
  const [paths, setPaths] = useState<string>("");
  const [online, setOnline] = useState(false);
  const [workers, setWorkers] = useState<string>("");
  const [maxWorkers, setMaxWorkers] = useState<string>("");
  const [scanId, setScanId] = useState<string | null>(null);
  const [status, setStatus] = useState<ScanStatus | null>(null);
  const [drives, setDrives] = useState<any[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (kind === "full") api.drives().then(setDrives).catch(setError);
  }, [kind]);

  useEffect(() => {
    if (!scanId) return;
    let alive = true;
    const tick = async () => {
      try {
        const s = await api.scan(scanId);
        if (!alive) return;
        setStatus(s);
        if (["running", "cancel_requested"].includes(s.status)) window.setTimeout(tick, 1000);
      } catch (e) {
        if (alive) setError(e);
      }
    };
    tick();
    return () => {
      alive = false;
    };
  }, [scanId]);

  const start = async () => {
    setBusy(true);
    setError(null);
    try {
      const list = paths
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter(Boolean);
      const res = await api.startScan({
        kind,
        paths: kind === "custom" ? list : undefined,
        online,
        workers: workers ? Number(workers) : undefined,
        max_workers: maxWorkers ? Number(maxWorkers) : undefined,
      });
      setScanId(res.scan_id);
      setStatus(null);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  const running = status && ["running", "cancel_requested"].includes(status.status);
  const p = status?.progress;
  const done = status && !running;

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>{COPY[kind].title}</h1>
          <p className="muted lead">{COPY[kind].lead}</p>
        </div>
      </header>
      <ErrorNote error={error} />
      <div className="grid-2">
        <Card title="Scan options">
          {kind === "custom" && (
            <label className="field">
              <span>Paths to scan (one per line)</span>
              <textarea rows={4} value={paths} onChange={(e) => setPaths(e.target.value)} placeholder={"D:\\\nC:\\Users\\me\\Downloads\\setup.exe"} spellCheck={false} />
            </label>
          )}
          {kind === "full" && (
            <div className="drive-list">
              {drives.map((d) => (
                <div key={d.mountpoint} className={`drive ${d.authorized_for_full_scan ? "" : "excluded"}`}>
                  <Icon name="disk" />
                  <b>{d.mountpoint}</b>
                  <span className="muted small">
                    {d.fstype} · {d.kind} · {d.usage ? `${bytes(d.usage.used)} used` : "size unknown"}
                  </span>
                  <span className="small">{d.authorized_for_full_scan ? "included" : "excluded"}</span>
                </div>
              ))}
            </div>
          )}
          <label className="check">
            <input type="checkbox" checked={online} onChange={(e) => setOnline(e.target.checked)} />
            <span>
              Online threat intelligence <span className="muted small">— sends file hashes and package names (never file contents) to MalwareBazaar, VirusTotal, URLhaus and OSV when keys are configured</span>
            </span>
          </label>
          <div className="row">
            <label className="field small-field">
              <span>Initial workers</span>
              <input inputMode="numeric" placeholder="auto (4–8)" value={workers} onChange={(e) => setWorkers(e.target.value.replace(/\D/g, ""))} />
            </label>
            <label className="field small-field">
              <span>Max workers</span>
              <input inputMode="numeric" placeholder="auto" value={maxWorkers} onChange={(e) => setMaxWorkers(e.target.value.replace(/\D/g, ""))} />
            </label>
          </div>
          <div className="row">
            <button className="btn primary" disabled={busy || Boolean(running) || (kind === "custom" && !paths.trim())} onClick={start}>
              <Icon name="play" /> Start {kind} scan
            </button>
            {running && (
              <button className="btn ghost" onClick={() => scanId && api.cancelScan(scanId)}>
                <Icon name="stop" /> Cancel
              </button>
            )}
          </div>
        </Card>

        <Card title={scanId ? `Scan ${scanId}` : "Progress"}>
          {!scanId && <p className="muted">No scan running from this page yet.</p>}
          {scanId && (
            <>
              <div className="scan-state">
                <span className={`status-pill ${status?.status === "completed" ? "ok" : status?.status === "failed" ? "danger" : ""}`}>
                  {status?.status ?? "starting"}
                </span>
                <span className="muted">phase: {p?.phase ?? "—"}</span>
              </div>
              <div className="metric-grid compact">
                <Metric label="Files" value={(p?.files_scanned ?? 0).toLocaleString()} sub={`${p?.files_per_s ?? 0}/s`} />
                <Metric label="Data" value={bytes(p?.bytes_scanned)} />
                <Metric label="Flagged" value={p?.flagged ?? 0} tone={(p?.flagged ?? 0) > 0 ? "warn" : undefined} />
                <Metric label="Workers" value={`${p?.active_workers ?? 0}/${p?.worker_limit ?? 0}`} sub={`max ${p?.max_workers ?? 0}`} />
                <Metric label="CPU" value={`${Math.round(p?.cpu ?? 0)}%`} sub={<Bar value={p?.cpu ?? 0} />} />
                <Metric label="RAM" value={`${Math.round(p?.ram ?? 0)}%`} sub={<Bar value={p?.ram ?? 0} />} />
              </div>
              {p?.current && running && <div className="mono small muted ellipsis">{p.current}</div>}
              {status?.error && <div className="note danger">{status.error}</div>}
              {done && status?.summary && (
                <div className="scan-done">
                  <p>
                    <b>{status.summary.findings_total ?? 0}</b> finding(s) in {(status.summary.files_scanned ?? 0).toLocaleString()} files.
                    Nothing has been removed.
                  </p>
                  <button className="btn primary" onClick={() => nav.go("threats", scanId)}>
                    Review findings in the Threat Center
                  </button>
                </div>
              )}
            </>
          )}
        </Card>
      </div>
    </div>
  );
}
