import { useEffect, useState } from "react";
import { api, resolveBackend } from "./api";
import { Icon } from "./icons";
import Overview from "./pages/Overview";
import ScanPage from "./pages/Scan";
import ThreatCenter from "./pages/ThreatCenter";
import Investigation from "./pages/Investigation";
import Quarantine from "./pages/Quarantine";
import Repair from "./pages/Repair";
import Agents from "./pages/Agents";
import History from "./pages/History";
import Settings from "./pages/Settings";

export type Page =
  | "overview"
  | "full"
  | "quick"
  | "custom"
  | "threats"
  | "investigation"
  | "quarantine"
  | "repair"
  | "agents"
  | "history"
  | "settings";

const NAV: { group: string; items: { id: Page; label: string; icon: string }[] }[] = [
  {
    group: "Protection",
    items: [
      { id: "overview", label: "Overview", icon: "overview" },
      { id: "full", label: "Full Scan", icon: "disk" },
      { id: "quick", label: "Quick Scan", icon: "bolt" },
      { id: "custom", label: "Custom Scan", icon: "folder" },
    ],
  },
  {
    group: "Response",
    items: [
      { id: "threats", label: "Threat Center", icon: "shield" },
      { id: "investigation", label: "AI Investigation", icon: "brain" },
      { id: "quarantine", label: "Quarantine", icon: "vault" },
      { id: "repair", label: "System Repair", icon: "wrench" },
    ],
  },
  {
    group: "Operations",
    items: [
      { id: "agents", label: "Agent Control Center", icon: "agents" },
      { id: "history", label: "Scan History", icon: "history" },
      { id: "settings", label: "Settings", icon: "settings" },
    ],
  },
];

export interface Nav {
  go: (page: Page, scanId?: string) => void;
  scanId?: string;
}

export default function App() {
  const [page, setPage] = useState<Page>("overview");
  const [scanId, setScanId] = useState<string | undefined>();
  const [conn, setConn] = useState<"connecting" | "ok" | "error">("connecting");
  const [connError, setConnError] = useState<string>("");
  const [version, setVersion] = useState("");

  useEffect(() => {
    let tries = 0;
    const connect = async () => {
      try {
        await resolveBackend();
        const h = await api.health();
        await api.status();
        setVersion(h.version);
        setConn("ok");
      } catch (e) {
        tries += 1;
        if (tries < 20) {
          window.setTimeout(connect, 750);
        } else {
          setConn("error");
          setConnError(e instanceof Error ? e.message : String(e));
        }
      }
    };
    connect();
  }, []);

  const nav: Nav = {
    go: (p, s) => {
      if (s !== undefined) setScanId(s);
      setPage(p);
    },
    scanId,
  };

  if (conn !== "ok") {
    return (
      <div className="splash">
        <img src="/sentry-logo.png" alt="SENTRY" className="splash-logo" />
        {conn === "connecting" ? (
          <p className="muted">Starting the SENTRY engine…</p>
        ) : (
          <div className="splash-error">
            <h2>Cannot reach the SENTRY engine</h2>
            <p className="muted">{connError}</p>
            <p>
              Install the engine with <code>pip install "sentry-guard[full]"</code>, or start it manually with{" "}
              <code>sentry serve --open</code> and use the browser window it opens.
            </p>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <img src="/sentry-logo.png" alt="" className="brand-mark" />
          <div>
            <div className="brand-name">SENTRY</div>
            <div className="brand-tag">Guards Against Intrusions</div>
          </div>
        </div>
        <nav>
          {NAV.map((g) => (
            <div key={g.group} className="nav-group">
              <div className="nav-group-label">{g.group}</div>
              {g.items.map((it) => (
                <button
                  key={it.id}
                  className={`nav-item ${page === it.id ? "active" : ""}`}
                  onClick={() => setPage(it.id)}
                  aria-current={page === it.id ? "page" : undefined}
                >
                  <Icon name={it.icon} />
                  <span>{it.label}</span>
                </button>
              ))}
            </div>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div className="tagline">Detect. Defend. Restore.</div>
          <div className="muted small">Engine {version}</div>
        </div>
      </aside>
      <main className="main">
        {page === "overview" && <Overview nav={nav} />}
        {(page === "full" || page === "quick" || page === "custom") && <ScanPage kind={page} nav={nav} key={page} />}
        {page === "threats" && <ThreatCenter nav={nav} />}
        {page === "investigation" && <Investigation nav={nav} />}
        {page === "quarantine" && <Quarantine />}
        {page === "repair" && <Repair nav={nav} />}
        {page === "agents" && <Agents nav={nav} />}
        {page === "history" && <History nav={nav} />}
        {page === "settings" && <Settings />}
      </main>
    </div>
  );
}
