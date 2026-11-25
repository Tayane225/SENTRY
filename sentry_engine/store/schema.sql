-- SENTRY persistent store (SQLite, WAL mode).
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT
);

CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  roots TEXT NOT NULL,            -- JSON list
  status TEXT NOT NULL,           -- running | completed | failed | cancelled | interrupted
  started_at TEXT NOT NULL,
  finished_at TEXT,
  options TEXT,                   -- JSON
  stats TEXT,                     -- JSON (progress + final statistics)
  engines TEXT,                   -- JSON (availability/versions used)
  error TEXT,
  pid INTEGER,
  requested_by TEXT
);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  dedup_key TEXT NOT NULL,
  category TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence REAL NOT NULL,
  title TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target TEXT NOT NULL,
  path TEXT,
  sha256 TEXT,
  status TEXT NOT NULL,
  body TEXT NOT NULL,             -- full Finding JSON
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (scan_id, dedup_key)
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_sha ON findings(sha256);

CREATE TABLE IF NOT EXISTS inventory (
  scan_id TEXT NOT NULL,
  path TEXT NOT NULL,
  size INTEGER,
  mtime REAL,
  sha256 TEXT,
  kind TEXT,
  magic TEXT,
  hidden INTEGER,
  flags TEXT
);
CREATE INDEX IF NOT EXISTS idx_inventory_scan ON inventory(scan_id);
CREATE INDEX IF NOT EXISTS idx_inventory_sha ON inventory(sha256);
CREATE INDEX IF NOT EXISTS idx_inventory_path ON inventory(path);

CREATE TABLE IF NOT EXISTS inaccessible (
  scan_id TEXT NOT NULL,
  path TEXT NOT NULL,
  reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_inacc_scan ON inaccessible(scan_id);

CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY,
  action TEXT NOT NULL,
  subject_type TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  scan_id TEXT,
  payload TEXT NOT NULL,          -- canonical signed payload (JSON)
  signature TEXT NOT NULL,        -- base64 Ed25519 signature
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  result TEXT,                    -- succeeded | failed | rejected
  result_detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_approvals_scan ON approvals(scan_id);

CREATE TABLE IF NOT EXISTS quarantine (
  id TEXT PRIMARY KEY,
  finding_id TEXT,
  original_path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size INTEGER,
  quarantined_at TEXT NOT NULL,
  status TEXT NOT NULL,           -- quarantined | restored | deleted
  protected TEXT,
  meta TEXT
);

CREATE TABLE IF NOT EXISTS recovery (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  finding_id TEXT,
  created_at TEXT NOT NULL,
  status TEXT NOT NULL,           -- active | rolled_back
  data TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notes (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL,
  author TEXT NOT NULL,
  created_at TEXT NOT NULL,
  text TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notes_finding ON notes(finding_id);

CREATE TABLE IF NOT EXISTS agent_runs (
  id TEXT PRIMARY KEY,
  scan_id TEXT,
  agent TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  status TEXT NOT NULL,
  capabilities TEXT,
  tools_used TEXT,
  denied TEXT,
  summary TEXT
);
CREATE INDEX IF NOT EXISTS idx_agent_runs_scan ON agent_runs(scan_id);

CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  kind TEXT NOT NULL,
  severity TEXT NOT NULL,
  message TEXT NOT NULL,
  data TEXT,
  acknowledged INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS hash_intel (
  sha256 TEXT PRIMARY KEY,
  name TEXT,
  source TEXT,
  category TEXT,
  added_at TEXT
);

CREATE TABLE IF NOT EXISTS allowlist (
  id TEXT PRIMARY KEY,
  sha256 TEXT,
  path_glob TEXT,
  reason TEXT,
  added_at TEXT,
  approval_id TEXT
);

CREATE TABLE IF NOT EXISTS intel_cache (
  source TEXT NOT NULL,
  key TEXT NOT NULL,
  fetched_at REAL NOT NULL,
  ttl REAL NOT NULL,
  data TEXT,
  PRIMARY KEY (source, key)
);

CREATE TABLE IF NOT EXISTS remediation_log (
  id TEXT PRIMARY KEY,
  approval_id TEXT,
  action TEXT NOT NULL,
  subject_id TEXT,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  status TEXT NOT NULL,           -- succeeded | failed | rejected | needs_elevation
  detail TEXT,
  verification TEXT               -- JSON
);

CREATE TABLE IF NOT EXISTS schedules (
  name TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  spec TEXT NOT NULL,
  created_at TEXT NOT NULL,
  os_task TEXT
);
