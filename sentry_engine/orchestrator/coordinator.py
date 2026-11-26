"""Master coordinator: runs the scan phases and the adaptive worker pool.

Hierarchy: one coordinator → specialised agents → N file workers (threads).
The filesystem phase is a producer (walker thread) / consumer (async workers
dispatching to a thread pool) pipeline with back-pressure. Progress is kept in
memory and persisted to the database every second for other processes (API, MCP).
"""

from __future__ import annotations

import asyncio
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any, Callable

from ..agents import all_agent_definitions, run_agent
from ..agents.specialists import _file_draft
from ..behavioral.ransomware import RansomwareTracker
from ..filesystem.walker import WalkStats, walk
from ..malware.analyzer import FileAnalyzer
from ..models import Finding, ScanOptions, Verdict
from ..risk import classify
from ..util import dumps, new_id, utcnow_iso
from ..vulnerability.dependencies import is_lockfile
from .evidence import EvidenceManager
from .scheduler import AdaptiveConcurrency, DynamicLimiter, default_limits
from .task_queue import LocalTaskQueue, Task

if TYPE_CHECKING:
    from ..engine import Engine

_ACTIVE: dict[str, "ScanProgress"] = {}


@dataclass
class ScanProgress:
    scan_id: str
    phase: str = "starting"
    files_seen: int = 0
    files_scanned: int = 0
    bytes_scanned: int = 0
    flagged: int = 0
    errors: int = 0
    active_workers: int = 0
    worker_limit: int = 0
    max_workers: int = 0
    cpu: float = 0.0
    ram: float = 0.0
    current: str = ""
    started: float = field(default_factory=time.time)
    cancelled: bool = False

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["elapsed_s"] = round(time.time() - self.started, 1)
        d["files_per_s"] = round(self.files_scanned / max(0.1, d["elapsed_s"]), 1)
        return d


def active_progress(scan_id: str) -> ScanProgress | None:
    return _ACTIVE.get(scan_id)


def request_cancel(scan_id: str) -> bool:
    p = _ACTIVE.get(scan_id)
    if p:
        p.cancelled = True
        return True
    return False


class Coordinator:
    def __init__(self, engine: "Engine", options: ScanOptions, on_progress: Callable[[ScanProgress], None] | None = None,
                 scan_id: str | None = None, on_created: Callable[[], None] | None = None):
        self.engine = engine
        self.options = options
        self.on_progress = on_progress
        self.on_created = on_created  # called once the scan record exists (callers may poll status from then on)
        self.scan_id = scan_id or new_id("S", 5)
        self.progress = ScanProgress(self.scan_id)
        self.online = engine.settings.online_intel if options.online_intel is None else bool(options.online_intel)

    # ------------------------------------------------------------------ entry point
    def run(self) -> dict[str, Any]:
        _ACTIVE[self.scan_id] = self.progress
        e = self.engine
        e.store.create_scan(self.scan_id, self.options.kind, self.options.roots, self.options.to_dict(), os.getpid(),
                            self.options.requested_by)
        if self.on_created:
            self.on_created()
        e.audit.append("scan.started", self.options.requested_by, {"scan_id": self.scan_id, "kind": self.options.kind,
                                                                   "roots": self.options.roots})
        try:
            summary = asyncio.run(self._run())
            status = "cancelled" if self.progress.cancelled else "completed"
            e.store.update_scan(self.scan_id, status=status, finished_at=utcnow_iso(), stats=summary["stats"],
                                engines=summary["engines"])
            e.audit.append("scan.finished", "engine", {"scan_id": self.scan_id, "status": status,
                                                       "findings": summary["stats"].get("findings_total")})
            summary["status"] = status
            return summary
        except Exception as exc:
            e.store.update_scan(self.scan_id, status="failed", finished_at=utcnow_iso(), error=f"{type(exc).__name__}: {exc}")
            e.audit.append("scan.failed", "engine", {"scan_id": self.scan_id, "error": str(exc)[:500]})
            raise
        finally:
            _ACTIVE.pop(self.scan_id, None)

    # ------------------------------------------------------------------ phases
    async def _run(self) -> dict[str, Any]:
        e = self.engine
        s = e.settings
        stats: dict[str, Any] = {"notes": []}
        em = EvidenceManager()
        analyzer = FileAnalyzer(e, include_archives=self.options.include_archives,
                                full_clam=self.options.kind == "full")
        ctx: dict[str, Any] = {"scan_id": self.scan_id, "options": self.options, "evidence": em, "analyzer": analyzer,
                               "progress": self.progress, "stats": stats, "online": self.online,
                               "ransomware": RansomwareTracker(), "lockfiles": [], "clam_candidates": [], "file_index": {}}
        agents = {a.name: a for a in all_agent_definitions(self.online)}
        runs: list[dict[str, Any]] = []
        engines = {"yara": e.yara.describe(), "clamav": e.clamav.describe(), "defender": e.defender.describe(),
                   "hash_intel_entries": e.hashintel.count(), "online_intel": self.online}
        if not e.yara.available:
            stats["notes"].append("YARA is unavailable: install yara-python for rule-based detection.")
        if not e.clamav.available:
            stats["notes"].append("ClamAV is not installed or not reachable: signature coverage relies on YARA, hash intelligence"
                                  " and (on Windows) Microsoft Defender corroboration. Install ClamAV for full signature scanning.")

        runs.append(run_agent(e, agents["scan_coordinator"], ctx, self.scan_id))
        roots = ctx.get("roots") or []
        e.store.update_scan(self.scan_id, roots=roots)
        stats["roots"] = roots
        stats["phases"] = ctx.get("phases")

        walk_stats = await self._filesystem_phase(ctx, roots)
        stats["filesystem"] = {"directories": walk_stats.directories, "files": walk_stats.files,
                               "symlinks_skipped": walk_stats.symlinks_skipped, "excluded": walk_stats.excluded,
                               "other_device_skipped": walk_stats.other_device_skipped,
                               "cloud_placeholders_skipped": walk_stats.cloud_placeholders,
                               "special_files": walk_stats.special_files, "inaccessible": len(walk_stats.inaccessible)}
        if walk_stats.inaccessible:
            e.store.executemany("INSERT INTO inaccessible(scan_id, path, reason) VALUES (?,?,?)",
                                [(self.scan_id, p, r) for p, r in walk_stats.inaccessible])
            stats["inaccessible_sample"] = [{"path": p, "reason": r} for p, r in walk_stats.inaccessible[:25]]

        if self.options.behavior and not self.progress.cancelled:
            runs.append(run_agent(e, agents["behavioral_analyst"], ctx, self.scan_id))
        if self.options.persistence and not self.progress.cancelled:
            runs.append(run_agent(e, agents["persistence_analyst"], ctx, self.scan_id))
        # corroboration post-pass runs after behaviour/persistence so their files get ClamAV/Defender/signature checks too
        if not self.progress.cancelled:
            runs.append(run_agent(e, agents["malware_analyst"], ctx, self.scan_id))
        if self.options.vulnerabilities and not self.progress.cancelled:
            runs.append(run_agent(e, agents["vulnerability_analyst"], ctx, self.scan_id))
        if self.online and not self.progress.cancelled:
            runs.append(run_agent(e, agents["threat_intel_analyst"], ctx, self.scan_id))
        runs.append(run_agent(e, agents["forensics_analyst"], ctx, self.scan_id))

        # classification (risk engine) and persistence of findings
        self.progress.phase = "classification"
        findings: list[Finding] = []
        n = 0
        for d in em:
            n += 1
            f = classify(d, self.scan_id, f"F-{self.scan_id[2:]}-{n:04d}", s.report_min_score)
            if f is not None:
                findings.append(f)
        for f in findings:
            e.store.upsert_finding(f)
        ctx["findings"] = findings
        runs.append(run_agent(e, agents["remediation_planner"], ctx, self.scan_id))
        runs.append(run_agent(e, agents["recovery_agent"], ctx, self.scan_id))

        stats.update(self._post_stats(findings))
        stats["agents"] = [{"agent": r["agent"], "status": r["status"], "run_id": r["run_id"],
                            "duration_s": r["summary"].get("duration_s")} for r in runs]
        stats["progress"] = self.progress.to_dict()
        stats["scan_options"] = {"exclusions": s.exclude_globs, "online_intel": self.online,
                                 "max_hash_size": s.max_hash_size, "max_content_scan_size": s.max_content_scan_size}
        self.progress.phase = "done"
        return {"scan_id": self.scan_id, "stats": stats, "engines": engines, "findings": [f.to_dict() for f in findings]}

    async def _filesystem_phase(self, ctx: dict[str, Any], roots: list[str]) -> WalkStats:
        e = self.engine
        s = e.settings
        mn, init, mx = default_limits(self.options.workers, self.options.max_workers, s)
        adapt = AdaptiveConcurrency(mn, init, mx, s.cpu_high_watermark, s.memory_high_watermark, s.adaptive_concurrency)
        limiter = DynamicLimiter(init)
        self.progress.worker_limit, self.progress.max_workers = init, mx
        self.progress.phase = "filesystem"
        queue = LocalTaskQueue(maxsize=mx * 8)
        loop = asyncio.get_running_loop()
        pool = ThreadPoolExecutor(max_workers=mx, thread_name_prefix="sentry-worker")
        walk_stats = WalkStats()
        inventory: list[tuple] = []
        em: EvidenceManager = ctx["evidence"]
        tracker: RansomwareTracker = ctx["ransomware"]
        own = e.own_dirs()

        def producer() -> None:
            try:
                for entry in walk(roots, s.exclude_globs, own, s.one_filesystem, walk_stats,
                                  should_stop=lambda: self.progress.cancelled):
                    self.progress.files_seen += 1
                    asyncio.run_coroutine_threadsafe(queue.put(Task("file", entry)), loop).result()
            finally:
                for _ in range(mx):
                    asyncio.run_coroutine_threadsafe(queue.put(None), loop).result()

        def handle(res) -> None:
            r = res.record
            self.progress.files_scanned += 1
            self.progress.bytes_scanned += r.size or 0
            if res.error:
                self.progress.errors += 1
                if len(walk_stats.inaccessible) < 10000:
                    walk_stats.inaccessible.append((r.path, res.error))
                return
            tracker.observe(r.path, r.mtime, r.flags, r.ext)
            if is_lockfile(r.path):
                ctx["lockfiles"].append(r.path)
            if res.clam_candidate:
                ctx["clam_candidates"].append(r.path)
                ctx["file_index"][r.path] = {"sha256": r.sha256, "size": r.size, "allowlisted": res.allowlisted}
            interesting = r.kind in ("executable", "script", "document", "archive", "shortcut", "html")
            if res.flagged or any(ev.verdict == Verdict.MALICIOUS.value for ev in res.evidence):
                self.progress.flagged += 1
                em.add(_file_draft(res))
            if s.store_full_inventory or interesting or res.flagged:
                inventory.append((self.scan_id, r.path, r.size, r.mtime, r.sha256, r.kind, r.magic, int(r.hidden),
                                  dumps(r.flags) if r.flags else None))
                if len(inventory) >= 1000:
                    e.store.executemany("INSERT INTO inventory VALUES (?,?,?,?,?,?,?,?,?)", inventory)
                    inventory.clear()

        async def worker() -> None:
            analyzer = ctx["analyzer"]
            while True:
                task = await queue.get()
                if task is None:
                    queue.done()
                    return
                async with limiter:
                    self.progress.active_workers = limiter.active
                    self.progress.current = task.payload.path[-160:]
                    try:
                        res = await loop.run_in_executor(pool, analyzer.analyze, task.payload)
                        handle(res)
                    except Exception as exc:  # isolate per-file failures
                        self.progress.errors += 1
                        walk_stats.inaccessible.append((task.payload.path, f"analysis error: {type(exc).__name__}"))
                queue.done()

        async def monitor() -> None:
            last_persist = 0.0
            while True:
                await asyncio.sleep(1.0)
                if int(time.time()) % 2 == 0:
                    new_limit = adapt.adjust(queue.backlog())
                    if new_limit != limiter.limit:
                        await limiter.set_limit(new_limit)
                self.progress.worker_limit = limiter.limit
                self.progress.active_workers = limiter.active
                self.progress.cpu, self.progress.ram = adapt.last.cpu, adapt.last.mem
                if self.on_progress:
                    self.on_progress(self.progress)
                if time.time() - last_persist > 1.0:
                    last_persist = time.time()
                    e.store.update_scan(self.scan_id, stats={"progress": self.progress.to_dict()})
                    row = e.store.one("SELECT status FROM scans WHERE id=?", (self.scan_id,))
                    if row and row["status"] == "cancel_requested":
                        self.progress.cancelled = True

        prod = loop.run_in_executor(None, producer)
        workers = [asyncio.create_task(worker()) for _ in range(mx)]
        mon = asyncio.create_task(monitor())
        try:
            await prod
            await asyncio.gather(*workers)
        finally:
            mon.cancel()
            pool.shutdown(wait=False, cancel_futures=True)
        if inventory:
            e.store.executemany("INSERT INTO inventory VALUES (?,?,?,?,?,?,?,?,?)", inventory)
        if self.on_progress:
            self.on_progress(self.progress)
        return walk_stats

    def _post_stats(self, findings: list[Finding]) -> dict[str, Any]:
        e = self.engine
        by_cat: dict[str, int] = {}
        by_sev: dict[str, int] = {}
        for f in findings:
            by_cat[f.category] = by_cat.get(f.category, 0) + 1
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        dup = e.store.query("SELECT sha256, COUNT(*) AS n, MAX(size) AS size FROM inventory WHERE scan_id=? AND sha256 IS NOT NULL "
                            "GROUP BY sha256 HAVING COUNT(*) > 1", (self.scan_id,))
        prev = e.store.one("SELECT id FROM scans WHERE id<>? AND status='completed' AND started_at < ? ORDER BY started_at DESC LIMIT 1",
                           (self.scan_id, utcnow_iso()))
        changed: list[dict[str, Any]] = []
        if prev:
            changed = e.store.query(
                "SELECT c.path, p.sha256 AS old_sha256, c.sha256 AS new_sha256, c.kind FROM inventory c JOIN inventory p "
                "ON p.path = c.path AND p.scan_id = ? WHERE c.scan_id = ? AND c.sha256 IS NOT NULL AND p.sha256 IS NOT NULL "
                "AND c.sha256 <> p.sha256 LIMIT 200", (prev["id"], self.scan_id))
        p = self.progress
        return {
            "files_scanned": p.files_scanned, "bytes_scanned": p.bytes_scanned, "files_flagged": p.flagged,
            "analysis_errors": p.errors, "findings_total": len(findings), "by_category": by_cat, "by_severity": by_sev,
            "threats": by_cat.get("confirmed_malware", 0) + by_cat.get("suspected_malware", 0),
            "suspicious_activities": by_cat.get("suspicious_behavior", 0),
            "vulnerabilities": by_cat.get("vulnerability", 0) + by_cat.get("configuration_weakness", 0),
            "duplicates": {"sets": len(dup), "redundant_bytes": sum((d["n"] - 1) * (d["size"] or 0) for d in dup),
                           "scope": "inventoried files (executables, scripts, documents, archives, flagged files)"},
            "modified_since_previous_scan": {"previous_scan": prev["id"] if prev else None, "count": len(changed),
                                             "sample": changed[:25]},
            "elapsed_s": round(time.time() - p.started, 1),
        }


def run_scan_in_thread(engine: "Engine", options: ScanOptions) -> str:
    """Start a scan in a background thread and return its id as soon as its record exists (API/MCP).

    Returning only after the scan row is stored guarantees that an immediate status poll never
    sees "unknown scan" (a race that showed up on fast Linux CI runners).
    """
    scan_id = new_id("S", 5)
    created = threading.Event()

    def target() -> None:
        coord = Coordinator(engine, options, scan_id=scan_id, on_created=created.set)  # one SQLite connection per thread
        try:
            coord.run()
        except Exception:
            pass
        finally:
            created.set()  # never leave the caller waiting if the scan failed before its record was written

    threading.Thread(target=target, name=f"scan-{scan_id}", daemon=True).start()
    created.wait(timeout=30)
    return scan_id
