"""The ten specialised SENTRY agents.

These are deterministic engine agents: each has one responsibility, restricted
capabilities, structured input/output and an audited run history. The coding
agent's LLM sub-agents (see the top-level ``agents/`` role prompts) reason over
their output; they never replace the engines.
"""

from __future__ import annotations

import os
from collections import defaultdict
from typing import Any

from ..models import Evidence, Verdict
from ..risk import Draft, score_evidence
from ..security import protected_reason
from ..util import IS_WINDOWS, ts_to_iso
from .base import Agent, ToolBroker


def _file_draft(analysis, protected_extra: list[str] | None = None) -> Draft:
    r = analysis.record
    d = Draft("file", r.path, path=r.path, sha256=r.sha256, size=r.size, evidence=[], allowlisted=analysis.allowlisted,
              protected=protected_reason(r.path, protected_extra))
    d.add(analysis.evidence)
    if "content_scan_partial" in r.flags:
        d.data["content_scan_partial"] = True
    d.data.update({"kind": r.kind, "magic": r.magic, "mtime": ts_to_iso(r.mtime), "ctime": ts_to_iso(r.ctime),
                   "hidden": r.hidden})
    if analysis.archive_info:
        d.data["archive"] = analysis.archive_info
    return d


# ---------------------------------------------------------------------------------------------- 1
class ScanCoordinatorAgent(Agent):
    def __init__(self):
        super().__init__("scan_coordinator", "Scan Coordinator",
                         "Defines the authorised scan scope and the phases to run.",
                         frozenset({"scope.read"}), "ScanOptions", "{roots, phases, drives}")

    def run(self, broker: ToolBroker, ctx: dict[str, Any]) -> dict[str, Any]:
        scope = broker.use("scope.read")
        opts = ctx["options"]
        s = broker.engine.settings
        if opts.kind == "quick":
            roots = scope.quick_scan_roots()
        elif opts.kind == "full":
            roots = scope.full_scan_roots(s.include_network_drives, s.include_removable_drives)
        else:
            roots = [os.path.abspath(os.path.expanduser(r)) for r in opts.roots]
        missing = [r for r in roots if not os.path.exists(r)]
        roots = [r for r in roots if os.path.exists(r)]
        phases = ["filesystem", "malware"]
        if opts.behavior:
            phases.append("behavior")
        if opts.persistence:
            phases.append("persistence")
        if opts.vulnerabilities:
            phases.append("vulnerability")
        if ctx.get("online"):
            phases.append("threat_intelligence")
        phases += ["forensics", "remediation_planning"]
        ctx["roots"] = roots
        ctx["phases"] = phases
        return {"roots": roots, "missing_roots": missing, "phases": phases}


# ---------------------------------------------------------------------------------------------- 2
class MalwareAnalystAgent(Agent):
    def __init__(self):
        super().__init__("malware_analyst", "Malware Detection Agent",
                         "Runs signature, rule and static analysis on files; corroborates suspicious files with additional engines.",
                         frozenset({"fs.analyze", "evidence.write", "detect.clamav", "detect.defender", "authenticode.read"}),
                         "file analyses from scan workers", "file drafts with evidence")

    def run(self, broker: ToolBroker, ctx: dict[str, Any]) -> dict[str, Any]:
        """Post-pass after the worker pool: ClamAV CLI batch, Defender corroboration, Authenticode."""
        em = broker.use("evidence.write")
        engine = broker.engine
        out: dict[str, Any] = {"clamav_batch": 0, "clamav_hits": 0, "defender_checked": 0, "defender_hits": 0, "signatures_checked": 0}
        clam = broker.use("detect.clamav") if engine.settings.use_clamav else None
        cands = ctx.get("clam_candidates") or []
        if clam is not None and clam.mode == "cli" and cands:
            ctx["progress"].phase = "clamav"
            hits = clam.scan_batch(cands)
            out["clamav_batch"] = len(cands)
            for path, ev in hits.items():
                info = ctx["file_index"].get(path) or {}
                d = Draft("file", path, path=path, sha256=info.get("sha256"), size=info.get("size"),
                          protected=protected_reason(path), allowlisted=info.get("allowlisted"))
                em.add(d, [ev])
                out["clamav_hits"] += 1
        if IS_WINDOWS:
            from ..malware.pe_analysis import authenticode_batch

            broker.use("authenticode.read")
            todo = [d for d in em if d.target_type in ("file", "process") and d.path and os.path.isfile(d.path)
                    and (d.data.get("magic") == "pe" or d.target_type == "process")
                    and not any(e.engine == "authenticode" for e in d.evidence)
                    and not any(e.verdict == Verdict.MALICIOUS.value for e in d.evidence)
                    and score_evidence(d.evidence)[0] >= 0.25][:200]
            sigs = authenticode_batch([d.path for d in todo])
            out["signatures_checked"] = len(sigs)
            for d in todo:
                st = sigs.get(d.path)
                if not st:
                    continue
                if st["status"] == "Valid":
                    d.add([Evidence(engine="authenticode", rule="authenticode.valid", weight=0, verdict=Verdict.CLEAN.value,
                                    description=f"Valid digital signature: {(st.get('subject') or '')[:120]}",
                                    details=st)])
                elif st["status"] == "HashMismatch":
                    d.add([Evidence(engine="authenticode", rule="authenticode.hash_mismatch", weight=45,
                                    description="Digital signature is broken: the file was modified after it was signed",
                                    attack=["T1036"], details=st)])
        opts = ctx["options"]
        use_def = engine.settings.use_defender if opts.defender is None else opts.defender
        if IS_WINDOWS and use_def:
            defender = broker.use("detect.defender")
            if defender.available:
                ctx["progress"].phase = "defender"
                budget = engine.settings.defender_max_files
                for d in sorted(em, key=lambda x: -score_evidence(x.evidence)[0]):
                    if budget <= 0:
                        break
                    if d.target_type != "file" or not d.path or not os.path.isfile(d.path):
                        continue
                    if any(e.verdict == Verdict.MALICIOUS.value for e in d.evidence) or score_evidence(d.evidence)[0] < 0.25:
                        continue
                    budget -= 1
                    out["defender_checked"] += 1
                    ev = defender.scan_file(d.path)
                    if ev:
                        d.add([ev])
                        if ev.verdict == Verdict.MALICIOUS.value:
                            out["defender_hits"] += 1
        return out


# ---------------------------------------------------------------------------------------------- 3
class BehavioralAnalystAgent(Agent):
    def __init__(self):
        super().__init__("behavioral_analyst", "Behavioural Analysis Agent",
                         "Inspects running processes, network activity, hosts-file tampering, ransomware patterns and Defender history.",
                         frozenset({"proc.read", "net.read", "fs.analyze", "evidence.write", "detect.defender"}),
                         "live system state + ransomware tracker", "process/network/directory drafts")

    def run(self, broker: ToolBroker, ctx: dict[str, Any]) -> dict[str, Any]:
        em = broker.use("evidence.write")
        analyzer = broker.use("fs.analyze")
        out: dict[str, Any] = {}
        ctx["progress"].phase = "behavior"
        procs_mod = broker.use("proc.read")
        procs, pstats = procs_mod.inspect_processes()
        out["processes"] = pstats
        analysed_exes: set[str] = set()
        running_exes: dict[str, list[int]] = defaultdict(list)
        for p in procs:
            if p.exe:
                running_exes[os.path.normcase(p.exe)].append(p.pid)
            if not p.evidence:
                continue
            sha = size = None
            ev = list(p.evidence)
            if p.exe and p.exe not in analysed_exes and os.path.isfile(p.exe):
                analysed_exes.add(p.exe)
                fa = analyzer.analyze_path(p.exe)
                sha, size = fa.record.sha256, fa.record.size
                ev += [e for e in fa.evidence if e.weight > 0 or e.verdict == Verdict.MALICIOUS.value]
            d = Draft("process", f"{p.name} (PID {p.pid})", path=p.exe, sha256=sha, size=size,
                      protected=protected_reason(p.exe) if p.exe else None,
                      data={"pid": p.pid, "cmdline": p.cmdline[:1000], "parent": p.parent_name, "user": p.username,
                            "started": ts_to_iso(p.create_time)})
            em.add(d, ev)
        ctx["running_exes"] = running_exes
        net = broker.use("net.read")
        conns, exposed, nstats = net.inspect_network()
        out["network"] = nstats
        ctx["exposed_services"] = exposed
        ctx["public_remote_ips"] = sorted({c.raddr.split(":")[0] for c in conns if c.raddr})[:50]
        for c in conns:
            em.add(Draft("network", f"{c.process or 'unknown'} → {c.raddr}", path=c.exe,
                         data={"pid": c.pid, "local": c.laddr, "remote": c.raddr, "status": c.status}), c.evidence)
        hosts_ev = net.inspect_hosts_file()
        if hosts_ev:
            em.add(Draft("configuration", "hosts file", data={"title": "Hosts file redirects or blocks security/update websites",
                                                               "severity": "high", "category": "suspicious_behavior",
                                                               "repair_step": "win.manual_hosts" if IS_WINDOWS else None}), hosts_ev)
        tracker = ctx.get("ransomware")
        rcount = 0
        if tracker is not None:
            for directory, ev, data in tracker.findings():
                rcount += 1
                em.add(Draft("directory", directory, path=directory, data={"title": f"Possible ransomware activity in {directory}", **data}), ev)
        out["ransomware_clusters"] = rcount
        if IS_WINDOWS and ctx["options"].kind in ("full", "quick"):
            from ..malware.defender import defender_detections

            dets, err = defender_detections()
            hist = []
            for det in dets or []:
                for res in det.get("Resources") or []:
                    path = str(res).split("_", 1)[1] if str(res).lower().startswith("file:_") else None
                    hist.append({"threat": det.get("ThreatName"), "resource": str(res)[:300], "detected": det.get("Detected"),
                                 "handled": det.get("ActionSuccess"), "still_present": bool(path and os.path.exists(path))})
                    if path and os.path.isfile(path):
                        fa = analyzer.analyze_path(path)
                        d = _file_draft(fa)
                        em.add(d, [Evidence(engine="defender", rule=str(det.get("ThreatName") or "defender.detection"),
                                            verdict=Verdict.MALICIOUS.value, weight=95,
                                            description=f"Microsoft Defender previously detected {det.get('ThreatName')} here and the file is still present",
                                            provenance=f"Defender detection history, {det.get('Detected')}")])
            ctx["stats"]["defender_history"] = hist[:100]
            if err:
                ctx["stats"].setdefault("notes", []).append(f"Defender history unavailable: {err[:120]}")
        return out


# ---------------------------------------------------------------------------------------------- 4
class PersistenceAnalystAgent(Agent):
    def __init__(self):
        super().__init__("persistence_analyst", "Persistence Detection Agent",
                         "Enumerates startup/persistence mechanisms and evaluates the programs they launch.",
                         frozenset({"persist.read", "fs.analyze", "authenticode.read", "evidence.write"}),
                         "OS startup locations", "persistence drafts")

    def run(self, broker: ToolBroker, ctx: dict[str, Any]) -> dict[str, Any]:
        em = broker.use("evidence.write")
        analyzer = broker.use("fs.analyze")
        pers = broker.use("persist.read")
        ctx["progress"].phase = "persistence"
        entries, errors = pers.enumerate_persistence()
        windir = os.environ.get("SystemRoot", r"C:\Windows").lower()
        evaluated = [(entry, pers.evaluate(entry)) for entry in entries]
        # analyse each distinct launched program once, in parallel (OS binaries only when the entry itself is suspicious)
        targets = sorted({e.target_path for e, ev in evaluated if e.target_path and os.path.isfile(e.target_path)
                          and not (IS_WINDOWS and e.target_path.lower().startswith(windir) and not any(x.weight > 0 for x in ev))})
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=8, thread_name_prefix="sentry-persist") as pool:
            analyses = dict(zip(targets, pool.map(analyzer.analyze_path, targets)))
        candidates = []
        for entry, ev in evaluated:
            tp = entry.target_path
            fa = analyses.get(tp) if tp else None
            file_ev = [e for e in (fa.evidence if fa else []) if (e.weight > 0 or e.verdict == Verdict.MALICIOUS.value)
                       and e.rule != "location.high_risk"]
            if file_ev:
                em.add(_file_draft(fa))
            all_ev = ev + [Evidence(engine=e.engine, rule=e.rule, weight=e.weight, verdict=e.verdict, source=e.source,
                                    description=f"Launched program: {e.description}", attack=e.attack, details=e.details,
                                    provenance=e.provenance) for e in file_ev]
            if any(e.weight > 0 for e in all_ev):
                candidates.append((entry, all_ev, fa.record.sha256 if fa else None))
        sigs: dict[str, dict] = {}
        if IS_WINDOWS:
            from ..malware.pe_analysis import authenticode_batch

            broker.use("authenticode.read")
            sigs = authenticode_batch([e.target_path for e, ev, _ in candidates
                                       if e.target_path and not any(x.verdict == Verdict.MALICIOUS.value for x in ev)])
        for entry, all_ev, sha in candidates:
            st = sigs.get(entry.target_path or "")
            if st and st.get("status") == "Valid":
                all_ev.append(Evidence(engine="authenticode", rule="authenticode.valid", weight=0, verdict=Verdict.CLEAN.value,
                                       description=f"Launched program has a valid signature: {(st.get('subject') or '')[:100]}",
                                       details=st))
            d = Draft("persistence", f"{entry.mechanism}: {entry.name}", path=entry.target_path, sha256=sha,
                      data={"persistence": entry.to_dict(), "mechanism": entry.mechanism, "location": entry.location,
                            "command": entry.command[:1000]})
            em.add(d, all_ev)
        ctx["stats"]["persistence"] = {"entries": len(entries), "flagged": len(candidates), "programs_analysed": len(targets),
                                       "errors": errors}
        return {"entries": len(entries), "flagged": len(candidates), "programs_analysed": len(targets), "errors": errors[:10]}


# ---------------------------------------------------------------------------------------------- 5
class VulnerabilityAnalystAgent(Agent):
    def __init__(self, online: bool):
        caps = {"config.read", "net.read", "vuln.deps", "vuln.tools", "evidence.write"}
        super().__init__("vulnerability_analyst", "Vulnerability Analysis Agent",
                         "Finds configuration weaknesses, exposed services and vulnerable dependencies (separate from malware).",
                         frozenset(caps | ({"intel.online"} if online else set())),
                         "config, listeners, lockfiles", "configuration / package drafts")
        self.online = online

    def run(self, broker: ToolBroker, ctx: dict[str, Any]) -> dict[str, Any]:
        em = broker.use("evidence.write")
        ctx["progress"].phase = "vulnerability"
        cfg = broker.use("config.read")
        issues, notes = cfg.run_config_checks()
        for i in issues:
            em.add(Draft("configuration", i.check_id + ("" if "exclusion" not in i.check_id else ":" + str(i.details.get("value"))),
                         data={"title": i.title, "severity": i.severity, "repair_step": i.repair_step, "check_id": i.check_id,
                               "category": i.category, **i.details}), [i.evidence()])
        for svc in ctx.get("exposed_services") or []:
            port = svc["port"]
            if IS_WINDOWS and port in (135, 139, 445, 5985):
                continue  # standard Windows listeners; firewall state is checked separately
            sev = "high" if port in (23, 2375, 6379, 11211, 9200, 27017) else "medium"
            em.add(Draft("configuration", f"exposed:{port}", data={
                "title": f"{svc['service']} (port {port}) is reachable from the network", "severity": sev,
                "process": svc.get("process"), "repair_step": None}),
                [Evidence(engine="vulnerability", rule="exposure.listener", weight=60,
                          description=f"{svc['service']} listens on all interfaces ({svc['address']}:{port}) via {svc.get('process') or 'unknown process'}")])
        deps = broker.use("vuln.deps")
        packages = []
        for lf in ctx.get("lockfiles") or []:
            packages += deps.parse_lockfile(lf)
        vulns: list[dict] = []
        osv_note = None
        if packages and self.online:
            try:
                vulns = deps.query_osv(packages, broker.engine.store, broker.engine.settings.intel_cache_ttl_seconds)
            except Exception as exc:
                osv_note = f"OSV query failed: {exc}"
        elif packages:
            osv_note = "Dependency vulnerability lookup skipped (offline mode; enable online intelligence to query OSV.dev)"
        tools = broker.use("vuln.tools")
        if ctx["options"].kind == "custom":
            for root in ctx.get("roots") or []:
                if os.path.isdir(root):
                    for runner in (tools.run_osv_scanner, tools.run_trivy):
                        found, err = runner(root)
                        vulns += found
        seen = set()
        for v in vulns:
            key = (v.get("package"), v.get("version"), v.get("id"))
            if key in seen:
                continue
            seen.add(key)
            fixed = f" Fixed in: {', '.join(v['fixed'])}." if v.get("fixed") else ""
            em.add(Draft("package", f"{v['package']}@{v['version']} ({v['id']})", path=v.get("source"),
                         data={"title": f"Vulnerable dependency {v['package']} {v['version']}: {v['id']}", "severity": v.get("severity", "medium"),
                               "advisory": v.get("url"), "aliases": v.get("aliases"), "ecosystem": v.get("ecosystem"), "fixed": v.get("fixed")}),
                   [Evidence(engine=v.get("tool", "osv"), rule=v["id"], weight=70, source="osv.dev" if not v.get("tool") else v["tool"],
                             description=(v.get("summary") or v["id"]) + fixed, details={"url": v.get("url")},
                             provenance=f"{v.get('tool', 'OSV.dev')} advisory {v['id']}")])
        if osv_note:
            ctx["stats"].setdefault("notes", []).append(osv_note)
        ctx["stats"].setdefault("notes", []).extend(notes)
        return {"config_issues": len(issues), "packages": len(packages), "vulnerabilities": len(seen), "notes": notes[:5]}


# ---------------------------------------------------------------------------------------------- 6
class ForensicsAnalystAgent(Agent):
    def __init__(self):
        super().__init__("forensics_analyst", "Digital Forensics Agent",
                         "Correlates files, processes, persistence and network activity; builds a timeline.",
                         frozenset({"evidence.write"}), "all drafts", "correlations, timeline")

    def run(self, broker: ToolBroker, ctx: dict[str, Any]) -> dict[str, Any]:
        em = broker.use("evidence.write")
        ctx["progress"].phase = "forensics"
        files = {os.path.normcase(d.path): d for d in em if d.target_type == "file" and d.path}
        links = 0
        for d in em:
            if d.target_type in ("persistence", "process", "network") and d.path:
                f = files.get(os.path.normcase(d.path))
                if f is not None and score_evidence(f.evidence)[0] >= 0.25:
                    links += 1
                    d.data.setdefault("related", []).append(f.key)
                    f.data.setdefault("related", []).append(d.key)
                    rel = {"persistence": "is started automatically by a startup entry",
                           "process": "is currently running", "network": "is communicating over the network"}[d.target_type]
                    f.add([Evidence(engine="forensics", rule=f"correlation.{d.target_type}", weight=20,
                                    description=f"This file {rel} ({d.target[:80]})")])
        running = ctx.get("running_exes") or {}
        for key, f in files.items():
            if key in running and score_evidence(f.evidence)[0] >= 0.25:
                f.data["running_pids"] = running[key][:10]
        # files dropped together: several suspicious files in one folder within 10 minutes
        by_dir: dict[str, list[Draft]] = defaultdict(list)
        for f in files.values():
            if score_evidence(f.evidence)[0] >= 0.25 and f.data.get("mtime"):
                by_dir[os.path.dirname(f.path)].append(f)
        clusters = 0
        from ..util import parse_iso

        for directory, group in by_dir.items():
            if len(group) < 3:
                continue
            times = sorted(parse_iso(g.data["mtime"]).timestamp() for g in group)
            if times[-1] - times[0] <= 600:
                clusters += 1
                for g in group:
                    g.add([Evidence(engine="forensics", rule="correlation.dropped_together", weight=15,
                                    description=f"{len(group)} suspicious files were written to the same folder within 10 minutes")])
        timeline = []
        for d in em:
            if score_evidence(d.evidence)[0] < 0.25 and not any(e.verdict == Verdict.MALICIOUS.value for e in d.evidence):
                continue
            when = d.data.get("mtime") or d.data.get("started")
            if when:
                timeline.append({"time": when, "event": f"{d.target_type}: {d.target[:120]}",
                                 "kind": "modified" if d.data.get("mtime") else "started"})
        timeline.sort(key=lambda x: x["time"])
        ctx["stats"]["timeline"] = timeline[-200:]
        return {"links": links, "drop_clusters": clusters, "timeline_events": len(timeline)}


# ---------------------------------------------------------------------------------------------- 7
class ThreatIntelAgent(Agent):
    def __init__(self, online: bool):
        super().__init__("threat_intel_analyst", "Threat Intelligence Agent",
                         "Looks up hashes and remote hosts in external intelligence (opt-in), with provenance and rate limits.",
                         frozenset({"evidence.write"} | ({"intel.online"} if online else set())),
                         "suspicious hashes and remote IPs", "intel evidence")
        self.online = online

    def run(self, broker: ToolBroker, ctx: dict[str, Any]) -> dict[str, Any]:
        em = broker.use("evidence.write")
        if not self.online:
            return {"skipped": "offline mode"}
        ctx["progress"].phase = "threat_intelligence"
        intel = broker.use("intel.online")
        out = {"vt": 0, "malwarebazaar": 0, "urlhaus": 0, "errors": []}
        cands = sorted((d for d in em if d.sha256 and d.target_type in ("file", "process", "persistence")),
                       key=lambda d: -score_evidence(d.evidence)[0])
        mb_budget, vt_budget = 100, 8
        for d in cands:
            if any(e.engine in ("virustotal", "malwarebazaar") for e in d.evidence):
                continue
            try:
                if mb_budget > 0 and intel.abuse_key:
                    mb_budget -= 1
                    ev = intel.malwarebazaar_hash(d.sha256)
                    out["malwarebazaar"] += 1
                    if ev:
                        d.add([ev])
                if vt_budget > 0 and intel.vt_key and score_evidence(d.evidence)[0] >= 0.25:
                    vt_budget -= 1
                    ev = intel.virustotal_hash(d.sha256)
                    out["vt"] += 1
                    if ev:
                        d.add([ev])
            except Exception as exc:
                out["errors"].append(str(exc)[:120])
        for ip in (ctx.get("public_remote_ips") or [])[:20]:
            try:
                ev = intel.urlhaus_host(ip)
                out["urlhaus"] += 1
                if ev:
                    em.add(Draft("network", f"remote host {ip}", data={"remote": ip}), [ev])
            except Exception as exc:
                out["errors"].append(str(exc)[:120])
        out["errors"] = out["errors"][:5]
        return out


# ---------------------------------------------------------------------------------------------- 8
class RemediationPlannerAgent(Agent):
    def __init__(self):
        super().__init__("remediation_planner", "Remediation Planning Agent",
                         "Proposes (never executes) remediation: actions per finding, repair steps and manual guidance.",
                         frozenset({"plan.write", "store.read"}), "classified findings", "remediation plan")

    def run(self, broker: ToolBroker, ctx: dict[str, Any]) -> dict[str, Any]:
        repair = broker.use("plan.write")
        findings = ctx.get("findings") or []
        linked = [f.data.get("repair_step") for f in findings if f.data.get("repair_step")]
        steps = repair.plan(linked)
        actions = []
        for f in findings:
            if f.category == "false_positive":
                continue
            actions.append({"finding_id": f.id, "title": f.title, "severity": f.severity, "recommended": f.recommended_action,
                            "allowed_actions": f.allowed_actions})
        cats = {f.category for f in findings}
        # only credible findings drive drastic recommendations (not low-confidence/unverified ones)
        attack = {t for f in findings if f.category in ("confirmed_malware", "suspected_malware") and not f.data.get("test_file")
                  for t in f.attack}
        manual = []
        confirmed = [f for f in findings if f.category == "confirmed_malware" and not f.data.get("test_file")]
        if confirmed or attack & {"T1003", "T1003.001", "T1056.001", "T1555.003"}:
            manual.append("any.manual_credentials")
        if any(f.target_type == "persistence" and f.category == "confirmed_malware" for f in findings) or "T1014" in attack:
            manual.append("win.manual_offline_scan" if IS_WINDOWS else "linux.manual_offline")
        if sum(1 for f in confirmed if f.severity == "critical") >= 3:
            manual.append("any.manual_clean_install")
        plan = {"actions": actions, "repair_steps": [s.to_dict() for s in steps],
                "manual_recommendations": [repair.get_step(m).to_dict() for m in manual if repair.get_step(m)],
                "summary": {"findings": len(findings), "categories": sorted(cats)}}
        ctx["stats"]["remediation_plan"] = plan
        return {"actions": len(actions), "repair_steps": len(steps), "manual": manual}


# ---------------------------------------------------------------------------------------------- 9
class RecoveryAgent(Agent):
    def __init__(self):
        super().__init__("recovery_agent", "Recovery Agent",
                         "Assesses recovery options (backups, restore points, rollback records) and proposes validated restoration.",
                         frozenset({"recovery.inspect", "store.read"}), "findings", "recovery assessment")

    def run(self, broker: ToolBroker, ctx: dict[str, Any]) -> dict[str, Any]:
        from ..util import is_admin, run_command, run_powershell

        rec = broker.use("recovery.inspect")
        findings = ctx.get("findings") or []
        ransomware = any("T1486" in f.attack for f in findings)
        options: list[dict[str, Any]] = []
        if IS_WINDOWS:
            if is_admin():
                rc, out, _ = run_powershell("@(Get-ComputerRestorePoint | Select-Object -Last 3 Description,CreationTime) | ConvertTo-Json -Compress", 60)
                options.append({"source": "System Restore", "available": rc == 0 and out.strip() not in ("", "[]"), "detail": out.strip()[:300]})
            else:
                options.append({"source": "System Restore", "available": None, "detail": "requires an elevated terminal to inspect"})
            od = os.environ.get("OneDrive")
            options.append({"source": "OneDrive (version history / Recycle Bin)", "available": bool(od and os.path.isdir(od)), "detail": od or ""})
        elif os.path.isdir("/timeshift"):
            options.append({"source": "Timeshift snapshots", "available": True, "detail": "/timeshift"})
        elif os.path.exists("/usr/bin/tmutil"):
            rc, out, _ = run_command(["tmutil", "latestbackup"], timeout=30)
            options.append({"source": "Time Machine", "available": rc == 0 and bool(out.strip()), "detail": out.strip()[:200]})
        records = rec.list(active_only=True)
        assessment = {"ransomware_suspected": ransomware, "backup_options": options, "rollback_records": len(records),
                      "advice": ("Do not pay a ransom. Isolate the machine from the network, keep encrypted files (decryptors sometimes "
                                 "appear later, see nomoreransom.org), remove the malware first, then restore from an offline backup."
                                 if ransomware else "Quarantined items can be restored and persistence removals rolled back from their recovery records.")}
        ctx["stats"]["recovery"] = assessment
        return {"options": len(options), "ransomware": ransomware}


# ---------------------------------------------------------------------------------------------- 10
class VerificationAgent(Agent):
    def __init__(self):
        super().__init__("verification_agent", "Verification Agent",
                         "Independently re-checks remediated findings and rescans affected folders; never trusts the executor's word.",
                         frozenset({"verify.read", "fs.analyze", "store.read"}), "remediated findings", "verification report")

    def run(self, broker: ToolBroker, ctx: dict[str, Any]) -> dict[str, Any]:
        v = broker.use("verify.read")
        store = broker.use("store.read")
        analyzer = broker.use("fs.analyze")
        engine = broker.engine
        scan_id = ctx["scan_id"]
        results = []
        dirs: set[str] = set()
        for f in store.list_findings(scan_id):
            item = f.data.get("quarantine_item")
            if item:
                q = engine.vault.store_item(item)
                if q and q["status"] == "quarantined":
                    r = v.verify_quarantine(engine, item, q["original_path"], q["sha256"])
                elif q and q["status"] == "deleted":
                    r = v.verify_deleted(engine, item)
                else:
                    r = {"verified": q is not None and q["status"] == "restored", "checks": [{"check": "item state", "ok": True, "detail": q["status"] if q else "missing"}]}
                results.append({"finding_id": f.id, "action": f.data.get("remediation"), **r})
                if f.path:
                    dirs.add(os.path.dirname(f.path))
            elif f.data.get("recovery_record") and f.data.get("persistence"):
                r = v.verify_persistence_removed(engine, f.data["persistence"])
                results.append({"finding_id": f.id, "action": f.data.get("remediation"), **r})
        reappeared = []
        for d in sorted(dirs)[:50]:
            try:
                names = os.listdir(d)
            except OSError:
                continue
            for n in names[:2000]:
                p = os.path.join(d, n)
                if os.path.isfile(p):
                    fa = analyzer.analyze(_entry(p))
                    if any(e.verdict == Verdict.MALICIOUS.value for e in fa.evidence) or score_evidence(fa.evidence)[0] >= 0.5:
                        reappeared.append({"path": p, "sha256": fa.record.sha256})
        ok = all(r["verified"] for r in results) and not reappeared
        report = {"verified": ok, "results": results, "rescanned_folders": len(dirs), "new_or_remaining_threats": reappeared[:50]}
        return report


def _entry(path: str):
    from ..filesystem.walker import WalkEntry

    st = os.lstat(path)
    return WalkEntry(path, st.st_size, st.st_mtime, st.st_ctime, st.st_mode, os.path.basename(path).startswith("."))


def all_agent_definitions(online: bool = False) -> list[Agent]:
    return [ScanCoordinatorAgent(), MalwareAnalystAgent(), BehavioralAnalystAgent(), PersistenceAnalystAgent(),
            VulnerabilityAnalystAgent(online), ForensicsAnalystAgent(), ThreatIntelAgent(online), RemediationPlannerAgent(),
            RecoveryAgent(), VerificationAgent()]
