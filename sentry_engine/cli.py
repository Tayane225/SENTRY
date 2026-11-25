"""SENTRY command-line interface.

Commands that create authority (init, approve, quarantine restore/delete, repair run,
recovery rollback, intel upload) are HUMAN-ONLY: they require an interactive
terminal and read the approver passphrase with getpass. They never accept a
passphrase from arguments, environment variables or piped stdin.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
from typing import Any

from . import service
from .util import IS_WINDOWS, human_bytes, sanitize
from .version import PRODUCT, SLOGAN, TAGLINE, __version__

SEV_ICON = {"critical": "✖", "high": "▲", "medium": "◆", "low": "•", "info": "·"}


# ---------------------------------------------------------------------------------------------- terminal helpers

def _enable_vt() -> bool:
    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return False
    if IS_WINDOWS:
        try:
            import ctypes

            k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            h = k32.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if k32.GetConsoleMode(h, ctypes.byref(mode)):
                k32.SetConsoleMode(h, mode.value | 0x0004)
        except Exception:
            return False
    return True


COLOR = False
_C = {"red": "31", "yellow": "33", "green": "32", "blue": "34", "cyan": "36", "bold": "1", "dim": "2", "magenta": "35"}
SEV_COLOR = {"critical": "red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}


def c(text: str, color: str) -> str:
    return f"\033[{_C[color]}m{text}\033[0m" if COLOR else text


def _configure_stdout() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass


def is_interactive_human() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def require_human(what: str) -> None:
    if not is_interactive_human():
        print(f"Refused: '{what}' must be run by a human in an interactive terminal. "
              "AI agents and scripts cannot approve or authorise SENTRY actions.", file=sys.stderr)
        raise SystemExit(3)


def out_json(data: Any) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False, default=str))


def banner() -> None:
    print(c(f"{PRODUCT} {__version__}", "bold") + c(f" — {SLOGAN}. {TAGLINE}", "cyan"))


def _engine(args):
    from .engine import Engine

    return Engine(getattr(args, "home", None))


def _resolve_scan(engine, scan_id: str | None) -> str:
    sid = scan_id or engine.store.latest_scan_id()
    if not sid:
        print("No scans yet. Run `sentry scan quick` first.", file=sys.stderr)
        raise SystemExit(2)
    return sid


def _parse_selection(text: str, n: int) -> list[int]:
    text = text.strip().lower()
    if text in ("all", "*"):
        return list(range(1, n + 1))
    if text in ("", "none", "n", "q"):
        return []
    picked: set[int] = set()
    for part in text.replace(" ", "").split(","):
        if "-" in part:
            a, b = part.split("-", 1)
            if a.isdigit() and b.isdigit():
                picked.update(range(int(a), int(b) + 1))
        elif part.isdigit():
            picked.add(int(part))
    return sorted(i for i in picked if 1 <= i <= n)


def _print_finding(i: int | None, f: dict[str, Any], verbose: bool = True) -> None:
    sev = f["severity"]
    head = (f"[{i}] " if i is not None else "") + c(f"{SEV_ICON.get(sev, '•')} {sev.upper():8}", SEV_COLOR.get(sev, "dim"))
    print(f" {head} {c(f['category_label'], 'bold')}  {f['id']}")
    print(f"      {f['title']}")
    print(c(f"      {f.get('path') or f['target']}", "dim"))
    if verbose:
        print(f"      Why: {f['explanation']}")
        if f["potential_damage"]:
            print(f"      Danger: {'; '.join(f['potential_damage'])}")
        print(f"      Confidence: {f['confidence_label']} ({f['confidence']:.2f}) · engines: {', '.join(f['detection_engines']) or '-'}")
        for lim in f.get("limitations") or []:
            print(c(f"      ⚠ {lim}", "yellow"))
        print(f"      Recommended: {f['recommended_action']}  [allowed: {', '.join(f['allowed_actions']) or 'none'}]  status: {f['status']}")
    print()


# ---------------------------------------------------------------------------------------------- commands

def cmd_init(args) -> int:
    require_human("sentry init")
    engine = _engine(args)
    banner()
    if engine.keystore.is_configured() and not args.change_passphrase:
        print(f"Approver already configured (fingerprint {engine.keystore.fingerprint()}).")
        print("Use `sentry init --change-passphrase` to change it.")
        return 0
    if args.change_passphrase:
        old = getpass.getpass("Current approver passphrase: ")
        new = getpass.getpass("New approver passphrase (min 10 chars): ")
        if new != getpass.getpass("Repeat new passphrase: "):
            print("Passphrases differ.")
            return 1
        engine.keystore.change_passphrase(old, new)
        engine.audit.append("approver.passphrase_changed", "human", {"fingerprint": engine.keystore.fingerprint()})
        print("Passphrase changed.")
        return 0
    print("Create your APPROVER PASSPHRASE. Only a person who knows it can approve quarantine, deletion or repair.")
    print(c("Never type it into an AI chat and never give it to an AI agent.", "yellow"))
    p1 = getpass.getpass("Approver passphrase (min 10 chars): ")
    if p1 != getpass.getpass("Repeat passphrase: "):
        print("Passphrases differ.")
        return 1
    fp = engine.keystore.create(p1)
    engine.pin_approver(fp)
    engine.audit.append("approver.created", "human", {"fingerprint": fp})
    print(c(f"Approver key created. Fingerprint: {fp}", "green"))
    return 0


def cmd_doctor(args) -> int:
    engine = _engine(args)
    st = service.doctor(engine)
    if args.json:
        out_json(st)
        return 0
    banner()
    print(f"Platform: {st['platform']}  ·  elevated: {st['admin']}  ·  data: {st['home']}")
    print(f"Approver configured: {st['approver_configured']}" + (f" (fingerprint {st['approver_fingerprint']})" if st['approver_fingerprint'] else ""))
    for name, info in st["engines"].items():
        ok = info.get("available", info.get("enabled"))
        print(f"  {c('✔', 'green') if ok else c('✘', 'red')} {name:13} {json.dumps({k: v for k, v in info.items() if k not in ('rule_files',)}, default=str)[:160]}")
    for a in st["advice"]:
        print(c(f"  → {a}", "yellow"))
    return 0


def cmd_drives(args) -> int:
    engine = _engine(args)
    d = service.drives(engine)
    if args.json:
        out_json(d)
        return 0
    for x in d:
        u = x["usage"] or {}
        print(f"{x['mountpoint']:<20} {x['fstype']:<8} {x['kind']:<10} {human_bytes(u.get('used', 0)):>10} / {human_bytes(u.get('total', 0)):<10}"
              f" full-scan: {'yes' if x['authorized_for_full_scan'] else 'no'}")
    return 0


def cmd_scan(args) -> int:
    engine = _engine(args)
    if not args.json:
        banner()
    last = [0.0]

    def on_progress(p) -> None:
        if args.json or not sys.stdout.isatty() or time.time() - last[0] < 0.5:
            return
        last[0] = time.time()
        line = (f"\r[{p.phase:<12}] {p.files_scanned:>9,} files · {human_bytes(p.bytes_scanned):>9} · "
                f"workers {p.active_workers}/{p.worker_limit} (max {p.max_workers}) · CPU {p.cpu:4.0f}% RAM {p.ram:3.0f}% · flagged {p.flagged}")
        sys.stdout.write(line[:150].ljust(150))
        sys.stdout.flush()

    res = service.start_scan(engine, args.kind, args.paths, background=False, requested_by=args.requested_by,
                             workers=args.workers, max_workers=args.max_workers, online_intel=True if args.online else None,
                             behavior=not args.no_behavior, persistence=not args.no_persistence,
                             vulnerabilities=not args.no_vuln, include_archives=not args.no_archives,
                             defender=False if args.no_defender else None, on_progress=on_progress)
    sid = res["scan_id"]
    rep = service.report(engine, sid, args.report or "md")
    html = service.report(engine, sid, "html")
    if args.json:
        out_json({"scan_id": sid, "status": res["status"], "statistics": res["statistics"],
                  "report_markdown": rep["path"], "report_html": html["path"],
                  "findings": service.findings(engine, sid), "next_step": service.approval_instructions(engine, sid)})
        return 0
    print()
    st = res["statistics"]
    print(c(f"\nScan {sid} {res['status']}", "bold") + f" — {st.get('files_scanned', 0):,} files, {human_bytes(st.get('bytes_scanned', 0))}, "
          f"{st.get('elapsed_s', 0)} s, {st.get('findings_total', 0)} finding(s)")
    for f in service.findings(engine, sid):
        _print_finding(None, f, verbose=False)
    for n in st.get("notes") or []:
        print(c(f"note: {n}", "yellow"))
    print(f"\nReport: {rep['path']}\nHTML:   {html['path']}")
    if st.get("findings_total"):
        print(c(f"\nNothing has been removed. Review the findings, then approve the ones you choose:  sentry approve {sid}", "cyan"))
    return 0


def cmd_status(args) -> int:
    engine = _engine(args)
    out_json(service.scan_status(engine, _resolve_scan(engine, args.scan_id)))
    return 0


def cmd_scans(args) -> int:
    engine = _engine(args)
    rows = service.list_scans(engine, args.limit)
    if args.json:
        out_json(rows)
        return 0
    for r in rows:
        print(f"{r['scan_id']}  {r['kind']:<6} {r['status']:<11} {r['started_at']}  files={r['files_scanned']}  findings={r['findings']}")
    return 0


def cmd_findings(args) -> int:
    engine = _engine(args)
    sid = _resolve_scan(engine, args.scan_id)
    rows = service.findings(engine, sid, args.min_severity, args.category)
    if args.json:
        out_json({"scan_id": sid, "untrusted_content": True, "findings": rows})
        return 0
    print(f"Scan {sid}: {len(rows)} finding(s)\n")
    for i, f in enumerate(rows, 1):
        _print_finding(i, f)
    return 0


def cmd_show(args) -> int:
    engine = _engine(args)
    f = service.finding(engine, args.finding_id)
    if args.json:
        out_json(f)
    else:
        _print_finding(None, f)
        for ev in f["evidence"]:
            print(f"   - [{ev['engine']}] {ev['rule']} (w={ev['weight']}, {ev['verdict']}): {ev['description']}")
        for n in f.get("ai_notes") or []:
            print(f"   🤖 {n['author']} @ {n['created_at']}: {n['text']}")
    return 0


def cmd_report(args) -> int:
    engine = _engine(args)
    sid = _resolve_scan(engine, args.scan_id)
    res = service.report(engine, sid, args.format)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(res["content"])
        print(args.out)
    elif args.print:
        print(res["content"])
    else:
        print(res["path"])
    return 0


def cmd_annotate(args) -> int:
    engine = _engine(args)
    out_json(service.annotate(engine, args.finding_id, args.author, args.text))
    return 0


def _collect_passphrase() -> str:
    return getpass.getpass(c("Approver passphrase: ", "bold"))


def _approve_and_maybe_execute(engine, requests: list[dict[str, Any]], args, scan_id: str | None) -> int:
    try:
        issued = service.issue_approvals(engine, _collect_passphrase(), requests, via="cli-tty", ttl_seconds=args.ttl)
    except Exception as exc:
        print(c(f"Approval refused: {exc}", "red"))
        return 4
    for a in issued:
        print(c(f"  ✅ {a['approval_id']}: {a['action'].upper()} {a['subject_id']}", "green") + f"  (single use, expires {a['expires_at']})")
    execute = args.execute
    if execute is None:
        execute = input("Execute the approved action(s) now? [Y/n] ").strip().lower() in ("", "y", "yes")
    if not execute:
        print(f"Approved but not executed. Run `sentry remediate{(' ' + scan_id) if scan_id else ''}` (or let your AI agent do it) before they expire.")
        return 0
    total_ok = True
    for a in issued:
        res = service.execute_approved(engine, approval_id=a["approval_id"], actor="human", verify_after=False)
        for r in res["executed"]:
            ok = r["status"] == "succeeded"
            total_ok &= ok
            print((c("  ✔ ", "green") if ok else c("  ✘ ", "red")) + f"{r.get('action', '')} → {r['status']}: {r.get('detail', '')}")
            for chk in (r.get("verification") or {}).get("checks", []):
                print(f"      {'✔' if chk['ok'] else '✘'} {chk['check']}: {chk['detail']}")
    if scan_id:
        v = service.verify(engine, scan_id)
        print(c(f"Verification: {'PASSED' if v.get('verified') else 'NOT fully verified'}", "green" if v.get("verified") else "yellow"))
    return 0 if total_ok else 5


def cmd_approve(args) -> int:
    require_human("sentry approve")
    engine = _engine(args)
    banner()
    if not engine.keystore.is_configured():
        print("No approver configured. Run `sentry init` first.")
        return 2
    if args.quarantine_item:
        action = args.action or "restore"
        if action not in ("restore", "delete"):
            print("Quarantine items support --action restore or delete.")
            return 2
        items = [q for q in service.quarantine_list(engine) if q["id"] == args.quarantine_item]
        if not items:
            print("Unknown or no longer quarantined item.")
            return 2
        q = items[0]
        print(f"{action.upper()} quarantined item {q['id']}: {q['original_path']}")
        if action == "delete":
            print(c("Permanent deletion cannot be undone.", "red"))
        if input("Type YES to continue: ").strip() != "YES":
            return 1
        return _approve_and_maybe_execute(engine, [{"subject_type": "quarantine_item", "subject_id": q["id"], "action": action}], args, None)
    if args.repair_step:
        step = engine.repair_step(args.repair_step)
        if not step or step["manual"]:
            print("Unknown or manual-only repair step. See `sentry repair plan`.")
            return 2
        print(f"REPAIR: {step['title']}\n  command: {step['command']}\n  admin: {step['requires_admin']}  reboot: {step['reboot_required']}")
        if input("Type YES to approve this repair: ").strip() != "YES":
            return 1
        return _approve_and_maybe_execute(engine, [{"subject_type": "repair_step", "subject_id": step["id"], "action": "repair"}], args, None)
    if args.rollback:
        print(f"ROLLBACK recovery record {args.rollback} (re-enables what was removed).")
        if input("Type YES to approve: ").strip() != "YES":
            return 1
        return _approve_and_maybe_execute(engine, [{"subject_type": "recovery_record", "subject_id": args.rollback, "action": "rollback"}], args, None)

    sid = _resolve_scan(engine, args.scan_id)
    rows = [f for f in service.findings(engine, sid) if f["allowed_actions"] and f["status"] in ("open", "failed", "approved")]
    if not rows:
        print("No findings awaiting a decision in this scan.")
        return 0
    print(c(f"Scan {sid}: {len(rows)} finding(s) awaiting your decision. Nothing happens without your approval.\n", "bold"))
    for i, f in enumerate(rows, 1):
        _print_finding(i, f)
    if args.findings:
        wanted = rows if args.findings.strip().lower() == "all" else [f for f in rows if f["id"] in {x.strip() for x in args.findings.split(",")}]
        picked = [rows.index(f) + 1 for f in wanted]
    else:
        picked = _parse_selection(input("Tick findings to act on (e.g. 1,3,5-7 | all | none): "), len(rows))
    if not picked:
        print("Nothing selected. No action taken.")
        return 0
    requests = []
    for i in picked:
        f = rows[i - 1]
        default = args.action or ("remove_persistence" if "remove_persistence" in f["allowed_actions"] else
                                  "repair" if "repair" in f["allowed_actions"] and "quarantine" not in f["allowed_actions"] else "quarantine")
        action = default
        if not args.action and len(f["allowed_actions"]) > 1:
            ans = input(f"  {f['id']} action {f['allowed_actions']} [{default}]: ").strip()
            action = ans or default
        if action not in f["allowed_actions"]:
            print(c(f"  skip {f['id']}: '{action}' not allowed (allowed: {f['allowed_actions']})", "yellow"))
            continue
        crit = False
        if f.get("protected") and action == "quarantine":
            print(c(f"  ⚠ {f['id']} is a PROTECTED system/security file ({f['protected']}). Removing it may break the OS.", "red"))
            name = os.path.basename(f.get("path") or "")
            if input(f"  Type the file name '{name}' to confirm, anything else to skip: ").strip() != name:
                continue
            crit = True
        requests.append({"subject_type": "finding", "subject_id": f["id"], "action": action, "critical_ack": crit, "_title": f["title"]})
    if not requests:
        print("Nothing to approve.")
        return 0
    print(c("\nYou are approving:", "bold"))
    for r in requests:
        print(f"  ✅ {r['subject_id']}  →  {r['action'].upper()}   {r.pop('_title')}")
    return _approve_and_maybe_execute(engine, requests, args, sid)


def cmd_remediate(args) -> int:
    engine = _engine(args)
    sid = None if args.approval else _resolve_scan(engine, args.scan_id)
    res = service.execute_approved(engine, scan_id=sid, approval_id=args.approval, actor=args.actor)
    if args.json:
        out_json(res)
        return 0
    if not res["executed"]:
        print(res.get("message"))
        return 0
    for r in res["executed"]:
        print(f"{r['approval_id']}: {r.get('action', '?')} → {r['status']}  {r.get('detail', '')}")
    if res.get("verification"):
        print(f"Verification: {'PASSED' if res['verification'].get('verified') else 'NOT fully verified'}")
    return 0


def cmd_verify(args) -> int:
    engine = _engine(args)
    out_json(service.verify(engine, _resolve_scan(engine, args.scan_id)))
    return 0


def cmd_quarantine(args) -> int:
    engine = _engine(args)
    if args.qcmd == "list":
        rows = service.quarantine_list(engine, args.all)
        if args.json:
            out_json(rows)
        else:
            for q in rows:
                print(f"{q['id']}  {q['status']:<11} {q['quarantined_at']}  {q['original_path']}")
        return 0
    args.quarantine_item, args.action = args.item, args.qcmd
    args.repair_step = args.rollback = args.scan_id = args.findings = None
    return cmd_approve(args)


def cmd_repair(args) -> int:
    engine = _engine(args)
    if args.rcmd == "plan":
        plan = service.repair_plan(engine, args.scan_id)
        if args.json:
            out_json(plan)
            return 0
        for s in plan["steps"]:
            tag = "manual" if s["manual"] else ("admin" if s["requires_admin"] else "user")
            print(f"{s['id']:<34} [{tag:<6}] {s['title']}")
            print(c(f"{'':37}{s['command'] or s['guidance']}", "dim"))
        return 0
    args.repair_step, args.quarantine_item, args.rollback, args.scan_id, args.findings, args.action = args.step, None, None, None, None, "repair"
    return cmd_approve(args)


def cmd_recovery(args) -> int:
    engine = _engine(args)
    if args.rcmd == "list":
        out_json(engine.recovery.list(active_only=not args.all))
        return 0
    args.rollback, args.quarantine_item, args.repair_step, args.scan_id, args.findings, args.action = args.record, None, None, None, None, "rollback"
    return cmd_approve(args)


def cmd_audit(args) -> int:
    engine = _engine(args)
    if args.acmd == "verify":
        res = engine.audit.verify()
        out_json(res)
        return 0 if res["ok"] else 6
    out_json(engine.audit.tail(args.n))
    return 0


def cmd_intel(args) -> int:
    engine = _engine(args)
    if args.icmd == "import":
        n = engine.hashintel.import_file(args.file, args.source)
        engine.audit.append("intel.import", "cli", {"file": args.file, "count": n})
        print(f"Imported {n} hashes.")
        return 0
    if args.icmd == "lookup":
        res = {"local": engine.hashintel.lookup(args.sha256)}
        if args.online:
            res["malwarebazaar"] = engine.intel.malwarebazaar_hash(args.sha256)
            res["virustotal"] = engine.intel.virustotal_hash(args.sha256)
        out_json({k: (v.to_dict() if v else None) for k, v in res.items()})
        return 0
    require_human("sentry intel upload")
    print(c(f"Uploading {args.path} to VirusTotal shares the file with a third party and its customers.", "yellow"))
    if input("Type UPLOAD to consent: ").strip() != "UPLOAD":
        return 1
    out_json(engine.intel.virustotal_upload(args.path, consent=True))
    return 0


def cmd_monitor(args) -> int:
    from .monitor import Monitor

    engine = _engine(args)
    banner()
    mon = Monitor(engine, args.paths or None, interval=args.interval)
    print("Continuous monitoring (alerts only — never removes anything). Ctrl+C to stop.")
    try:
        mon.run(once=args.once, on_alert=lambda a: print(c(f"[ALERT {a['severity'].upper()}] {a['message']}", SEV_COLOR.get(a["severity"], "yellow"))))
    except KeyboardInterrupt:
        pass
    return 0


def cmd_schedule(args) -> int:
    from .monitor.schedule import add_schedule, list_schedules, remove_schedule

    engine = _engine(args)
    if args.scmd == "add":
        out_json(add_schedule(engine, args.name, args.type, args.daily, args.paths))
    elif args.scmd == "remove":
        out_json(remove_schedule(engine, args.name))
    else:
        out_json(list_schedules(engine))
    return 0


def cmd_serve(args) -> int:
    from .api.server import serve

    return serve(args.home, args.port, args.open, args.print_connection)


def cmd_mcp(args) -> int:
    from .mcp_server import main as mcp_main

    return mcp_main(args.home)


def cmd_testfile(args) -> int:
    engine = _engine(args)
    out_json(service.eicar(engine, args.directory, "eicar" if args.eicar else "sentry"))
    return 0


def cmd_settings(args) -> int:
    engine = _engine(args)
    if args.set:
        changes = {}
        for kv in args.set:
            k, _, v = kv.partition("=")
            try:
                changes[k] = json.loads(v)
            except ValueError:
                changes[k] = v
        out_json(service.update_settings(engine, changes, "cli"))
    else:
        out_json(engine.settings.to_dict(redact=True))
    return 0


def cmd_agents(args) -> int:
    engine = _engine(args)
    out_json(service.agents_overview(engine, args.scan_id))
    return 0


def cmd_metrics(args) -> int:
    engine = _engine(args)
    out_json(service.metrics(engine))
    return 0


# ---------------------------------------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentry", description=f"{PRODUCT} — {SLOGAN}. {TAGLINE}")
    p.add_argument("--home", help="SENTRY data directory (default: platform data dir or $SENTRY_HOME)")
    p.add_argument("--version", action="version", version=f"sentry {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="(human) create the approver key and passphrase")
    s.add_argument("--change-passphrase", action="store_true")
    s.set_defaults(fn=cmd_init)
    s = sub.add_parser("doctor", help="engine availability and environment checks")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_doctor)
    s = sub.add_parser("drives", help="list drives and whether a full scan covers them")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_drives)

    s = sub.add_parser("scan", help="scan: quick | full | custom PATH...")
    s.add_argument("kind", choices=["quick", "full", "custom"])
    s.add_argument("paths", nargs="*")
    s.add_argument("--workers", type=int, help="initial concurrent workers (default 4-8)")
    s.add_argument("--max-workers", type=int, help="upper bound for adaptive scaling (up to 512)")
    s.add_argument("--online", action="store_true", help="enable hash/host reputation and OSV lookups (sends hashes/package names, never files)")
    s.add_argument("--no-behavior", action="store_true")
    s.add_argument("--no-persistence", action="store_true")
    s.add_argument("--no-vuln", action="store_true")
    s.add_argument("--no-archives", action="store_true")
    s.add_argument("--no-defender", action="store_true")
    s.add_argument("--report", choices=["md", "json", "html"])
    s.add_argument("--requested-by", default="cli")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("status", help="scan progress/status")
    s.add_argument("scan_id", nargs="?")
    s.set_defaults(fn=cmd_status)
    s = sub.add_parser("scans", help="scan history")
    s.add_argument("--limit", type=int, default=30)
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_scans)
    s = sub.add_parser("findings", help="list findings with explanations")
    s.add_argument("scan_id", nargs="?")
    s.add_argument("--min-severity", default="info", choices=["info", "low", "medium", "high", "critical"])
    s.add_argument("--category")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_findings)
    s = sub.add_parser("show", help="one finding in detail")
    s.add_argument("finding_id")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_show)
    s = sub.add_parser("report", help="write a report (md, html, json)")
    s.add_argument("scan_id", nargs="?")
    s.add_argument("--format", default="md", choices=["md", "html", "json"])
    s.add_argument("--out")
    s.add_argument("--print", action="store_true")
    s.set_defaults(fn=cmd_report)
    s = sub.add_parser("annotate", help="attach an AI investigation note to a finding (advisory only)")
    s.add_argument("finding_id")
    s.add_argument("--author", default="agent")
    s.add_argument("--text", required=True)
    s.set_defaults(fn=cmd_annotate)

    s = sub.add_parser("approve", help="(human) tick findings and approve actions with your passphrase")
    s.add_argument("scan_id", nargs="?")
    s.add_argument("--findings", help="comma-separated finding ids or 'all' (still asks for the passphrase)")
    s.add_argument("--action", choices=["quarantine", "remove_persistence", "allowlist", "repair", "restore", "delete", "rollback"])
    s.add_argument("--quarantine-item")
    s.add_argument("--repair-step")
    s.add_argument("--rollback")
    s.add_argument("--ttl", type=int, help="approval validity in seconds (60-86400, default 1800)")
    ex = s.add_mutually_exclusive_group()
    ex.add_argument("--execute", dest="execute", action="store_true", default=None)
    ex.add_argument("--no-execute", dest="execute", action="store_false")
    s.set_defaults(fn=cmd_approve)

    s = sub.add_parser("remediate", help="execute actions the user already approved, then verify")
    s.add_argument("scan_id", nargs="?")
    s.add_argument("--approval")
    s.add_argument("--actor", default="cli")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_remediate)
    s = sub.add_parser("verify", help="independent post-remediation verification")
    s.add_argument("scan_id", nargs="?")
    s.set_defaults(fn=cmd_verify)

    s = sub.add_parser("quarantine", help="list / (human) restore / (human) delete quarantined items")
    qs = s.add_subparsers(dest="qcmd", required=True)
    q = qs.add_parser("list")
    q.add_argument("--all", action="store_true")
    q.add_argument("--json", action="store_true")
    for name in ("restore", "delete"):
        q = qs.add_parser(name)
        q.add_argument("item")
        q.add_argument("--ttl", type=int)
        q.add_argument("--execute", dest="execute", action="store_true", default=None)
    s.set_defaults(fn=cmd_quarantine)

    s = sub.add_parser("repair", help="repair plan / (human) run a repair step")
    rs = s.add_subparsers(dest="rcmd", required=True)
    r = rs.add_parser("plan")
    r.add_argument("scan_id", nargs="?")
    r.add_argument("--json", action="store_true")
    r = rs.add_parser("run")
    r.add_argument("step")
    r.add_argument("--ttl", type=int)
    r.add_argument("--execute", dest="execute", action="store_true", default=None)
    s.set_defaults(fn=cmd_repair)

    s = sub.add_parser("recovery", help="recovery records / (human) rollback")
    rs = s.add_subparsers(dest="rcmd", required=True)
    r = rs.add_parser("list")
    r.add_argument("--all", action="store_true")
    r = rs.add_parser("rollback")
    r.add_argument("record")
    r.add_argument("--ttl", type=int)
    r.add_argument("--execute", dest="execute", action="store_true", default=None)
    s.set_defaults(fn=cmd_recovery)

    s = sub.add_parser("audit", help="verify or show the tamper-evident audit log")
    a = s.add_subparsers(dest="acmd", required=True)
    a.add_parser("verify")
    t = a.add_parser("tail")
    t.add_argument("-n", type=int, default=30)
    s.set_defaults(fn=cmd_audit)

    s = sub.add_parser("intel", help="threat intelligence")
    i = s.add_subparsers(dest="icmd", required=True)
    x = i.add_parser("lookup")
    x.add_argument("sha256")
    x.add_argument("--online", action="store_true")
    x = i.add_parser("import")
    x.add_argument("file")
    x.add_argument("--source", default="import")
    x = i.add_parser("upload", help="(human) upload a file to VirusTotal after explicit consent")
    x.add_argument("path")
    s.set_defaults(fn=cmd_intel)

    s = sub.add_parser("monitor", help="continuous protection (alerts only)")
    s.add_argument("paths", nargs="*")
    s.add_argument("--interval", type=int, default=10)
    s.add_argument("--once", action="store_true")
    s.set_defaults(fn=cmd_monitor)
    s = sub.add_parser("schedule", help="scheduled scans")
    ss = s.add_subparsers(dest="scmd", required=True)
    x = ss.add_parser("add")
    x.add_argument("--name", required=True)
    x.add_argument("--type", choices=["quick", "full", "custom"], default="quick")
    x.add_argument("--daily", default="02:00", help="HH:MM")
    x.add_argument("paths", nargs="*")
    x = ss.add_parser("remove")
    x.add_argument("name")
    ss.add_parser("list")
    s.set_defaults(fn=cmd_schedule)

    s = sub.add_parser("serve", help="local API + web UI on 127.0.0.1 (used by the desktop app)")
    s.add_argument("--port", type=int, default=0)
    s.add_argument("--open", action="store_true")
    s.add_argument("--print-connection", action="store_true")
    s.set_defaults(fn=cmd_serve)
    s = sub.add_parser("mcp", help="MCP stdio server for AI coding agents")
    s.set_defaults(fn=cmd_mcp)
    s = sub.add_parser("test-file", help="create a harmless test file (SENTRY signature, or --eicar)")
    s.add_argument("directory")
    s.add_argument("--eicar", action="store_true")
    s.set_defaults(fn=cmd_testfile)
    s = sub.add_parser("settings", help="show or change non-security settings")
    s.add_argument("--set", nargs="*", metavar="KEY=VALUE")
    s.set_defaults(fn=cmd_settings)
    s = sub.add_parser("agents", help="agent definitions and run history")
    s.add_argument("scan_id", nargs="?")
    s.set_defaults(fn=cmd_agents)
    s = sub.add_parser("metrics", help="dashboard metrics (JSON)")
    s.set_defaults(fn=cmd_metrics)
    return p


def main(argv: list[str] | None = None) -> int:
    global COLOR
    _configure_stdout()
    COLOR = _enable_vt()
    args = build_parser().parse_args(argv)
    try:
        return int(args.fn(args) or 0)
    except KeyError as exc:
        print(f"Not found: {exc}", file=sys.stderr)
        return 2
    except (ValueError, PermissionError) as exc:
        print(f"Error: {sanitize(str(exc), 500)}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
