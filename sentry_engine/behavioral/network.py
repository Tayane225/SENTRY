"""Network inspection: unusual connections, exposed services, hosts-file tampering."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field

import psutil

from ..malware.static_analysis import high_risk_location
from ..models import Evidence
from ..util import IS_WINDOWS

SUSPICIOUS_REMOTE_PORTS = {4444: "Metasploit default", 1337: "common backdoor port", 31337: "common backdoor port",
                           6666: "IRC botnet", 6667: "IRC botnet", 12345: "NetBus trojan", 3333: "mining pool",
                           14444: "mining pool", 45700: "mining pool", 5555: "Android debug / RAT"}
RISKY_LISTEN_PORTS = {21: "FTP", 23: "Telnet", 135: "RPC", 139: "NetBIOS", 445: "SMB", 3389: "Remote Desktop",
                      5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB", 3306: "MySQL",
                      5432: "PostgreSQL", 11211: "Memcached", 2375: "Docker API (unauthenticated)", 5985: "WinRM"}
PROTECTED_DOMAINS = ("microsoft.com", "windowsupdate.com", "update.microsoft.com", "google.com", "bing.com",
                     "virustotal.com", "malwarebytes.com", "kaspersky.com", "avast.com", "eset.com", "clamav.net",
                     "github.com", "apple.com")


@dataclass
class ConnInfo:
    pid: int | None
    process: str | None
    exe: str | None
    laddr: str
    raddr: str | None
    status: str
    evidence: list[Evidence] = field(default_factory=list)


def _is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified)
    except ValueError:
        return False


def inspect_network() -> tuple[list[ConnInfo], list[dict], dict]:
    """Return (suspicious connections, exposed listeners, stats)."""
    stats = {"connections": 0, "listening": 0, "error": None}
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError) as exc:
        stats["error"] = f"network table not readable ({type(exc).__name__}); run elevated for full visibility"
        return [], [], stats
    proc_cache: dict[int, tuple[str | None, str | None]] = {}

    def proc_of(pid: int | None) -> tuple[str | None, str | None]:
        if not pid:
            return None, None
        if pid not in proc_cache:
            try:
                p = psutil.Process(pid)
                proc_cache[pid] = (p.name(), p.exe())
            except (psutil.Error, OSError):
                proc_cache[pid] = (None, None)
        return proc_cache[pid]

    suspicious: list[ConnInfo] = []
    exposed: list[dict] = []
    for c in conns:
        stats["connections"] += 1
        if c.status == psutil.CONN_LISTEN and c.laddr:
            stats["listening"] += 1
            ip, port = c.laddr.ip, c.laddr.port
            if ip in ("0.0.0.0", "::") and port in RISKY_LISTEN_PORTS:
                name, exe = proc_of(c.pid)
                exposed.append({"port": port, "service": RISKY_LISTEN_PORTS[port], "address": ip, "process": name, "exe": exe})
            continue
        if not c.raddr:
            continue
        rip, rport = c.raddr.ip, c.raddr.port
        name, exe = proc_of(c.pid)
        ci = ConnInfo(c.pid, name, exe, f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "", f"{rip}:{rport}", c.status)
        if rport in SUSPICIOUS_REMOTE_PORTS and _is_public(rip):
            ci.evidence.append(Evidence(engine="behavior.network", rule="network.suspicious_port", weight=35,
                                        description=f"Connection to {rip}:{rport} ({SUSPICIOUS_REMOTE_PORTS[rport]})",
                                        attack=["T1571"]))
        if exe and high_risk_location(exe) and _is_public(rip):
            ci.evidence.append(Evidence(engine="behavior.network", rule="network.untrusted_process_outbound", weight=30,
                                        description=f"Program in {high_risk_location(exe)} talks to the internet ({rip}:{rport})",
                                        attack=["T1071"]))
        if ci.evidence:
            suspicious.append(ci)
    return suspicious, exposed, stats


def inspect_hosts_file() -> list[Evidence]:
    path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers", "etc", "hosts") if IS_WINDOWS else "/etc/hosts"
    ev: list[Evidence] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read(1024 * 1024).splitlines()
    except OSError:
        return ev
    hijacked = []
    for line in lines:
        s = line.split("#", 1)[0].strip()
        if not s:
            continue
        parts = s.split()
        if len(parts) < 2:
            continue
        ip, hosts = parts[0], parts[1:]
        for h in hosts:
            hl = h.lower()
            if not any(hl == d or hl.endswith("." + d) for d in PROTECTED_DOMAINS):
                continue
            sinkholed = ip in ("127.0.0.1", "::1", "0.0.0.0")
            security_site = any(k in hl for k in ("virustotal", "malwarebytes", "kaspersky", "avast", "eset", "clamav", "update"))
            if not sinkholed or security_site:
                # redirected elsewhere (possible phishing/MITM), or security/update site blocked
                hijacked.append(f"{h} -> {ip}")
    if hijacked:
        ev.append(Evidence(engine="behavior.network", rule="network.hosts_hijack", weight=50,
                           description="Hosts file redirects or blocks security/update sites: " + ", ".join(hijacked[:5]),
                           details={"entries": hijacked[:20], "path": path}, attack=["T1562.001"]))
    return ev
