"""Plain-language explanations: what a finding is, what it could do, what to do about it."""

from __future__ import annotations

from .models import Category

DAMAGE_BY_TECHNIQUE = {
    "T1003": "Steal saved passwords and login credentials from memory",
    "T1003.001": "Steal Windows passwords and login tokens from memory",
    "T1014": "Hide itself deep in the operating system where normal tools cannot see it",
    "T1027": "Hide its real purpose from antivirus scanners",
    "T1027.002": "Hide its code from antivirus scanners by packing/encrypting it",
    "T1027.006": "Smuggle a malicious file past email and web filters",
    "T1036": "Disguise itself as a legitimate file to trick you",
    "T1036.002": "Trick you into opening a program that looks like a document",
    "T1036.005": "Pretend to be a trusted Windows component",
    "T1036.007": "Trick you into opening a program that looks like a document",
    "T1036.008": "Trick you into running a program disguised as another file type",
    "T1047": "Run commands through Windows Management Instrumentation",
    "T1053.003": "Run automatically on a schedule (cron)",
    "T1053.005": "Run automatically on a schedule, even after reboots",
    "T1055": "Inject malicious code into legitimate running programs to hide",
    "T1056.001": "Record your keystrokes, including passwords and messages",
    "T1059.001": "Run arbitrary PowerShell commands on your computer",
    "T1059.003": "Run arbitrary commands on your computer",
    "T1059.004": "Run arbitrary shell commands on your computer",
    "T1059.005": "Run arbitrary Visual Basic code on your computer",
    "T1059.006": "Run arbitrary Python code on your computer",
    "T1059.007": "Run arbitrary JavaScript code on your computer",
    "T1070.003": "Erase traces of an intrusion",
    "T1071": "Communicate with an attacker's command-and-control server",
    "T1098.004": "Give an attacker permanent remote SSH access",
    "T1105": "Download and install additional malware",
    "T1137": "Start automatically whenever you use Office",
    "T1140": "Unpack hidden malicious payloads",
    "T1197": "Download files in the background using Windows BITS",
    "T1203": "Exploit a software vulnerability to take control when the file is opened",
    "T1204.002": "Infect the computer as soon as the file is opened",
    "T1218.005": "Run malicious scripts through a trusted Windows program (mshta)",
    "T1218.010": "Run malicious scripts through a trusted Windows program (regsvr32)",
    "T1218.011": "Run malicious code through a trusted Windows program (rundll32)",
    "T1486": "Encrypt your files and demand a ransom (permanent data loss)",
    "T1490": "Delete backups and shadow copies so you cannot recover your files",
    "T1496": "Use your CPU/GPU to mine cryptocurrency, slowing the computer and raising power costs",
    "T1505.003": "Give an attacker remote control of a web server",
    "T1543.001": "Start automatically at every login (macOS Launch Agent)",
    "T1543.002": "Start automatically at every boot as a system service",
    "T1543.003": "Start automatically at every boot as a Windows service",
    "T1543.004": "Start automatically at every boot as a system daemon",
    "T1546.003": "Run automatically when system events occur (hard to spot)",
    "T1546.004": "Run every time a terminal shell starts",
    "T1546.010": "Load into almost every program that starts",
    "T1546.012": "Hijack a legitimate program so that malware runs instead",
    "T1547.001": "Start automatically every time you log in",
    "T1547.004": "Run during Windows logon with high privileges",
    "T1547.009": "Run when you click a familiar shortcut",
    "T1547.013": "Start automatically when your desktop session starts",
    "T1555.003": "Steal passwords, cookies and crypto wallets stored by your browsers",
    "T1562.001": "Disable your antivirus so other malware is not detected",
    "T1562.004": "Turn off your firewall to allow remote access",
    "T1564.001": "Hide files from you",
    "T1564.003": "Run invisibly without any window",
    "T1566.001": "Deliver malware through a booby-trapped attachment",
    "T1571": "Talk to an attacker's server over an unusual network port",
    "T1574.006": "Load attacker code into every program that runs",
    "T1574.007": "Make the system run an attacker's program instead of a legitimate one",
    "T1620": "Run malicious code directly in memory without leaving files",
}

CATEGORY_TEXT = {
    Category.CONFIRMED_MALWARE.value: "A signature-grade engine positively identified this item as malicious.",
    Category.SUSPECTED_MALWARE.value: "Several independent indicators point to malicious intent, but no signature engine confirmed it.",
    Category.SUSPICIOUS_BEHAVIOR.value: "This activity or configuration matches techniques used by attackers.",
    Category.VULNERABILITY.value: "This software has a publicly known security vulnerability.",
    Category.CONFIGURATION_WEAKNESS.value: "This setting weakens the computer's defences.",
    Category.FALSE_POSITIVE.value: "You previously marked this item as safe (allowlisted); it is shown for transparency only.",
    Category.UNVERIFIED.value: "Weak indicators only. Many legitimate files share these traits, so investigate before acting.",
}

RECOMMENDED = {
    Category.CONFIRMED_MALWARE.value: "Quarantine (reversible). After review, permanently delete the quarantined copy.",
    Category.SUSPECTED_MALWARE.value: "Quarantine and investigate. The quarantine can be undone if this is a false positive.",
    Category.UNVERIFIED.value: "Investigate first. Quarantine only if you do not recognise the file.",
    Category.SUSPICIOUS_BEHAVIOR.value: "Investigate. Remove the persistence entry or quarantine the related file if it is not legitimate.",
    Category.VULNERABILITY.value: "Update the affected software to a fixed version.",
    Category.CONFIGURATION_WEAKNESS.value: "Apply the recommended configuration repair.",
    Category.FALSE_POSITIVE.value: "No action needed.",
}


def potential_damage(attack: list[str], category: str, test_file: bool = False) -> list[str]:
    if test_file:
        return ["None. This is a harmless test file designed to check that antivirus detection works."]
    out: list[str] = []
    for t in attack:
        d = DAMAGE_BY_TECHNIQUE.get(t) or DAMAGE_BY_TECHNIQUE.get(t.split(".")[0])
        if d and d not in out:
            out.append(d)
    if not out:
        if category == Category.CONFIRMED_MALWARE.value:
            out = ["Run unauthorised code on your computer", "Install additional malicious components",
                   "Steal or damage your data"]
        elif category == Category.SUSPECTED_MALWARE.value:
            out = ["Possible unauthorised code execution if the file is opened or run"]
        elif category == Category.CONFIGURATION_WEAKNESS.value:
            out = ["Makes it easier for malware or attackers to compromise the computer"]
        elif category == Category.VULNERABILITY.value:
            out = ["Could be exploited by an attacker to run code or steal data"]
    return out[:6]


def recommended_action(category: str, protected: str | None, target_type: str) -> str:
    if protected and target_type == "file":
        return ("Do NOT delete. This is an operating-system or security component. Investigate it; prefer "
                "system repair (SFC/DISM or package reinstall) and an offline antivirus scan.")
    if target_type == "persistence" and category in (Category.SUSPICIOUS_BEHAVIOR.value, Category.CONFIRMED_MALWARE.value):
        return "Disable/remove the startup entry (a backup is kept for rollback) and quarantine the program it launches."
    if target_type == "process":
        return "Investigate the process. Quarantine its executable if malicious (stop the process or reboot first if the file is locked)."
    return RECOMMENDED.get(category, "Investigate.")


def explanation(category: str, title: str, evidence: list[dict], test_file: bool = False) -> str:
    if test_file:
        return ("This is an anti-malware TEST file (EICAR or the SENTRY test signature). It is harmless by design and is "
                "detected so that you can verify the detection, approval and quarantine pipeline end to end.")
    reasons = [e["description"] for e in sorted(evidence, key=lambda e: -float(e.get("weight", 0))) if float(e.get("weight", 0)) > 0][:4]
    base = CATEGORY_TEXT.get(category, "")
    if reasons:
        return base + " Main reasons: " + "; ".join(r.rstrip(".") for r in reasons) + "."
    return base
