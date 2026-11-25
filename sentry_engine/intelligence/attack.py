"""MITRE ATT&CK technique reference used to classify evidence (https://attack.mitre.org/)."""

from __future__ import annotations

TECHNIQUES: dict[str, tuple[str, str]] = {
    # id: (name, tactic)
    "T1003": ("OS Credential Dumping", "Credential Access"),
    "T1003.001": ("OS Credential Dumping: LSASS Memory", "Credential Access"),
    "T1014": ("Rootkit", "Defense Evasion"),
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1027.002": ("Obfuscated Files or Information: Software Packing", "Defense Evasion"),
    "T1027.006": ("Obfuscated Files or Information: HTML Smuggling", "Defense Evasion"),
    "T1036": ("Masquerading", "Defense Evasion"),
    "T1036.002": ("Masquerading: Right-to-Left Override", "Defense Evasion"),
    "T1036.005": ("Masquerading: Match Legitimate Resource Name or Location", "Defense Evasion"),
    "T1036.007": ("Masquerading: Double File Extension", "Defense Evasion"),
    "T1036.008": ("Masquerading: Masquerade File Type", "Defense Evasion"),
    "T1037.004": ("Boot or Logon Initialization Scripts: RC Scripts", "Persistence"),
    "T1047": ("Windows Management Instrumentation", "Execution"),
    "T1053.003": ("Scheduled Task/Job: Cron", "Persistence"),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", "Persistence"),
    "T1055": ("Process Injection", "Defense Evasion"),
    "T1056.001": ("Input Capture: Keylogging", "Collection"),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "Execution"),
    "T1059.003": ("Command and Scripting Interpreter: Windows Command Shell", "Execution"),
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell", "Execution"),
    "T1059.005": ("Command and Scripting Interpreter: Visual Basic", "Execution"),
    "T1059.006": ("Command and Scripting Interpreter: Python", "Execution"),
    "T1059.007": ("Command and Scripting Interpreter: JavaScript", "Execution"),
    "T1070": ("Indicator Removal", "Defense Evasion"),
    "T1070.003": ("Indicator Removal: Clear Command History", "Defense Evasion"),
    "T1548.002": ("Abuse Elevation Control Mechanism: Bypass User Account Control", "Privilege Escalation"),
    "T1553.001": ("Subvert Trust Controls: Gatekeeper Bypass", "Defense Evasion"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1098.004": ("Account Manipulation: SSH Authorized Keys", "Persistence"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1112": ("Modify Registry", "Defense Evasion"),
    "T1137": ("Office Application Startup", "Persistence"),
    "T1140": ("Deobfuscate/Decode Files or Information", "Defense Evasion"),
    "T1197": ("BITS Jobs", "Defense Evasion"),
    "T1203": ("Exploitation for Client Execution", "Execution"),
    "T1204.002": ("User Execution: Malicious File", "Execution"),
    "T1218.005": ("System Binary Proxy Execution: Mshta", "Defense Evasion"),
    "T1218.010": ("System Binary Proxy Execution: Regsvr32", "Defense Evasion"),
    "T1218.011": ("System Binary Proxy Execution: Rundll32", "Defense Evasion"),
    "T1486": ("Data Encrypted for Impact", "Impact"),
    "T1490": ("Inhibit System Recovery", "Impact"),
    "T1496": ("Resource Hijacking", "Impact"),
    "T1505.003": ("Server Software Component: Web Shell", "Persistence"),
    "T1543.001": ("Create or Modify System Process: Launch Agent", "Persistence"),
    "T1543.002": ("Create or Modify System Process: Systemd Service", "Persistence"),
    "T1543.003": ("Create or Modify System Process: Windows Service", "Persistence"),
    "T1543.004": ("Create or Modify System Process: Launch Daemon", "Persistence"),
    "T1546.003": ("Event Triggered Execution: Windows Management Instrumentation Event Subscription", "Persistence"),
    "T1546.004": ("Event Triggered Execution: Unix Shell Configuration Modification", "Persistence"),
    "T1546.010": ("Event Triggered Execution: AppInit DLLs", "Persistence"),
    "T1546.012": ("Event Triggered Execution: Image File Execution Options Injection", "Persistence"),
    "T1547.001": ("Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", "Persistence"),
    "T1547.004": ("Boot or Logon Autostart Execution: Winlogon Helper DLL", "Persistence"),
    "T1547.009": ("Boot or Logon Autostart Execution: Shortcut Modification", "Persistence"),
    "T1547.013": ("Boot or Logon Autostart Execution: XDG Autostart Entries", "Persistence"),
    "T1555.003": ("Credentials from Password Stores: Credentials from Web Browsers", "Credential Access"),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", "Defense Evasion"),
    "T1562.004": ("Impair Defenses: Disable or Modify System Firewall", "Defense Evasion"),
    "T1564.001": ("Hide Artifacts: Hidden Files and Directories", "Defense Evasion"),
    "T1564.003": ("Hide Artifacts: Hidden Window", "Defense Evasion"),
    "T1566.001": ("Phishing: Spearphishing Attachment", "Initial Access"),
    "T1571": ("Non-Standard Port", "Command and Control"),
    "T1574.006": ("Hijack Execution Flow: Dynamic Linker Hijacking", "Persistence"),
    "T1574.007": ("Hijack Execution Flow: Path Interception by PATH Environment Variable", "Persistence"),
    "T1620": ("Reflective Code Loading", "Defense Evasion"),
}


def url_for(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def describe(tid: str) -> dict[str, str]:
    name, tactic = TECHNIQUES.get(tid, ("Unknown technique", "Unknown"))
    return {"id": tid, "name": name, "tactic": tactic, "url": url_for(tid)}
