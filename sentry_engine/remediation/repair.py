"""System repair catalogue (Windows / Linux / macOS).

Each executable step has a fixed command whose SHA-256 is bound into the human
approval, so an approved step cannot be swapped for another command. Steps that
cannot be safely automated (offline scans, Windows Recovery, SIP, credential
rotation, reinstallation) are explicit *manual guidance*.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from ..malware.defender import find_mpcmdrun
from ..util import canonical_json, platform_name, run_command, run_powershell
from ..vulnerability.config_checks import unb64id


@dataclass
class RepairStep:
    id: str
    title: str
    description: str
    platform: str
    argv: list[str] | None = None
    powershell: str | None = None
    requires_admin: bool = True
    reboot_required: bool = False
    risk: str = "low"
    manual: bool = False
    guidance: str = ""
    verify_check: str | None = None
    timeout: int = 3600
    tags: list[str] = field(default_factory=list)

    @property
    def command_sha256(self) -> str:
        return hashlib.sha256(canonical_json({"argv": self.argv, "powershell": self.powershell})).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["command_sha256"] = self.command_sha256
        d["command"] = " ".join(self.argv) if self.argv else (f"powershell -Command {self.powershell}" if self.powershell else None)
        return d


def _mp() -> str:
    return find_mpcmdrun() or "MpCmdRun.exe"


def _static_catalog() -> dict[str, RepairStep]:
    steps = [
        # ------------------------------------------------------------------ Windows
        RepairStep("win.sfc", "Repair Windows system files (SFC)", "Runs System File Checker, which verifies protected Windows files and restores corrupted or modified ones from the component store.",
                   "windows", ["sfc.exe", "/scannow"], timeout=7200, tags=["baseline"]),
        RepairStep("win.dism", "Repair the Windows component store (DISM)", "Repairs the Windows image used by SFC (downloads clean files from Windows Update if needed). Run before SFC if SFC cannot fix files.",
                   "windows", ["DISM.exe", "/Online", "/Cleanup-Image", "/RestoreHealth"], timeout=7200, tags=["baseline"]),
        RepairStep("win.defender_update_signatures", "Update Microsoft Defender signatures", "Downloads the latest antivirus definitions.",
                   "windows", [_mp(), "-SignatureUpdate"], timeout=1800, tags=["baseline"]),
        RepairStep("win.defender_full_scan", "Run a Microsoft Defender full scan", "Second-opinion full scan by Microsoft Defender. Note: Defender applies its own configured remediation to what it finds.",
                   "windows", [_mp(), "-Scan", "-ScanType", "2"], requires_admin=False, timeout=6 * 3600, risk="low", tags=["baseline"]),
        RepairStep("win.enable_defender_realtime", "Turn Microsoft Defender real-time protection back on", "Re-enables real-time protection that was disabled.",
                   "windows", powershell="Set-MpPreference -DisableRealtimeMonitoring $false", verify_check="win.defender.realtime_off", timeout=120),
        RepairStep("win.enable_firewall", "Turn Windows Firewall on for all profiles", "Enables the firewall for Domain, Private and Public networks.",
                   "windows", powershell="Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True", verify_check="win.firewall.off", timeout=120),
        RepairStep("win.enable_uac", "Re-enable User Account Control", "Sets EnableLUA=1. Takes effect after a restart.",
                   "windows", ["reg.exe", "add", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "/v", "EnableLUA", "/t", "REG_DWORD", "/d", "1", "/f"],
                   reboot_required=True, verify_check="win.uac.disabled", timeout=60),
        RepairStep("win.disable_smb1", "Disable the SMBv1 server protocol", "Sets SMB1=0 for the LanmanServer service. Takes effect after a restart.",
                   "windows", ["reg.exe", "add", r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "/v", "SMB1", "/t", "REG_DWORD", "/d", "0", "/f"],
                   reboot_required=True, verify_check="win.smb1.enabled", timeout=60),
        RepairStep("win.enable_rdp_nla", "Require Network Level Authentication for Remote Desktop", "Sets UserAuthentication=1 for RDP-Tcp.",
                   "windows", ["reg.exe", "add", r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "/v", "UserAuthentication", "/t", "REG_DWORD", "/d", "1", "/f"],
                   verify_check="win.rdp.no_nla", timeout=60),
        RepairStep("win.manual_offline_scan", "Microsoft Defender Offline scan", "Reboots into a trusted environment to remove rootkits and malware that hide while Windows runs.",
                   "windows", manual=True, risk="medium", guidance="Windows Security > Virus & threat protection > Scan options > Microsoft Defender Offline scan > Scan now. Save your work first: the PC restarts."),
        RepairStep("win.manual_recovery", "Windows Recovery Environment / Reset this PC", "For systems that cannot be cleaned or no longer boot.",
                   "windows", manual=True, risk="high", guidance="Settings > System > Recovery. Use 'Reset this PC' (keep or remove files) or boot into WinRE (hold Shift while clicking Restart). Back up personal files first."),
        RepairStep("win.manual_windows_update", "Install pending Windows updates", "Missing security updates leave known vulnerabilities open.",
                   "windows", manual=True, guidance="Settings > Windows Update > Check for updates. Install everything, then restart."),
        RepairStep("win.manual_tamper_protection", "Turn on Defender Tamper Protection", "Prevents malware from changing Defender settings.",
                   "windows", manual=True, guidance="Windows Security > Virus & threat protection > Manage settings > Tamper Protection: On."),
        RepairStep("win.manual_uac_prompt", "Restore the UAC consent prompt", "Administrators should be asked before elevation.",
                   "windows", manual=True, guidance="Control Panel > User Accounts > Change User Account Control settings: choose the default level."),
        RepairStep("win.manual_rdp", "Disable Remote Desktop if unused", "", "windows", manual=True,
                   guidance="Settings > System > Remote Desktop: Off."),
        RepairStep("win.manual_guest", "Disable the Guest account", "", "windows", manual=True,
                   guidance="In an elevated terminal: net user Guest /active:no (the account name may be localised)."),
        RepairStep("win.manual_execution_policy", "Restrict PowerShell execution policy", "", "windows", manual=True,
                   guidance="In an elevated PowerShell: Set-ExecutionPolicy RemoteSigned -Scope LocalMachine"),
        RepairStep("win.manual_hosts", "Restore the hosts file", "Removes malicious redirections of security/update websites.", "windows", manual=True,
                   guidance=r"Open C:\Windows\System32\drivers\etc\hosts in Notepad as administrator and remove the lines reported by SENTRY."),
        # ------------------------------------------------------------------ Linux
        RepairStep("linux.verify_packages", "Verify installed package files", "Lists package files whose content differs from the package database (dpkg/rpm). Read-only.",
                   "linux", ["sh", "-c", "command -v dpkg >/dev/null && dpkg --verify || rpm -Va"], risk="none", timeout=3600, tags=["baseline"]),
        RepairStep("linux.enable_ufw", "Enable the UFW firewall", "", "linux", ["ufw", "--force", "enable"], verify_check="linux.firewall.off", timeout=120),
        RepairStep("linux.manual_sshd", "Harden SSH", "", "linux", manual=True,
                   guidance="Edit /etc/ssh/sshd_config: PermitRootLogin no, PasswordAuthentication no (after installing your SSH key), then: sudo systemctl reload sshd"),
        RepairStep("linux.manual_path", "Fix world-writable PATH directories", "", "linux", manual=True, guidance="sudo chmod o-w <dir> for each reported directory."),
        RepairStep("linux.manual_permissions", "Fix sensitive file permissions", "", "linux", manual=True,
                   guidance="sudo chmod 640 /etc/shadow; sudo chmod 644 /etc/passwd; sudo chmod 440 /etc/sudoers"),
        RepairStep("linux.manual_offline", "Offline remediation", "Rootkits and kernel-level compromise require cleaning from trusted media.", "linux", manual=True, risk="high",
                   guidance="Boot from trusted live media, mount the disk read-only, run `sentry scan custom /mnt/disk`, run fsck on unmounted filesystems, and consider reinstalling the OS. Rotate all credentials and SSH keys."),
        # ------------------------------------------------------------------ macOS
        RepairStep("mac.enable_gatekeeper", "Re-enable Gatekeeper", "", "macos", ["spctl", "--master-enable"], verify_check="mac.gatekeeper.disabled", timeout=60),
        RepairStep("mac.enable_firewall", "Enable the application firewall", "", "macos",
                   ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on"], verify_check="mac.firewall.off", timeout=60),
        RepairStep("mac.software_update_check", "List available macOS updates", "Read-only check for security updates.", "macos",
                   ["softwareupdate", "-l"], requires_admin=False, risk="none", timeout=600, tags=["baseline"]),
        RepairStep("mac.manual_sip", "Re-enable System Integrity Protection", "", "macos", manual=True, risk="medium",
                   guidance="Restart into Recovery (hold the power button on Apple silicon / Cmd+R on Intel), open Terminal, run: csrutil enable, restart."),
        RepairStep("mac.manual_filevault", "Turn on FileVault", "", "macos", manual=True, guidance="System Settings > Privacy & Security > FileVault: Turn On."),
        # ------------------------------------------------------------------ all platforms
        RepairStep("any.manual_credentials", "Rotate credentials", "Malware that ran on this machine may have stolen passwords, tokens and keys.", "any", manual=True,
                   guidance="From a clean device: change passwords for email, banking and work accounts, revoke sessions/tokens, rotate SSH/API keys, enable MFA."),
        RepairStep("any.manual_clean_install", "Clean operating-system installation", "The only reliable fix for rootkits, firmware or deep compromise.", "any", manual=True, risk="high",
                   guidance="Back up documents (not programs), create installation media on a clean computer, reinstall the OS, restore data and rescan it with SENTRY before opening it."),
    ]
    return {s.id: s for s in steps}


_SAFE_PKG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_\-:]{0,120}$")


def get_step(step_id: str) -> RepairStep | None:
    cat = _static_catalog()
    if step_id in cat:
        return cat[step_id]
    if step_id.startswith("win.remove_exclusion.path:"):
        try:
            path = unb64id(step_id.split(":", 1)[1])
        except Exception:
            return None
        if not path or any(c in path for c in "'\"`$;\r\n") or len(path) > 400:
            return None
        return RepairStep(step_id, f"Remove antivirus exclusion: {path}", "Removes a Microsoft Defender exclusion so the location is scanned again.",
                          "windows", powershell=f"Remove-MpPreference -ExclusionPath '{path}'", timeout=120,
                          verify_check="win.defender.exclusion.path")
    if step_id.startswith("linux.reinstall_package:"):
        pkg = step_id.split(":", 1)[1]
        if not _SAFE_PKG.match(pkg):
            return None
        return RepairStep(step_id, f"Reinstall package {pkg}", "Restores the original files of a package whose files were modified.",
                          "linux", ["sh", "-c", f"command -v apt-get >/dev/null && apt-get install --reinstall -y '{pkg}' || dnf reinstall -y '{pkg}'"],
                          timeout=1800)
    return None


def catalog(platform: str | None = None) -> list[RepairStep]:
    plat = platform or platform_name()
    return [s for s in _static_catalog().values() if s.platform in (plat, "any")]


def plan(linked_steps: list[str], platform: str | None = None, include_baseline: bool = True) -> list[RepairStep]:
    plat = platform or platform_name()
    out: dict[str, RepairStep] = {}
    for sid in linked_steps:
        st = get_step(sid)
        if st and st.platform in (plat, "any"):
            out[st.id] = st
    if include_baseline:
        for s in catalog(plat):
            if "baseline" in s.tags or (s.manual and s.id.startswith("any.")):
                out.setdefault(s.id, s)
    return list(out.values())


def run_step(step: RepairStep) -> tuple[int, str]:
    if step.manual:
        return -3, "manual step"
    if step.powershell:
        rc, out, err = run_powershell(step.powershell, timeout=step.timeout)
    else:
        rc, out, err = run_command(step.argv or [], timeout=step.timeout)
    text = (out + ("\n" + err if err else "")).replace("\x00", "")
    return rc, text[-8000:]
