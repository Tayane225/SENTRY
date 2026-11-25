/*
   SENTRY — script, web shell, ransomware and miner indicators.
   Sensitive tokens are hex-encoded so host antivirus products do not flag the rule file.
   Meta conventions: category, severity, confidence (high|medium|low), weight (0-100), attack (ATT&CK ids, comma separated).
*/

rule SENTRY_Webshell_PHP_Request_Exec
{
    meta:
        description = "PHP web shell: executes code or commands taken directly from an HTTP request"
        category = "webshell"
        severity = "high"
        confidence = "medium"
        weight = 70
        attack = "T1505.003"
    strings:
        $php = "<?php" nocase
        $e1 = /(eval|assert|system|passthru|shell_exec|popen|proc_open)\s*\(\s*(base64_decode\s*\(\s*)?(stripslashes\s*\(\s*)?\$_(POST|GET|REQUEST|COOKIE)\s*\[/ nocase
        $e2 = /preg_replace\s*\(\s*['"].{1,40}\/e['"]/ nocase
    condition:
        filesize < 2MB and $php and ($e1 or $e2)
}

rule SENTRY_Webshell_ASPX_Command
{
    meta:
        description = "ASP.NET page that starts processes with request-controlled input (web shell pattern)"
        category = "webshell"
        severity = "high"
        confidence = "medium"
        weight = 65
        attack = "T1505.003"
    strings:
        $tag = "<%@" nocase
        $p = "Process.Start" nocase
        $psi = "ProcessStartInfo" nocase
        $r1 = "Request.Form" nocase
        $r2 = "Request.QueryString" nocase
        $r3 = "Request[" nocase
        $cmd = "cmd.exe" nocase
    condition:
        filesize < 1MB and $tag and ($p or $psi) and (1 of ($r*)) and $cmd
}

rule SENTRY_Reverse_Shell_Unix
{
    meta:
        description = "Unix reverse shell one-liner (gives a remote attacker an interactive shell)"
        category = "backdoor"
        severity = "high"
        confidence = "medium"
        weight = 70
        attack = "T1059.004"
    strings:
        $a = /bash\s+-i\s*>&\s*\/dev\/tcp\// nocase
        $b = /\/dev\/tcp\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{2,5}/
        $c = /\bnc(at)?\s.{0,60}-e\s+\/bin\/(ba|z)?sh/
        $d = /mkfifo\s+\/tmp\/[A-Za-z0-9_.]+.{0,80}\|\s*nc\s/
        $e = /pty\.spawn\(\s*['"]\/bin\/(ba)?sh['"]\s*\)/
    condition:
        filesize < 5MB and any of them
}

rule SENTRY_Recovery_Inhibition_Command
{
    meta:
        description = "Command that deletes shadow copies, backups or disables Windows recovery (typical ransomware step)"
        category = "ransomware"
        severity = "high"
        confidence = "medium"
        weight = 55
        attack = "T1490"
    strings:
        $a = /vssadmin(\.exe)?\s+delete\s+shadows/ nocase
        $b = /wmic(\.exe)?\s+shadowcopy\s+delete/ nocase
        $c = /bcdedit(\.exe)?\s+\/set\s+\{?default\}?\s+recoveryenabled\s+no/ nocase
        $d = /wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup)/ nocase
        $e = /bcdedit(\.exe)?\s+\/set\s+\{?default\}?\s+bootstatuspolicy\s+ignoreallfailures/ nocase
        $f = /Get-WmiObject\s+Win32_Shadowcopy\s*\|\s*.{0,40}Delete/ nocase
    condition:
        any of them
}

rule SENTRY_Recovery_Inhibition_Multiple
{
    meta:
        description = "Several backup/recovery destruction commands in one file (strong ransomware indicator)"
        category = "ransomware"
        severity = "critical"
        confidence = "high"
        weight = 85
        attack = "T1490,T1486"
    strings:
        $a = /vssadmin(\.exe)?\s+delete\s+shadows/ nocase
        $b = /wmic(\.exe)?\s+shadowcopy\s+delete/ nocase
        $c = /bcdedit(\.exe)?\s+\/set\s+\{?default\}?\s+recoveryenabled\s+no/ nocase
        $d = /wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup)/ nocase
        $e = /bcdedit(\.exe)?\s+\/set\s+\{?default\}?\s+bootstatuspolicy\s+ignoreallfailures/ nocase
    condition:
        2 of them
}

rule SENTRY_Ransom_Note
{
    meta:
        description = "Ransom note text (files encrypted, payment and decryption instructions)"
        category = "ransomware"
        severity = "critical"
        confidence = "medium"
        weight = 75
        attack = "T1486"
    strings:
        $a = "your files have been encrypted" nocase
        $b = "all your files are encrypted" nocase
        $c = "your files are encrypted" nocase
        $d = "to decrypt your files" nocase
        $e = "decryption key" nocase
        $f = "bitcoin" nocase
        $g = ".onion" nocase
        $h = "tor browser" nocase
        $i = "decryptor" nocase
    condition:
        filesize < 300KB and 1 of ($a, $b, $c, $d) and 2 of ($e, $f, $g, $h, $i)
}

rule SENTRY_PowerShell_Defense_Evasion
{
    meta:
        description = "Disables Microsoft Defender features, adds AV exclusions or bypasses AMSI"
        category = "defense_evasion"
        severity = "high"
        confidence = "medium"
        weight = 60
        attack = "T1562.001"
    strings:
        $a = /Set-MpPreference\s.{0,80}-Disable(RealtimeMonitoring|BehaviorMonitoring|IOAVProtection|ScriptScanning|IntrusionPreventionSystem)\s+(\$true|1)/ nocase
        $b = /Add-MpPreference\s.{0,40}-Exclusion(Path|Process|Extension)/ nocase
        $c = { 41 6D 73 69 55 74 69 6C 73 }
        $d = { 61 6D 73 69 49 6E 69 74 46 61 69 6C 65 64 }
        $e = /DisableAntiSpyware.{0,40}(\/d\s+1|-Value\s+1)/ nocase
    condition:
        filesize < 10MB and any of them
}

rule SENTRY_Script_Downloader
{
    meta:
        description = "Script downloads a file over HTTP and saves or runs it (dropper/downloader)"
        category = "downloader"
        severity = "high"
        confidence = "medium"
        weight = 55
        attack = "T1105"
    strings:
        $http = "http" nocase
        $shell = "WScript.Shell" nocase
        $run = ".Run" nocase
        $stream = "ADODB.Stream" nocase
        $save = "SaveToFile" nocase
        $xhr = /MSXML2\.(Server)?XMLHTTP/ nocase
        $winhttp = "WinHttp.WinHttpRequest" nocase
    condition:
        filesize < 1MB and $http and (($stream and $save) or $xhr or $winhttp) and ($shell or $run)
}

rule SENTRY_Coinminer
{
    meta:
        description = "Cryptocurrency miner configuration or binary (uses your CPU/GPU for someone else's profit)"
        category = "pua"
        severity = "medium"
        confidence = "medium"
        weight = 55
        attack = "T1496"
    strings:
        $a = "stratum+tcp://" nocase
        $b = "stratum+ssl://" nocase
        $c = "\"donate-level\""
        $d = "xmrig" nocase
        $e = "cryptonight" nocase
        $f = "randomx" nocase
    condition:
        ($a or $b) or ($c and ($d or $f)) or ($d and $e)
}

rule SENTRY_HTML_Smuggling
{
    meta:
        description = "HTML that assembles a file from an embedded encoded blob and triggers a download (HTML smuggling)"
        category = "suspicious"
        severity = "medium"
        confidence = "medium"
        weight = 50
        attack = "T1027.006"
    strings:
        $blob = "new Blob(" nocase
        $atob = /atob\(\s*['"][A-Za-z0-9+\/=]{2000}/
        $save = "msSaveOrOpenBlob"
        $url = "createObjectURL"
        $dl = ".download"
    condition:
        filesize < 30MB and $atob and $blob and ($save or ($url and $dl))
}
