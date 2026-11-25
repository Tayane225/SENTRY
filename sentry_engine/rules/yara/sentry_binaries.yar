/*
   SENTRY — executable and document indicators.
   Import-table heuristics (process injection, keylogging APIs) live in the static PE
   analyser, which reads the real import table; they are not duplicated here.
*/

import "pe"

rule SENTRY_PE_UPX_Packed
{
    meta:
        description = "Executable packed with UPX (hides code from static inspection; also used by legitimate software)"
        category = "suspicious"
        severity = "low"
        confidence = "low"
        weight = 15
        attack = "T1027.002"
    condition:
        uint16(0) == 0x5A4D and for any s in pe.sections : ( s.name == "UPX0" or s.name == "UPX1" )
}

rule SENTRY_PE_Browser_Credential_Theft
{
    meta:
        description = "Executable references browser password stores, crypto wallets and messenger sessions together (info-stealer pattern)"
        category = "infostealer"
        severity = "high"
        confidence = "medium"
        weight = 50
        attack = "T1555.003"
    strings:
        $a = "\\Google\\Chrome\\User Data" nocase ascii wide
        $b = "Login Data" ascii wide
        $c = "\\Mozilla\\Firefox\\Profiles" nocase ascii wide
        $d = "logins.json" ascii wide
        $e = "encrypted_key" ascii wide
        $f = "wallet.dat" nocase ascii wide
        $g = "\\Telegram Desktop\\tdata" nocase ascii wide
        $h = "\\Microsoft\\Edge\\User Data" nocase ascii wide
    condition:
        uint16(0) == 0x5A4D and 4 of them
}

rule SENTRY_HackTool_Credential_Dumper_Strings
{
    meta:
        description = "Strings of a well-known credential dumping tool"
        category = "hacktool"
        severity = "high"
        confidence = "high"
        weight = 85
        attack = "T1003.001"
    strings:
        $a = { 73 65 6B 75 72 6C 73 61 3A 3A 6C 6F 67 6F 6E 70 61 73 73 77 6F 72 64 73 }
        $b = { 67 65 6E 74 69 6C 6B 69 77 69 }
        $c = { 6D 69 6D 69 6B 61 74 7A }
        $d = { 73 00 65 00 6B 00 75 00 72 00 6C 00 73 00 61 00 }
    condition:
        2 of them
}

rule SENTRY_RTF_Exploit_Object
{
    meta:
        description = "RTF document embedding an OLE object associated with Equation Editor exploits"
        category = "exploit"
        severity = "high"
        confidence = "medium"
        weight = 60
        attack = "T1203"
    strings:
        $obj = "\\objdata" nocase
        $upd = "\\objupdate" nocase
        $eq1 = "equation.3" nocase
        $eq2 = "4571756174696f6e2e33" nocase
        $eq3 = "0002ce02" nocase
    condition:
        uint32(0) == 0x74725C7B and $obj and ($upd or $eq1 or $eq2 or $eq3)
}

rule SENTRY_PDF_Auto_Action
{
    meta:
        description = "PDF that runs JavaScript or launches a program automatically when opened"
        category = "suspicious"
        severity = "medium"
        confidence = "medium"
        weight = 40
        attack = "T1204.002"
    strings:
        $js1 = "/JavaScript"
        $js2 = "/JS"
        $oa = "/OpenAction"
        $aa = "/AA"
        $launch = "/Launch"
    condition:
        uint32(0) == 0x46445025 and ((($js1 or $js2) and ($oa or $aa)) or $launch)
}
