/*
   SENTRY — harmless test signatures.
   Strings are hex-encoded so this rule file never matches itself and is not
   flagged by host antivirus products.
*/

rule SENTRY_Test_Signature
{
    meta:
        description = "SENTRY harmless test signature (used to exercise detection and quarantine safely)"
        category = "test"
        severity = "medium"
        confidence = "high"
        weight = 95
    strings:
        $m = { 53 45 4E 54 52 59 2D 48 41 52 4D 4C 45 53 53 2D 54 45 53 54 2D 53 49 47 4E 41 54 55 52 45 3A }
    condition:
        $m at 0
}

rule EICAR_Test_File
{
    meta:
        description = "EICAR standard anti-malware test file (harmless by design)"
        category = "test"
        severity = "medium"
        confidence = "high"
        weight = 95
    strings:
        $head = { 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 29 37 7D 24 }
        $tail = { 45 49 43 41 52 2D 53 54 41 4E 44 41 52 44 2D 41 4E 54 49 56 49 52 55 53 2D 54 45 53 54 2D 46 49 4C 45 21 }
    condition:
        $head at 0 and $tail and filesize < 256
}
