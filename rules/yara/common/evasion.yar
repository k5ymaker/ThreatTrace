/*
  ThreatTrace YARA Rules — Defense Evasion Patterns
  Cross-platform evasion: obfuscation, encoding, timestomping, log tampering
*/

rule Base64_Encoded_Executable {
    meta:
        rule_id        = "yara:common:Base64_Encoded_Executable"
        description    = "Detects Base64-encoded executable or script content in logs"
        severity       = "high"
        mitre_tactic   = "Defense Evasion"
        mitre_technique = "T1027"
        author         = "ThreatTrace"

    strings:
        // MZ header base64
        $mz_b64 = "TVqQAAMAAAAEAAAA" nocase
        // PE header
        $pe_b64 = "TVoAAAAAAAAAAAA" nocase
        // PowerShell base64 common prefix (JABjAGwAaQBlAG4AdAA= = $client)
        $ps_b64 = "JABjAGwAaQBlAG4AdAA=" nocase
        // Long base64 blocks in command lines (heuristic)
        $long_b64 = /[A-Za-z0-9+\/]{200,}={0,2}/

    condition:
        $mz_b64 or $pe_b64 or $ps_b64 or $long_b64
}

rule Timestomping_Indicators {
    meta:
        rule_id        = "yara:common:Timestomping_Indicators"
        description    = "Detects timestomping tool usage for artifact manipulation"
        severity       = "high"
        mitre_tactic   = "Defense Evasion"
        mitre_technique = "T1070.006"
        author         = "ThreatTrace"

    strings:
        $t1 = "timestomp" nocase
        $t2 = "SetFileTime" nocase
        $t3 = "touch -t 197001010000" nocase
        $t4 = "$(Get-Item" nocase
        $t5 = ".CreationTime = " nocase

    condition:
        any of them
}

rule Process_Injection_Tools {
    meta:
        rule_id        = "yara:common:Process_Injection_Tools"
        description    = "Detects process injection tool strings and techniques"
        severity       = "critical"
        mitre_tactic   = "Defense Evasion"
        mitre_technique = "T1055"
        author         = "ThreatTrace"

    strings:
        $i1 = "VirtualAllocEx" nocase
        $i2 = "WriteProcessMemory" nocase
        $i3 = "CreateRemoteThread" nocase
        $i4 = "NtQueueApcThread" nocase
        $i5 = "mavinject" nocase
        $i6 = "syringe" nocase
        $i7 = "inject.exe" nocase
        $i8 = "hollowing" nocase

    condition:
        any of them
}

rule Disable_Security_Tools {
    meta:
        rule_id        = "yara:common:Disable_Security_Tools"
        description    = "Detects attempts to disable security tools and AV"
        severity       = "critical"
        mitre_tactic   = "Defense Evasion"
        mitre_technique = "T1562.001"
        author         = "ThreatTrace"

    strings:
        $av1 = "Set-MpPreference -DisableRealtimeMonitoring $true" nocase
        $av2 = "Add-MpPreference -ExclusionPath" nocase
        $av3 = "sc stop windefend" nocase
        $av4 = "net stop windefend" nocase
        $av5 = "taskkill /im MsMpEng.exe" nocase
        $av6 = "netsh advfirewall set allprofiles state off" nocase
        $av7 = "Set-NetFirewallProfile -Enabled False" nocase
        $av8 = "setenforce 0" nocase
        $av9 = "systemctl stop auditd" nocase
        $av10 = "service auditd stop" nocase

    condition:
        any of them
}

rule UAC_Bypass {
    meta:
        rule_id        = "yara:common:UAC_Bypass"
        description    = "Detects User Account Control (UAC) bypass techniques"
        severity       = "high"
        mitre_tactic   = "Privilege Escalation"
        mitre_technique = "T1548.002"
        author         = "ThreatTrace"

    strings:
        $u1 = "fodhelper.exe" nocase
        $u2 = "eventvwr.exe" nocase
        $u3 = "sdclt.exe" nocase
        $u4 = "cmstp.exe" nocase
        $u5 = "HKCU:\\Software\\Classes\\ms-settings\\" nocase
        $u6 = "HKCU:\\Software\\Classes\\mscfile\\" nocase

    condition:
        any of them
}
