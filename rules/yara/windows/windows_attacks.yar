/*
  ThreatTrace YARA Rules — Windows Attack Patterns
  Detects: Mimikatz, PowerShell abuse, LOLBins, credential dumping, lateral movement
*/

rule Mimikatz_Strings {
    meta:
        rule_id        = "yara:windows:Mimikatz_Strings"
        description    = "Detects Mimikatz credential dumping tool strings in logs"
        severity       = "critical"
        mitre_tactic   = "Credential Access"
        mitre_technique = "T1003.001"
        reference      = "https://attack.mitre.org/techniques/T1003/001/"
        author         = "ThreatTrace"
        false_positives = "Security research environments"

    strings:
        $s1 = "sekurlsa::logonpasswords" nocase
        $s2 = "sekurlsa::wdigest" nocase
        $s3 = "lsadump::sam" nocase
        $s4 = "lsadump::dcsync" nocase
        $s5 = "lsadump::lsa" nocase
        $s6 = "privilege::debug" nocase
        $s7 = "kerberos::ptt" nocase
        $s8 = "kerberos::list" nocase
        $s9 = "token::elevate" nocase
        $s10 = "coffee" nocase
        $s11 = "Benjamin Delpy" nocase

    condition:
        any of them
}

rule PowerShell_EncodedCommand {
    meta:
        rule_id        = "yara:windows:PowerShell_EncodedCommand"
        description    = "Detects PowerShell encoded command execution (obfuscation)"
        severity       = "high"
        mitre_tactic   = "Defense Evasion"
        mitre_technique = "T1027"
        author         = "ThreatTrace"
        false_positives = "Legitimate encoded PS scripts in automation"

    strings:
        $e1 = "-EncodedCommand" nocase
        $e2 = "-EnC " nocase
        $e3 = "-eNc" nocase
        $e4 = "-ec " nocase
        $enc1 = "JABjAGwAaQBlAG4AdAA=" nocase  // $client base64
        $enc2 = "powershell -w hidden" nocase
        $enc3 = "powershell -windowstyle hidden" nocase
        $enc4 = "bypass -nop -w hidden" nocase
        $enc5 = "-noni -nop -w hidden -enc" nocase

    condition:
        any of ($e1, $e2, $e3, $e4) or
        any of ($enc1, $enc2, $enc3, $enc4, $enc5)
}

rule PowerShell_DownloadCradle {
    meta:
        rule_id        = "yara:windows:PowerShell_DownloadCradle"
        description    = "Detects PowerShell download cradles used for payload delivery"
        severity       = "critical"
        mitre_tactic   = "Execution"
        mitre_technique = "T1059.001"
        author         = "ThreatTrace"
        false_positives = "Legitimate software installers"

    strings:
        $d1 = "IEX(New-Object Net.WebClient).DownloadString" nocase
        $d2 = "(New-Object System.Net.WebClient).DownloadFile" nocase
        $d3 = "Invoke-Expression (New-Object" nocase
        $d4 = "[System.Net.WebRequest]::Create" nocase
        $d5 = "bitsadmin /transfer" nocase
        $d6 = "certutil -urlcache -split -f" nocase
        $d7 = "certutil.exe -decode" nocase
        $d8 = "Start-BitsTransfer" nocase
        $d9 = "Invoke-WebRequest" nocase

    condition:
        any of them
}

rule LOLBins_Execution {
    meta:
        rule_id        = "yara:windows:LOLBins_Execution"
        description    = "Detects Living-off-the-Land Binary abuse for execution"
        severity       = "high"
        mitre_tactic   = "Defense Evasion"
        mitre_technique = "T1218"
        author         = "ThreatTrace"
        false_positives = "Legitimate admin use of these tools"

    strings:
        $l1 = "regsvr32 /s /n /u /i:http" nocase
        $l2 = "mshta.exe http" nocase
        $l3 = "rundll32.exe javascript:" nocase
        $l4 = "wscript.exe //e:javascript" nocase
        $l5 = "cscript.exe //e:javascript" nocase
        $l6 = "installutil.exe /logfile=" nocase
        $l7 = "msbuild.exe " nocase
        $l8 = "odbcconf.exe /a {regsvr" nocase
        $l9 = "pcalua.exe -a" nocase
        $l10 = "wmic process call create" nocase
        $l11 = "xwizard.exe" nocase
        $l12 = "forfiles /p" nocase

    condition:
        any of them
}

rule WMI_LateralMovement {
    meta:
        rule_id        = "yara:windows:WMI_LateralMovement"
        description    = "Detects WMI-based lateral movement and remote execution"
        severity       = "high"
        mitre_tactic   = "Lateral Movement"
        mitre_technique = "T1021.006"
        author         = "ThreatTrace"

    strings:
        $w1 = "wmic /node:" nocase
        $w2 = "wmic /user: /password:" nocase
        $w3 = "Win32_Process.Create" nocase
        $w4 = "Win32_ProcessStartup" nocase
        $w5 = "WmiExec" nocase
        $w6 = "wmiexec.py" nocase
        $w7 = "impacket" nocase

    condition:
        any of them
}

rule Credential_Dumping_LSASS {
    meta:
        rule_id        = "yara:windows:Credential_Dumping_LSASS"
        description    = "Detects LSASS memory access for credential dumping"
        severity       = "critical"
        mitre_tactic   = "Credential Access"
        mitre_technique = "T1003.001"
        author         = "ThreatTrace"

    strings:
        $s1 = "procdump" nocase
        $s2 = "procdump.exe -ma lsass" nocase
        $s3 = "lsass.dmp" nocase
        $s4 = "tasklist /v /fo csv" nocase
        $s5 = "comsvcs.dll MiniDump" nocase
        $s6 = "Out-Minidump" nocase
        $s7 = "NanoDump" nocase
        $s8 = "HandleKatz" nocase

    condition:
        any of them
}

rule EventLog_Clearing {
    meta:
        rule_id        = "yara:windows:EventLog_Clearing"
        description    = "Detects Windows event log clearing commands"
        severity       = "critical"
        mitre_tactic   = "Defense Evasion"
        mitre_technique = "T1070.001"
        author         = "ThreatTrace"

    strings:
        $s1 = "wevtutil cl " nocase
        $s2 = "wevtutil clear-log" nocase
        $s3 = "Clear-EventLog" nocase
        $s4 = "Remove-EventLog" nocase
        $s5 = "wevtutil el | Foreach {wevtutil cl" nocase

    condition:
        any of them
}

rule PsExec_LateralMovement {
    meta:
        rule_id        = "yara:windows:PsExec_LateralMovement"
        description    = "Detects PsExec usage for lateral movement"
        severity       = "high"
        mitre_tactic   = "Lateral Movement"
        mitre_technique = "T1021.002"
        author         = "ThreatTrace"

    strings:
        $p1 = "psexec" nocase
        $p2 = "\\\\.*\\IPC$" nocase
        $p3 = "PSEXESVC" nocase
        $p4 = "psexec64" nocase
        $p5 = "RemoteExec" nocase

    condition:
        any of them
}

rule Ransomware_Indicators {
    meta:
        rule_id        = "yara:windows:Ransomware_Indicators"
        description    = "Detects ransomware-related file extension patterns and commands"
        severity       = "critical"
        mitre_tactic   = "Impact"
        mitre_technique = "T1486"
        author         = "ThreatTrace"

    strings:
        $ext1 = ".locky" nocase
        $ext2 = ".zepto" nocase
        $ext3 = ".cerber" nocase
        $ext4 = ".encrypted" nocase
        $ext5 = ".WNCRYPT" nocase
        $ext6 = ".WNCRYT" nocase
        $ext7 = ".lockbit" nocase
        $cmd1 = "vssadmin delete shadows /all" nocase
        $cmd2 = "bcdedit /set {default} recoveryenabled No" nocase
        $cmd3 = "wbadmin delete catalog -quiet" nocase
        $cmd4 = "cipher /w:" nocase

    condition:
        any of them
}
