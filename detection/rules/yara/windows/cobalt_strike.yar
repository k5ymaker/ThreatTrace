/*
 * ThreatTrace YARA Rules - Cobalt Strike Beacon Detection
 * Category: Windows
 * Author: ThreatTrace
 */

rule ThreatTrace_CobaltStrike_NamedPipes {
    meta:
        description = "Cobalt Strike - Named pipe patterns used by Beacon for inter-process communication"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1559.001"
    strings:
        $np1 = "msagent_" ascii
        $np2 = "postex_" ascii
        $np3 = "mojo." ascii
        $np4 = "status_" ascii
        $np5 = "interprocess_" ascii
        $np6 = "MSSE-" ascii
        $np7 = "ntsvcs" ascii
        $np8 = "scerpc" ascii
        $np9 = "wkssvc" ascii
    condition:
        2 of them
}

rule ThreatTrace_CobaltStrike_BeaconStagingURIs {
    meta:
        description = "Cobalt Strike - Beacon staging and callback URI patterns"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1071.001"
    strings:
        $u1 = "/jquery-3." ascii
        $u2 = "/pixel.gif" ascii
        $u3 = "/updates.rss" ascii
        $u4 = "/load" ascii
        $u5 = "/ca" ascii
        $u6 = "/fwlink" ascii
        $u7 = "/match" ascii
        $u8 = "/tab_assets/" ascii
    condition:
        any of them
}

rule ThreatTrace_CobaltStrike_PowerShellSleepJitter {
    meta:
        description = "Cobalt Strike - PowerShell beacon sleep with jitter calculation pattern"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1027"
    strings:
        $s1 = "Start-Sleep -Seconds" ascii
        $s2 = "Start-Sleep -s" ascii
        $jit1 = "jitter" nocase
        $jit2 = "Get-Random" ascii
        $get  = "Get-Random -Minimum" ascii
        $iex  = "IEX" ascii
    condition:
        ($s1 or $s2) and ($jit1 or $jit2 or $get)
}

rule ThreatTrace_CobaltStrike_ShellcodePatterns {
    meta:
        description = "Cobalt Strike - HeapAlloc/VirtualAlloc shellcode loader pattern"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1055"
    strings:
        $va  = "VirtualAlloc" ascii
        $wp  = "VirtualProtect" ascii
        $ha  = "HeapAlloc" ascii
        $crt = "CreateThread" ascii
        $ru  = "RtlMoveMemory" ascii
        $hex = { FC 48 83 E4 F0 E8 C0 00 00 00 41 51 41 50 }  // CS x64 beacon prologue
    condition:
        $hex or (3 of ($va, $wp, $ha, $crt, $ru))
}

rule ThreatTrace_CobaltStrike_BinaryStrings {
    meta:
        description = "Cobalt Strike - Characteristic strings found in CS Beacon artifacts"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1027"
    strings:
        $cs1 = "cobaltstrike" nocase
        $cs2 = "CobaltStrike" ascii
        $cs3 = "cs_beacon" ascii
        $cs4 = "beacon.dll" nocase
        $cs5 = "ReflectiveDll" ascii
        $cs6 = "ReflectiveLoader" ascii
        $cs7 = "beacon_gate" ascii
    condition:
        any of them
}

rule ThreatTrace_CobaltStrike_MallowableC2 {
    meta:
        description = "Cobalt Strike - Malleable C2 profile indicator strings"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1071.001"
    strings:
        $m1 = "set useragent" nocase
        $m2 = "set sleeptime" nocase
        $m3 = "http-beacon" nocase
        $m4 = "prepend" nocase
        $m5 = "set uri" nocase
        $m6 = "stage {" ascii
        $m7 = "set compile_time" nocase
    condition:
        3 of them
}

rule ThreatTrace_CobaltStrike_ProcessInjection {
    meta:
        description = "Cobalt Strike - Process injection technique strings used by Beacon"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1055.001"
    strings:
        $p1 = "OpenProcess" ascii
        $p2 = "WriteProcessMemory" ascii
        $p3 = "CreateRemoteThread" ascii
        $p4 = "NtCreateThreadEx" ascii
        $p5 = "QueueUserAPC" ascii
        $p6 = "SetThreadContext" ascii
        $p7 = "SuspendThread" ascii
        $p8 = "ResumeThread" ascii
    condition:
        4 of them
}
