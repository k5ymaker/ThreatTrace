rule ThreatTrace_PtH_NTLMAuth {
    meta:
        description = "Pass-the-Hash NTLM authentication"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1550.002"
    strings:
        $ntlm1 = "NTLM" nocase
        $ntlm2 = "NTLMv2" nocase
        $ntlm3 = "LogonType: 3" nocase
        $ntlm4 = "LogonType=3" nocase
    condition:
        any of ($ntlm*)
}

rule ThreatTrace_PtH_Mimikatz {
    meta:
        description = "Pass-the-Hash via Mimikatz sekurlsa::pth"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1550.002"
    strings:
        $pth1 = "sekurlsa::pth" nocase
        $pth2 = "pth-winexe" nocase
        $pth3 = "pth-net" nocase
        $pth4 = "pth-smbclient" nocase
    condition:
        any of ($pth*)
}

rule ThreatTrace_PtH_Overpass {
    meta:
        description = "Overpass-the-Hash / Pass-the-Ticket"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1550.003"
    strings:
        $oph1 = "kerberos::ptt" nocase
        $oph2 = "Rubeus.exe" nocase
        $oph3 = ".kirbi" nocase
        $oph4 = "golden ticket" nocase
        $oph5 = "silver ticket" nocase
    condition:
        any of ($oph*)
}
