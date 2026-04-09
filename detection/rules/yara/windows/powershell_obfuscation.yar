rule ThreatTrace_PS_EncodedCommand {
    meta:
        description = "PowerShell encoded command execution"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1059.001"
    strings:
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-EncodedC" nocase
        $enc3 = " -enc " nocase
        $enc4 = " -ec " nocase
    condition:
        any of ($enc*)
}

rule ThreatTrace_PS_DownloadCradle {
    meta:
        description = "PowerShell download cradle"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1059.001"
    strings:
        $dl1 = "DownloadString(" nocase
        $dl2 = "DownloadFile(" nocase
        $dl3 = "WebClient" nocase
        $dl4 = "Net.Sockets.TCPClient" nocase
        $dl5 = "Invoke-WebRequest" nocase
        $dl6 = "iwr " nocase
        $dl7 = "curl " nocase
        $dl8 = "wget " nocase
    condition:
        any of ($dl*)
}

rule ThreatTrace_PS_InvokeExpression {
    meta:
        description = "PowerShell Invoke-Expression obfuscation"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1059.001"
    strings:
        $iex1 = "IEX(" nocase
        $iex2 = "Invoke-Expression" nocase
        $iex3 = "FromBase64String(" nocase
        $iex4 = "::FromBase64String" nocase
    condition:
        any of ($iex*)
}

rule ThreatTrace_PS_AMSIBypass {
    meta:
        description = "PowerShell AMSI bypass attempt"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1562.001"
    strings:
        $amsi1 = "AmsiScanBuffer" nocase
        $amsi2 = "amsiInitFailed" nocase
        $amsi3 = "[Runtime.InteropServices.Marshal]::WriteInt32" nocase
        $amsi4 = "System.Management.Automation.AmsiUtils" nocase
        $amsi5 = "amsiContext" nocase
    condition:
        any of ($amsi*)
}

rule ThreatTrace_PS_EmpireMarkers {
    meta:
        description = "PowerShell Empire C2 framework markers"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1059.001"
    strings:
        $emp1 = "Invoke-Mimikatz" nocase
        $emp2 = "Invoke-Shellcode" nocase
        $emp3 = "Out-EncodedCommand" nocase
        $emp4 = "Invoke-Obfuscation" nocase
        $emp5 = "PowerSploit" nocase
        $emp6 = "Empire" nocase
    condition:
        any of ($emp*)
}

rule ThreatTrace_PS_HiddenWindow {
    meta:
        description = "PowerShell hidden window execution"
        author = "ThreatTrace"
        severity = "MEDIUM"
        mitre_technique = "T1059.001"
    strings:
        $hw1 = "-WindowStyle Hidden" nocase
        $hw2 = "-w hidden" nocase
        $hw3 = "-nop" nocase
        $hw4 = "-NonInteractive" nocase
        $hw5 = "-noni" nocase
    condition:
        2 of ($hw*)
}
