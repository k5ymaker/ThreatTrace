rule ThreatTrace_Persistence_ScheduledTask {
    meta:
        description = "Suspicious scheduled task creation via command line"
        author = "ThreatTrace"
        severity = "MEDIUM"
        mitre_technique = "T1053.005"
    strings:
        $st1 = "schtasks /create" nocase
        $st2 = "schtasks.exe /create" nocase
        $st3 = "SchTasks /Create" nocase
    condition:
        any of ($st*)
}

rule ThreatTrace_Persistence_RunKey {
    meta:
        description = "Persistence via Registry Run key modification"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1547.001"
    strings:
        $run1 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $run2 = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $run3 = "CurrentVersion\\Run" nocase
        $run4 = "CurrentVersion\\RunOnce" nocase
    condition:
        any of ($run*)
}

rule ThreatTrace_Persistence_ServiceCreation {
    meta:
        description = "Service creation for persistence"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1543.003"
    strings:
        $svc1 = "sc create" nocase
        $svc2 = "sc.exe create" nocase
        $svc3 = "New-Service" nocase
        $svc4 = "CreateService" nocase
    condition:
        any of ($svc*)
}

rule ThreatTrace_Persistence_WMISubscription {
    meta:
        description = "WMI event subscription for persistence"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1546.003"
    strings:
        $wmi1 = "__EventFilter" nocase
        $wmi2 = "__EventConsumer" nocase
        $wmi3 = "__FilterToConsumerBinding" nocase
        $wmi4 = "ActiveScriptEventConsumer" nocase
        $wmi5 = "CommandLineEventConsumer" nocase
    condition:
        any of ($wmi*)
}

rule ThreatTrace_Persistence_StartupFolder {
    meta:
        description = "Startup folder persistence"
        author = "ThreatTrace"
        severity = "MEDIUM"
        mitre_technique = "T1547.001"
    strings:
        $su1 = "\\Start Menu\\Programs\\Startup\\" nocase
        $su2 = "\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\" nocase
        $su3 = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu" nocase
    condition:
        any of ($su*)
}
