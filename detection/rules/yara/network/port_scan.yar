rule ThreatTrace_PortScan_NmapUA {
    meta:
        description = "Nmap port scanner user agent or patterns"
        author = "ThreatTrace"
        severity = "MEDIUM"
        mitre_technique = "T1046"
    strings:
        $nmap1 = "Nmap" nocase
        $nmap2 = "nmap" nocase
        $nmap3 = "(Nmap" nocase
        $nmap4 = "nmap NSE" nocase
    condition:
        any of ($nmap*)
}

rule ThreatTrace_PortScan_Masscan {
    meta:
        description = "Masscan port scanner"
        author = "ThreatTrace"
        severity = "MEDIUM"
        mitre_technique = "T1046"
    strings:
        $ms1 = "masscan" nocase
        $ms2 = "Masscan" nocase
        $ms3 = "mass scan" nocase
    condition:
        any of ($ms*)
}

rule ThreatTrace_PortScan_ZMap {
    meta:
        description = "ZMap internet-wide scanner"
        author = "ThreatTrace"
        severity = "MEDIUM"
        mitre_technique = "T1046"
    strings:
        $zm1 = "ZMap" nocase
        $zm2 = "zmap" nocase
        $zm3 = "Shodan" nocase
        $zm4 = "Censys" nocase
    condition:
        any of ($zm*)
}

rule ThreatTrace_PortScan_ConnectionRefused {
    meta:
        description = "Mass connection refused pattern in logs"
        author = "ThreatTrace"
        severity = "LOW"
        mitre_technique = "T1046"
    strings:
        $cr1 = "Connection refused" nocase
        $cr2 = "connection refused" nocase
        $cr3 = "ECONNREFUSED" nocase
    condition:
        any of ($cr*)
}
