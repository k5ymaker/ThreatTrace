/*
 * ThreatTrace YARA Rules - Security Scanner User-Agent Detection
 * Category: Apache / Web Application
 * Author: ThreatTrace
 */

rule ThreatTrace_Scanner_SQLmap {
    meta:
        description = "Scanner - sqlmap SQL injection scanner User-Agent detected"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1595.002"
    strings:
        $ua1 = "sqlmap" nocase
        $ua2 = "sqlmap/" nocase
        $ua3 = "python-requests" nocase
    condition:
        $ua1 or $ua2
}

rule ThreatTrace_Scanner_NiktoWebScanner {
    meta:
        description = "Scanner - Nikto web vulnerability scanner User-Agent detected"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1595.002"
    strings:
        $ua1 = "Nikto" nocase
        $ua2 = "nikto/" nocase
        $ua3 = "Nikto/2" ascii
    condition:
        any of them
}

rule ThreatTrace_Scanner_NmapScripts {
    meta:
        description = "Scanner - Nmap or Nmap NSE script User-Agent in HTTP request"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1595.001"
    strings:
        $ua1 = "Nmap Scripting Engine" ascii
        $ua2 = "nmap" nocase
        $ua3 = "NSE/" ascii
    condition:
        any of them
}

rule ThreatTrace_Scanner_Masscan {
    meta:
        description = "Scanner - masscan port/banner scanner User-Agent detected"
        author = "ThreatTrace"
        severity = "MEDIUM"
        mitre_technique = "T1595.001"
    strings:
        $ua1 = "masscan" nocase
        $ua2 = "masscan/" nocase
    condition:
        any of them
}

rule ThreatTrace_Scanner_OwaspZAP {
    meta:
        description = "Scanner - OWASP ZAP web application scanner User-Agent detected"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1595.002"
    strings:
        $ua1 = "OWASP_ZAP" ascii
        $ua2 = "ZAP/" ascii
        $ua3 = "zaproxy" nocase
    condition:
        any of them
}

rule ThreatTrace_Scanner_BurpSuite {
    meta:
        description = "Scanner - Burp Suite proxy/scanner User-Agent detected"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1595.002"
    strings:
        $ua1 = "BurpSuite" nocase
        $ua2 = "Burp Suite" nocase
        $ua3 = "burp" nocase
    condition:
        any of them
}

rule ThreatTrace_Scanner_VulnerabilityScanner {
    meta:
        description = "Scanner - Commercial vulnerability scanner (Acunetix, Nessus, OpenVAS) detected"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1595.002"
    strings:
        $ua1 = "Acunetix" nocase
        $ua2 = "acunetix-product" nocase
        $ua3 = "Nessus" nocase
        $ua4 = "OpenVAS" nocase
        $ua5 = "Tenable" nocase
    condition:
        any of them
}

rule ThreatTrace_Scanner_DirectoryBruteforce {
    meta:
        description = "Scanner - Directory brute-force tool (DirBuster, gobuster, ffuf, feroxbuster) User-Agent"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1595.002"
    strings:
        $ua1 = "DirBuster" nocase
        $ua2 = "dirbuster" nocase
        $ua3 = "gobuster" nocase
        $ua4 = "wfuzz" nocase
        $ua5 = "ffuf" nocase
        $ua6 = "feroxbuster" nocase
        $ua7 = "dirsearch" nocase
    condition:
        any of them
}

rule ThreatTrace_Scanner_BruteForceTools {
    meta:
        description = "Scanner - Password brute-force tools (hydra, medusa) User-Agent detected"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1110"
    strings:
        $ua1 = "Hydra" nocase
        $ua2 = "THC-Hydra" ascii
        $ua3 = "Medusa" nocase
        $ua4 = "patator" nocase
    condition:
        any of them
}

rule ThreatTrace_Scanner_ExploitFrameworks {
    meta:
        description = "Scanner - Exploitation framework (Metasploit, Nuclei) User-Agent detected"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1190"
    strings:
        $ua1 = "Metasploit" nocase
        $ua2 = "msfconsole" nocase
        $ua3 = "nuclei" nocase
        $ua4 = "Nuclei -" ascii
        $ua5 = "libwww-perl" nocase
        $ua6 = "exploit" nocase
    condition:
        any of them
}
