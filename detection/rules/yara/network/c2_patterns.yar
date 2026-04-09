rule ThreatTrace_C2_CobaltStrikeURI {
    meta:
        description = "Cobalt Strike default beacon URIs"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1071.001"
    strings:
        $cs1 = "/jquery-3.3.1.slim.min.js"
        $cs2 = "/pixel.gif"
        $cs3 = "/updates.rss"
        $cs4 = "/load"
        $cs5 = "/ca"
        $cs6 = "/submit.php"
        $cs7 = "/cm"
        $cs8 = "/logout"
    condition:
        any of ($cs*)
}

rule ThreatTrace_C2_MetasploitURI {
    meta:
        description = "Metasploit handler default URIs"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1071.001"
    strings:
        $msf1 = "/AAAA"
        $msf2 = "/s/ref="
        $msf3 = "/search?"
        $msf4 = "/index.php?a="
    condition:
        any of ($msf*)
}

rule ThreatTrace_C2_EmpireURI {
    meta:
        description = "PowerShell Empire C2 default URIs"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1071.001"
    strings:
        $emp1 = "/news.php"
        $emp2 = "/admin/get.php"
        $emp3 = "/login/process.php"
        $emp4 = "/admin/login"
    condition:
        any of ($emp*)
}

rule ThreatTrace_C2_SliverC2 {
    meta:
        description = "Sliver C2 framework patterns"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1071.001"
    strings:
        $sliver1 = "sliver" nocase
        $sliver2 = "implant" nocase
        $sliver3 = ".sliver-client"
        $sliver4 = "SLIVER_" nocase
    condition:
        any of ($sliver*)
}

rule ThreatTrace_C2_OldUserAgent {
    meta:
        description = "C2 framework using outdated user-agent strings"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1071.001"
    strings:
        $ua1 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)"
        $ua2 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)"
        $ua3 = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"
    condition:
        any of ($ua*)
}
