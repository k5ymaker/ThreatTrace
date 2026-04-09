/*
 * ThreatTrace YARA Rules - C2 Beaconing via Web Logs
 * Category: Apache / Web Application
 * Author: ThreatTrace
 */

rule ThreatTrace_C2_CobaltStrikeDefaultURIs {
    meta:
        description = "C2 - Cobalt Strike default beacon staging and communication URIs"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1071.001"
    strings:
        $uri1 = "/jquery-3." ascii
        $uri2 = "/pixel.gif" ascii
        $uri3 = "/updates.rss" ascii
        $uri4 = "/load" ascii
        $uri5 = "/match" ascii
        $uri6 = "/submit.php" ascii
        $uri7 = "/ca" ascii
        $uri8 = "/ptj" ascii
        $uri9 = "/jquery-3.3.1.slim.min.js" ascii
        $uri10 = "/image.gif" ascii
    condition:
        2 of them
}

rule ThreatTrace_C2_MetasploitDefaultURIs {
    meta:
        description = "C2 - Metasploit reverse handler default communication URIs"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1071.001"
    strings:
        $uri1 = "/s/ref=" ascii
        $uri2 = "/AAAA" ascii
        $uri3 = "/pki/" ascii
        $uri4 = "/favicon.ico" ascii
        $ua1  = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)" ascii
        $ua2  = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)" ascii
    condition:
        2 of them
}

rule ThreatTrace_C2_MeterpreterUserAgent {
    meta:
        description = "C2 - Meterpreter characteristic User-Agent strings in HTTP requests"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1071.001"
    strings:
        $ua1 = "Meterpreter" nocase
        $ua2 = "meterpreter" ascii
        $ua3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" ascii
    condition:
        any of them
}

rule ThreatTrace_C2_EmpireC2URIs {
    meta:
        description = "C2 - PowerShell Empire C2 framework communication URI patterns"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1071.001"
    strings:
        $uri1 = "/news.php" ascii
        $uri2 = "/admin/get.php" ascii
        $uri3 = "/login/process.php" ascii
        $uri4 = "/admin/agent.php" ascii
        $uri5 = "/index.jsp" ascii
        $uri6 = "/index.php?l=" ascii
    condition:
        any of them
}

rule ThreatTrace_C2_PoshC2Patterns {
    meta:
        description = "C2 - PoshC2 framework characteristic request patterns"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1071.001"
    strings:
        $uri1 = "/imgs/" ascii
        $uri2 = "/assets/" ascii
        $cookie1 = "SESSIONID=" ascii
        $ua1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit" ascii
        $posh1 = "PoshC2" nocase
        $posh2 = "posh_v2_" nocase
    condition:
        2 of them
}

rule ThreatTrace_C2_SliverC2Patterns {
    meta:
        description = "C2 - Sliver C2 framework communication patterns in HTTP logs"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1071.001"
    strings:
        $s1 = "sliver" nocase
        $s2 = "/rpc" ascii
        $s3 = "Sliver/" ascii
        $s4 = "/api/" ascii
        $hdr = "Content-Type: application/grpc" ascii
    condition:
        any of ($s1, $s3, $s4, $hdr)
}

rule ThreatTrace_C2_CovenantPatterns {
    meta:
        description = "C2 - Covenant C2 framework Grunt beacon communication patterns"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1071.001"
    strings:
        $c1 = "Covenant" nocase
        $c2 = "/GruntHTTP" ascii
        $c3 = "/grunt" nocase
        $c4 = "GruntId=" ascii
        $c5 = "GruntTasking" ascii
    condition:
        any of them
}

rule ThreatTrace_C2_SuspiciousBeaconUA {
    meta:
        description = "C2 - Suspicious outdated User-Agent strings commonly used by C2 beacons"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1071.001"
    strings:
        $ua1 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)" ascii
        $ua2 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)" ascii
        $ua3 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)" ascii
        $ua4 = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36" ascii
    condition:
        any of them
}
