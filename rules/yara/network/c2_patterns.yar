/*
  ThreatTrace YARA Rules — C2 and Network Attack Patterns
  Detects: Cobalt Strike, Metasploit, DNS tunneling, beaconing indicators
*/

rule CobaltStrike_Indicators {
    meta:
        rule_id        = "yara:network:CobaltStrike_Indicators"
        description    = "Detects Cobalt Strike C2 framework indicators in network logs"
        severity       = "critical"
        mitre_tactic   = "Command and Control"
        mitre_technique = "T1071.001"
        reference      = "https://attack.mitre.org/techniques/T1071/001/"
        author         = "ThreatTrace"
        false_positives = "Red team exercises"

    strings:
        $cs1 = "__utma" nocase
        $cs2 = "checksum8" nocase
        $cs3 = "/jquery-3.3.1.min.js" nocase
        $cs4 = "x-forwarded-for" nocase
        $cs5 = "X-Malware-Behaviors" nocase
        $cs6 = "AAAAAAAA" nocase
        $cs7 = "Content-Type: application/octet-stream\r\nContent-Length: 0" nocase
        $cs8 = "/s/ref=nb_sb_noss_1" nocase  // Amazon Malleable C2
        $cs9 = "/api/2/slack.rtm.start" nocase  // Slack Malleable C2
        $cs10 = "beacon.x64" nocase
        $cs11 = "CobaltStrike" nocase

    condition:
        any of them
}

rule Metasploit_Indicators {
    meta:
        rule_id        = "yara:network:Metasploit_Indicators"
        description    = "Detects Metasploit Framework indicators in network logs"
        severity       = "critical"
        mitre_tactic   = "Command and Control"
        mitre_technique = "T1071"
        author         = "ThreatTrace"
        false_positives = "Authorized penetration testing"

    strings:
        $m1 = "Metasploit" nocase
        $m2 = "meterpreter" nocase
        $m3 = "mettle" nocase
        $m4 = "/multi/handler" nocase
        $m5 = "PAYLOAD_UUID" nocase
        $m6 = "Msf::Handler" nocase

    condition:
        any of them
}

rule DNS_Tunneling {
    meta:
        rule_id        = "yara:network:DNS_Tunneling"
        description    = "Detects DNS tunneling tool signatures"
        severity       = "high"
        mitre_tactic   = "Exfiltration"
        mitre_technique = "T1048.003"
        author         = "ThreatTrace"

    strings:
        $t1 = "iodine" nocase
        $t2 = "dns2tcp" nocase
        $t3 = "dnscat2" nocase
        $t4 = "dnscapy" nocase
        $t5 = "tuns" nocase
        $t6 = "powerdns" nocase

    condition:
        any of them
}

rule Tor_Proxy_Usage {
    meta:
        rule_id        = "yara:network:Tor_Proxy_Usage"
        description    = "Detects Tor network and proxy usage for C2 anonymization"
        severity       = "high"
        mitre_tactic   = "Command and Control"
        mitre_technique = "T1090.003"
        author         = "ThreatTrace"

    strings:
        $t1 = ".onion" nocase
        $t2 = "tor2web" nocase
        $t3 = "torify" nocase
        $t4 = "SOCKS5 127.0.0.1:9050" nocase
        $t5 = "ProxyChains" nocase
        $t6 = "torsocks" nocase

    condition:
        any of them
}

rule Data_Exfiltration_CloudStorage {
    meta:
        rule_id        = "yara:network:Data_Exfiltration_CloudStorage"
        description    = "Detects large data transfers to cloud storage that may indicate exfiltration"
        severity       = "medium"
        mitre_tactic   = "Exfiltration"
        mitre_technique = "T1567.002"
        author         = "ThreatTrace"

    strings:
        $s1 = "PUT https://s3.amazonaws.com" nocase
        $s2 = "upload.blob.core.windows.net" nocase
        $s3 = "storage.googleapis.com" nocase
        $s4 = "api.dropboxapi.com/2/files/upload" nocase
        $s5 = "content.dropboxapi.com/2/files/upload" nocase
        $s6 = "graph.microsoft.com/v1.0/drive/root" nocase

    condition:
        any of them
}
