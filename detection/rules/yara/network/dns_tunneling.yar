rule ThreatTrace_DNSTunnel_Tools {
    meta:
        description = "DNS tunneling tool names"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1071.004"
    strings:
        $t1 = "iodine" nocase
        $t2 = "dnscat" nocase
        $t3 = "dns2tcp" nocase
        $t4 = "DNScat" nocase
        $t5 = "ozymandns" nocase
    condition:
        any of ($t*)
}

rule ThreatTrace_DNSTunnel_LongQuery {
    meta:
        description = "Excessively long DNS query subdomain"
        author = "ThreatTrace"
        severity = "MEDIUM"
        mitre_technique = "T1071.004"
    strings:
        $long = /[a-zA-Z0-9+\/]{50,}\.[a-zA-Z]{2,}/
    condition:
        $long
}

rule ThreatTrace_DNSTunnel_Base64Subdomain {
    meta:
        description = "Base64-encoded data in DNS subdomain"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1071.004"
    strings:
        $b64 = /[A-Za-z0-9+\/]{30,}={0,2}\.[a-z]{2,}/
    condition:
        $b64
}

rule ThreatTrace_DNSTunnel_TXTQuery {
    meta:
        description = "High volume TXT record queries"
        author = "ThreatTrace"
        severity = "MEDIUM"
        mitre_technique = "T1071.004"
    strings:
        $txt1 = " TXT "
        $txt2 = "type=TXT"
        $txt3 = "qtype=16"
        $txt4 = "IN TXT"
    condition:
        any of ($txt*)
}
