rule ThreatTrace_Exfil_CloudStorage {
    meta:
        description = "Data exfiltration to public cloud storage"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1567.002"
    strings:
        $cs1 = "mega.nz" nocase
        $cs2 = "anonfiles.com" nocase
        $cs3 = "transfer.sh" nocase
        $cs4 = "file.io" nocase
        $cs5 = "gofile.io" nocase
        $cs6 = "pastebin.com" nocase
        $cs7 = "ghostbin.com" nocase
        $cs8 = "hastebin.com" nocase
        $cs9 = "tempfile.ninja" nocase
        $cs10 = "pixeldrain.com" nocase
    condition:
        any of ($cs*)
}

rule ThreatTrace_Exfil_FTPExternal {
    meta:
        description = "FTP transfer to external host"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1048.003"
    strings:
        $ftp1 = "ftp://"
        $ftp2 = "STOR " nocase
        $ftp3 = "PUT " nocase
        $ftp4 = "passive mode" nocase
    condition:
        any of ($ftp*)
}

rule ThreatTrace_Exfil_LargePost {
    meta:
        description = "Suspicious large HTTP POST request"
        author = "ThreatTrace"
        severity = "MEDIUM"
        mitre_technique = "T1041"
    strings:
        $post = "POST"
        $large1 = "Content-Length: 1000000"
        $large2 = "bytes=10485760"
    condition:
        $post and any of ($large*)
}

rule ThreatTrace_Exfil_EncodedDNS {
    meta:
        description = "Encoded data in DNS query names"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1048.001"
    strings:
        $hex = /[0-9a-f]{40,}\.[a-z]{2,6}/
        $b64 = /[A-Za-z0-9+\/]{30,}={0,2}\./
    condition:
        any of them
}
