rule ThreatTrace_CredStuffing_MultiUser {
    meta:
        description = "Credential stuffing - multiple username attempts"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1110.004"
    strings:
        $fail1 = "Failed password for"
        $fail2 = "Failed password for invalid user"
        $user1 = "Invalid user"
        $post = "POST"
        $login = "/login"
    condition:
        ($fail1 or $fail2 or $user1) and ($post or $login)
}

rule ThreatTrace_CredStuffing_AutomatedUA {
    meta:
        description = "Automated credential stuffing user agent"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1110.004"
    strings:
        $ua1 = "python-requests" nocase
        $ua2 = "Go-http-client" nocase
        $ua3 = "Wget/" nocase
        $ua4 = "curl/" nocase
        $ua5 = "libwww-perl" nocase
    condition:
        any of ($ua*)
}
