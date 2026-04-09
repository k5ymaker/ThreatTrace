rule ThreatTrace_PrivEsc_SUID {
    meta:
        description = "SUID bit setting for privilege escalation"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1548.001"
    strings:
        $suid1 = "chmod u+s" nocase
        $suid2 = "chmod 4755" nocase
        $suid3 = "chmod +s" nocase
        $suid4 = "chmod 4777" nocase
    condition:
        any of ($suid*)
}

rule ThreatTrace_PrivEsc_SudoAbuse {
    meta:
        description = "Sudo abuse or /etc/sudoers modification"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1548.003"
    strings:
        $sudo1 = "echo '' >> /etc/sudoers" nocase
        $sudo2 = "ALL=(ALL) NOPASSWD" nocase
        $sudo3 = "sudo -l" nocase
        $sudo4 = "sudo su" nocase
        $sudo5 = "visudo" nocase
    condition:
        any of ($sudo*)
}

rule ThreatTrace_PrivEsc_PasswdMod {
    meta:
        description = "Password file manipulation for privilege escalation"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1098"
    strings:
        $pw1 = "passwd -d root" nocase
        $pw2 = "echo '' >> /etc/passwd" nocase
        $pw3 = "usermod -aG sudo" nocase
        $pw4 = "adduser.*sudo" nocase
        $pw5 = "openssl passwd" nocase
    condition:
        any of ($pw*)
}

rule ThreatTrace_PrivEsc_DirtyCow {
    meta:
        description = "Dirty COW or pkexec privilege escalation"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1068"
    strings:
        $dc1 = "dirtycow" nocase
        $dc2 = "CVE-2016-5195" nocase
        $dc3 = "CVE-2021-4034" nocase
        $dc4 = "pkexec" nocase
    condition:
        any of ($dc*)
}
