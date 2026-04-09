/*
  ThreatTrace YARA Rules — Linux Attack Patterns
  Detects: Privilege escalation, persistence, reverse shells, crypto miners
*/

rule Linux_PrivEsc_SUID {
    meta:
        rule_id        = "yara:linux:Linux_PrivEsc_SUID"
        description    = "Detects SUID/SGID exploitation for privilege escalation"
        severity       = "high"
        mitre_tactic   = "Privilege Escalation"
        mitre_technique = "T1548.001"
        author         = "ThreatTrace"

    strings:
        $s1 = "find / -perm -4000" nocase
        $s2 = "find / -perm -u=s" nocase
        $s3 = "find / -perm /6000" nocase
        $s4 = "-perm -4000 -type f" nocase
        $s5 = "chmod 4755" nocase
        $s6 = "chmod u+s" nocase
        $s7 = "cp /bin/sh /tmp/sh; chmod 4755 /tmp/sh" nocase

    condition:
        any of them
}

rule Linux_Cron_Persistence {
    meta:
        rule_id        = "yara:linux:Linux_Cron_Persistence"
        description    = "Detects suspicious cron job creation for persistence"
        severity       = "high"
        mitre_tactic   = "Persistence"
        mitre_technique = "T1053.003"
        author         = "ThreatTrace"

    strings:
        $c1 = "/etc/cron.d/" nocase
        $c2 = "crontab -" nocase
        $c3 = "* * * * * root" nocase
        $c4 = "/var/spool/cron/" nocase
        $c5 = "bash -i >& /dev/tcp/" nocase
        $c6 = "* * * * * curl" nocase
        $c7 = "* * * * * wget" nocase

    condition:
        any of them
}

rule Reverse_Shell_Patterns {
    meta:
        rule_id        = "yara:linux:Reverse_Shell_Patterns"
        description    = "Detects reverse shell command patterns"
        severity       = "critical"
        mitre_tactic   = "Command and Control"
        mitre_technique = "T1059.004"
        author         = "ThreatTrace"

    strings:
        $rs1 = "bash -i >& /dev/tcp/" nocase
        $rs2 = "bash -i >& /dev/udp/" nocase
        $rs3 = "0<&196;exec 196<>/dev/tcp/" nocase
        $rs4 = "python -c 'import socket,subprocess,os" nocase
        $rs5 = "python3 -c 'import socket" nocase
        $rs6 = "perl -e 'use Socket;" nocase
        $rs7 = "ruby -rsocket -e" nocase
        $rs8 = "nc -e /bin/sh" nocase
        $rs9 = "ncat -e /bin/sh" nocase
        $rs10 = "mkfifo /tmp/f;cat /tmp/f|/bin/sh" nocase
        $rs11 = "rm /tmp/f;mkfifo /tmp/f" nocase
        $rs12 = "php -r '$sock=fsockopen(" nocase

    condition:
        any of them
}

rule CryptoMiner_Indicators {
    meta:
        rule_id        = "yara:linux:CryptoMiner_Indicators"
        description    = "Detects cryptocurrency miner installation or execution"
        severity       = "high"
        mitre_tactic   = "Impact"
        mitre_technique = "T1496"
        author         = "ThreatTrace"

    strings:
        $m1 = "xmrig" nocase
        $m2 = "monero" nocase
        $m3 = "stratum+tcp://" nocase
        $m4 = "cryptonight" nocase
        $m5 = "pool.minexmr.com" nocase
        $m6 = "nanopool.org" nocase
        $m7 = "minergate" nocase
        $m8 = "ethermine.org" nocase
        $m9 = "/var/tmp/kworker" nocase
        $m10 = "wget http://85." nocase

    condition:
        any of them
}

rule SSH_AuthorizedKeys_Modification {
    meta:
        rule_id        = "yara:linux:SSH_AuthorizedKeys_Modification"
        description    = "Detects modification of SSH authorized_keys for persistence"
        severity       = "critical"
        mitre_tactic   = "Persistence"
        mitre_technique = "T1098.004"
        author         = "ThreatTrace"

    strings:
        $s1 = ".ssh/authorized_keys" nocase
        $s2 = "echo >> ~/.ssh/authorized_keys" nocase
        $s3 = "tee -a ~/.ssh/authorized_keys" nocase
        $s4 = "echo \"ssh-rsa" nocase
        $s5 = "chmod 600 ~/.ssh/authorized_keys" nocase

    condition:
        any of them
}

rule Passwd_Shadow_Access {
    meta:
        rule_id        = "yara:linux:Passwd_Shadow_Access"
        description    = "Detects access to /etc/shadow or /etc/passwd for credential harvesting"
        severity       = "critical"
        mitre_tactic   = "Credential Access"
        mitre_technique = "T1003.008"
        author         = "ThreatTrace"

    strings:
        $s1 = "cat /etc/shadow" nocase
        $s2 = "cat /etc/passwd" nocase
        $s3 = "unshadow /etc/passwd /etc/shadow" nocase
        $s4 = "john --wordlist" nocase
        $s5 = "hashcat -m 1800" nocase

    condition:
        any of them
}

rule Sudo_Abuse {
    meta:
        rule_id        = "yara:linux:Sudo_Abuse"
        description    = "Detects sudo privilege escalation patterns"
        severity       = "high"
        mitre_tactic   = "Privilege Escalation"
        mitre_technique = "T1548.003"
        author         = "ThreatTrace"

    strings:
        $s1 = "sudo -l" nocase
        $s2 = "sudo su -" nocase
        $s3 = "sudo /bin/bash" nocase
        $s4 = "sudo python3 -c" nocase
        $s5 = "sudo awk 'BEGIN {system(" nocase
        $s6 = "echo 'ALL ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers" nocase

    condition:
        any of them
}
