rule ThreatTrace_Linux_BashReverse {
    meta:
        description = "Bash reverse shell via /dev/tcp"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1059.004"
    strings:
        $bash1 = "/dev/tcp/"
        $bash2 = "bash -i >&"
        $bash3 = "bash -i >& /dev/tcp"
        $bash4 = "0>&1"
        $bash5 = "0<&196"
    condition:
        any of ($bash*)
}

rule ThreatTrace_Linux_NetcatReverse {
    meta:
        description = "Netcat reverse shell"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1059.004"
    strings:
        $nc1 = "nc -e /bin/bash" nocase
        $nc2 = "nc -e /bin/sh" nocase
        $nc3 = "ncat --exec" nocase
        $nc4 = "nc -lvp" nocase
        $nc5 = "nc.exe -e" nocase
    condition:
        any of ($nc*)
}

rule ThreatTrace_Linux_PythonReverse {
    meta:
        description = "Python reverse shell one-liner"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1059.004"
    strings:
        $py1 = "python -c 'import socket,subprocess"
        $py2 = "python3 -c 'import socket"
        $py3 = "s.connect(("
        $py4 = "os.dup2(s.fileno()"
    condition:
        any of ($py*)
}

rule ThreatTrace_Linux_SocatReverse {
    meta:
        description = "Socat reverse shell"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1059.004"
    strings:
        $socat1 = "socat TCP:"
        $socat2 = "socat EXEC:"
        $socat3 = "socat tcp-connect"
    condition:
        any of ($socat*)
}

rule ThreatTrace_Linux_PerlReverse {
    meta:
        description = "Perl/PHP/Ruby reverse shell"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1059.004"
    strings:
        $p1 = "perl -e 'use Socket"
        $p2 = "php -r '$sock=fsockopen"
        $p3 = "ruby -rsocket -e"
    condition:
        any of ($p*)
}
