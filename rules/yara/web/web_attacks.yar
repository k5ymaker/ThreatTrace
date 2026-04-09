/*
  ThreatTrace YARA Rules — Web Attack Patterns
  Detects: SQL injection, XSS, path traversal, web shells, scanner activity
*/

rule SQLInjection_Classic {
    meta:
        rule_id        = "yara:web:SQLInjection_Classic"
        description    = "Detects classic SQL injection patterns in HTTP request logs"
        severity       = "high"
        mitre_tactic   = "Initial Access"
        mitre_technique = "T1190"
        reference      = "https://attack.mitre.org/techniques/T1190/"
        author         = "ThreatTrace"
        false_positives = "Legitimate SQL debugging tools"

    strings:
        $s1 = "' OR '1'='1" nocase
        $s2 = "' OR 1=1--" nocase
        $s3 = "UNION SELECT" nocase
        $s4 = "UNION ALL SELECT" nocase
        $s5 = "1' AND '1'='1" nocase
        $s6 = "'; DROP TABLE" nocase
        $s7 = "'; INSERT INTO" nocase
        $s8 = "SELECT * FROM" nocase
        $s9 = "--+&" nocase
        $s10 = "0x31303235343830303536" nocase
        $s11 = "benchmark(10000000," nocase
        $s12 = "sleep(0x" nocase
        $s13 = "waitfor delay" nocase

    condition:
        any of them
}

rule SQLInjection_Advanced {
    meta:
        rule_id        = "yara:web:SQLInjection_Advanced"
        description    = "Detects advanced/encoded SQL injection attempts"
        severity       = "high"
        mitre_tactic   = "Initial Access"
        mitre_technique = "T1190"
        author         = "ThreatTrace"
        false_positives = "URL-encoded form submissions"

    strings:
        $hex1 = "%27%20OR%20%271%27%3D%271" nocase  // ' OR '1'='1
        $hex2 = "%27%20UNION%20SELECT" nocase
        $hex3 = "0x27204f5220" nocase               // hex encoded
        $comment1 = "/*!UNION*/"
        $comment2 = "/**/UNION/**/"
        $comment3 = "UNION%20SELECT"

    condition:
        any of them
}

rule PathTraversal {
    meta:
        rule_id        = "yara:web:PathTraversal"
        description    = "Detects directory/path traversal attempts"
        severity       = "high"
        mitre_tactic   = "Discovery"
        mitre_technique = "T1083"
        author         = "ThreatTrace"
        false_positives = "Legitimate path references in URLs"

    strings:
        $t1 = "../../../etc/passwd"
        $t2 = "..%2F..%2F..%2Fetc%2Fpasswd" nocase
        $t3 = "..\\..\\..\\windows\\system32" nocase
        $t4 = "%2e%2e%2f" nocase
        $t5 = "....//....//....//etc/passwd"
        $t6 = "/etc/shadow"
        $t7 = "/proc/self/environ"
        $t8 = "file:///etc/passwd"
        $t9 = "C:\\Windows\\System32\\cmd.exe" nocase
        $t10 = "%252e%252e%252f" nocase  // double-encoded

    condition:
        any of them
}

rule XSS_Patterns {
    meta:
        rule_id        = "yara:web:XSS_Patterns"
        description    = "Detects Cross-Site Scripting (XSS) payloads in HTTP logs"
        severity       = "medium"
        mitre_tactic   = "Execution"
        mitre_technique = "T1059.007"
        author         = "ThreatTrace"
        false_positives = "Security scanner testing"

    strings:
        $x1 = "<script>alert(" nocase
        $x2 = "<script>document.cookie" nocase
        $x3 = "javascript:alert(" nocase
        $x4 = "onerror=alert(" nocase
        $x5 = "onload=alert(" nocase
        $x6 = "%3Cscript%3Ealert(" nocase
        $x7 = "<img src=x onerror=" nocase
        $x8 = "eval(atob(" nocase
        $x9 = "String.fromCharCode(" nocase
        $x10 = "&#x3C;script&#x3E;" nocase

    condition:
        any of them
}

rule WebShell_Access {
    meta:
        rule_id        = "yara:web:WebShell_Access"
        description    = "Detects access to common web shell file names and patterns"
        severity       = "critical"
        mitre_tactic   = "Persistence"
        mitre_technique = "T1505.003"
        author         = "ThreatTrace"
        false_positives = "Security tools named similarly"

    strings:
        $w1 = "c99.php" nocase
        $w2 = "r57.php" nocase
        $w3 = "b374k.php" nocase
        $w4 = "wso.php" nocase
        $w5 = "shell.php" nocase
        $w6 = "cmd.php" nocase
        $w7 = "upload.php?cmd=" nocase
        $w8 = "?cmd=whoami" nocase
        $w9 = "?cmd=id" nocase
        $w10 = "/webshell" nocase
        $w11 = "weevely" nocase
        $w12 = "<?php system(" nocase
        $w13 = "passthru($_GET" nocase
        $w14 = "exec($_REQUEST" nocase

    condition:
        any of them
}

rule ScannerUserAgents {
    meta:
        rule_id        = "yara:web:ScannerUserAgents"
        description    = "Detects known vulnerability scanner and attack tool user agents"
        severity       = "medium"
        mitre_tactic   = "Discovery"
        mitre_technique = "T1595"
        author         = "ThreatTrace"
        false_positives = "Authorized penetration testing"

    strings:
        $ua1 = "sqlmap" nocase
        $ua2 = "nikto" nocase
        $ua3 = "masscan" nocase
        $ua4 = "nessus" nocase
        $ua5 = "openvas" nocase
        $ua6 = "w3af" nocase
        $ua7 = "acunetix" nocase
        $ua8 = "burpsuite" nocase
        $ua9 = "zgrab" nocase
        $ua10 = "dirbuster" nocase
        $ua11 = "gobuster" nocase
        $ua12 = "hydra" nocase
        $ua13 = "metasploit" nocase
        $ua14 = "python-httpx" nocase
        $ua15 = "python-requests/2" nocase

    condition:
        any of them
}

rule LFI_Patterns {
    meta:
        rule_id        = "yara:web:LFI_Patterns"
        description    = "Detects Local File Inclusion (LFI) attempts"
        severity       = "high"
        mitre_tactic   = "Initial Access"
        mitre_technique = "T1190"
        author         = "ThreatTrace"

    strings:
        $l1 = "?page=php://input" nocase
        $l2 = "?page=php://filter" nocase
        $l3 = "?file=php://filter/convert.base64-encode/resource=" nocase
        $l4 = "include=http://" nocase
        $l5 = "?page=http://" nocase
        $l6 = "php://filter/read=convert.base64-encode" nocase
        $l7 = "data://text/plain;base64," nocase
        $l8 = "phar://" nocase
        $l9 = "zip://" nocase

    condition:
        any of them
}
