/*
 * ThreatTrace YARA Rules - Local File Inclusion / Remote File Inclusion
 * Category: Apache / Web Application
 * Author: ThreatTrace
 */

rule ThreatTrace_LFI_PathTraversal {
    meta:
        description = "LFI - Directory traversal sequence detected in request"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1083"
    strings:
        $t1 = "../../../" ascii
        $t2 = "..%2F..%2F..%2F" nocase
        $t3 = "..%252F..%252F" nocase
        $t4 = "..%c0%af" nocase
        $t5 = "..%c1%9c" nocase
        $t6 = "..\\..\\..\\" ascii
        $t7 = "..%5c..%5c" nocase
        $t8 = "....//....//....%2F" nocase
        $t9 = "..%2f..%2f" nocase
    condition:
        any of them
}

rule ThreatTrace_LFI_SensitiveLinuxFiles {
    meta:
        description = "LFI - Attempt to read sensitive Linux system files"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1083"
    strings:
        $f1 = "/etc/passwd" ascii
        $f2 = "/etc/shadow" ascii
        $f3 = "/etc/hosts" ascii
        $f4 = "/etc/group" ascii
        $f5 = "/etc/sudoers" ascii
        $f6 = "/etc/ssh/sshd_config" ascii
        $f7 = "/root/.bash_history" ascii
        $f8 = "/root/.ssh/id_rsa" ascii
    condition:
        any of them
}

rule ThreatTrace_LFI_ProcFilesystem {
    meta:
        description = "LFI - Attempt to access Linux /proc filesystem entries"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1083"
    strings:
        $p1 = "/proc/self/environ" ascii
        $p2 = "/proc/self/cmdline" ascii
        $p3 = "/proc/self/fd/" ascii
        $p4 = "/proc/self/maps" ascii
        $p5 = "/proc/version" ascii
        $p6 = "/proc/net/tcp" ascii
        $p7 = "proc%2fself%2fenviron" nocase
        $p8 = "proc/self/environ" ascii
    condition:
        any of them
}

rule ThreatTrace_LFI_PHPWrappers {
    meta:
        description = "LFI - PHP stream wrapper abuse (php://input, php://filter)"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1190"
    strings:
        $w1 = "php://input" nocase
        $w2 = "php://filter" nocase
        $w3 = "php://fd" nocase
        $w4 = "php://memory" nocase
        $w5 = "php://temp" nocase
        $w6 = "php%3A%2F%2Ffilter" nocase
        $w7 = "php%3A%2F%2Finput" nocase
        $w8 = "convert.base64-decode" nocase
    condition:
        any of them
}

rule ThreatTrace_RFI_FileWrapper {
    meta:
        description = "RFI - file:// wrapper used to access local filesystem via RFI"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1190"
    strings:
        $f1 = "file:///etc/" ascii
        $f2 = "file:///" ascii
        $f3 = "file%3A%2F%2F%2F" nocase
        $f4 = "file%3a%2f%2f" nocase
    condition:
        any of them
}

rule ThreatTrace_RFI_DangerousWrappers {
    meta:
        description = "RFI - expect:// or data:// PHP wrapper abuse for code execution"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1190"
    strings:
        $e1 = "expect://" nocase
        $e2 = "expect%3A%2F%2F" nocase
        $d1 = "data://" nocase
        $d2 = "data:text/plain" nocase
        $d3 = "data:application/x-httpd-php" nocase
        $z1 = "zip://" nocase
        $z2 = "phar://" nocase
    condition:
        any of them
}

rule ThreatTrace_LFI_WindowsPathTraversal {
    meta:
        description = "LFI - Windows path traversal sequences targeting system files"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1083"
    strings:
        $w1 = "..\\..\\..\\windows" nocase
        $w2 = "..%5c..%5cwindows" nocase
        $w3 = "/windows/win.ini" nocase
        $w4 = "c:\\windows\\system32" nocase
        $w5 = "c%3A%5Cwindows%5Csystem32" nocase
        $w6 = "boot.ini" nocase
        $w7 = "\\windows\\system32\\drivers\\etc\\hosts" nocase
        $w8 = "c:/windows/win.ini" nocase
    condition:
        any of them
}

rule ThreatTrace_RFI_RemoteInclusion {
    meta:
        description = "RFI - Remote file inclusion via HTTP or FTP in include parameter"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1190"
    strings:
        $r1 = "include=http://" nocase
        $r2 = "include=https://" nocase
        $r3 = "include=ftp://" nocase
        $r4 = "page=http://" nocase
        $r5 = "file=http://" nocase
        $r6 = "path=http://" nocase
        $r7 = "url=http://" nocase
        $r8 = "src=http://" nocase
    condition:
        any of them
}
