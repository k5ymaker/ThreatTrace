/*
 * ThreatTrace YARA Rules - Web Shell Detection
 * Category: Apache / Web Application
 * Author: ThreatTrace
 */

rule ThreatTrace_Webshell_SuspiciousParameters {
    meta:
        description = "Webshell - Suspicious shell command parameters in HTTP POST body"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1505.003"
    strings:
        $p1 = "cmd=" ascii
        $p2 = "exec=" ascii
        $p3 = "command=" ascii
        $p4 = "execute=" ascii
        $p5 = "shell=" ascii
        $p6 = "run=" ascii
        $p7 = "query=" ascii
        $p8 = "payload=" ascii
    condition:
        any of them
}

rule ThreatTrace_Webshell_KnownFilenames {
    meta:
        description = "Webshell - Known webshell filenames accessed via HTTP"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1505.003"
    strings:
        $fn1 = "c99.php" nocase
        $fn2 = "r57.php" nocase
        $fn3 = "shell.php" nocase
        $fn4 = "wso.php" nocase
        $fn5 = "b374k.php" nocase
        $fn6 = "weevely.php" nocase
        $fn7 = "laudanum.php" nocase
        $fn8 = "alfa.php" nocase
        $fn9 = "indoxploit.php" nocase
        $fn10 = "WSO.php" ascii
        $fn11 = "FilesMan.php" nocase
        $fn12 = "webshell.php" nocase
    condition:
        any of them
}

rule ThreatTrace_Webshell_EvalBase64Request {
    meta:
        description = "Webshell - eval(base64_decode) pattern in HTTP request indicating PHP webshell execution"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1505.003"
    strings:
        $e1 = "eval(base64_decode" nocase
        $e2 = "eval(gzinflate(base64_decode" nocase
        $e3 = "eval(str_rot13" nocase
        $e4 = "eval(gzuncompress" nocase
        $e5 = "assert(base64_decode" nocase
        $e6 = "preg_replace.*eval" nocase
        $e7 = "eval%28base64_decode" nocase
    condition:
        any of them
}

rule ThreatTrace_Webshell_PHPExecFunctions {
    meta:
        description = "Webshell - PHP OS command execution functions in HTTP parameters"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1505.003"
    strings:
        $f1 = "system(" nocase
        $f2 = "passthru(" nocase
        $f3 = "shell_exec(" nocase
        $f4 = "popen(" nocase
        $f5 = "proc_open(" nocase
        $f6 = "pcntl_exec(" nocase
        $f7 = "exec(" nocase
        $f8 = "assert(" nocase
    condition:
        2 of them
}

rule ThreatTrace_Webshell_PHPOpenTag {
    meta:
        description = "Webshell - PHP opening tag with eval injection in request body"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1505.003"
    strings:
        $tag1 = "<?php eval(" nocase
        $tag2 = "<?php system(" nocase
        $tag3 = "<?php passthru(" nocase
        $tag4 = "<?php shell_exec(" nocase
        $tag5 = "<?php @eval(" nocase
        $tag6 = "<?php @system(" nocase
        $tag7 = "%3C%3Fphp+eval" nocase
        $tag8 = "<?php" ascii
    condition:
        1 of ($tag1, $tag2, $tag3, $tag4, $tag5, $tag6, $tag7)
}

rule ThreatTrace_Webshell_ChinaChopper {
    meta:
        description = "Webshell - China Chopper webshell characteristic strings"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1505.003"
    strings:
        $cc1 = "eval(Request.Item[" nocase
        $cc2 = "eval(Request[" nocase
        $cc3 = "Response.Write(md5(" nocase
        $cc4 = "caidao" nocase
        $cc5 = "Response.End" nocase
        $cc6 = "Request.Item" nocase
        $cc7 = "Server.CreateObject" nocase
    condition:
        2 of them
}

rule ThreatTrace_Webshell_B374kWeevely {
    meta:
        description = "Webshell - b374k or Weevely shell characteristic strings"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1505.003"
    strings:
        $b1 = "b374k" nocase
        $b2 = "weevely" nocase
        $b3 = "FilesMan" nocase
        $b4 = "PassWD" ascii
        $b5 = "getimagesize" nocase
        $b6 = "php_uname" nocase
        $b7 = "posix_getpwuid" nocase
        $b8 = "disk_free_space" nocase
    condition:
        2 of them
}

rule ThreatTrace_Webshell_PostToPHP {
    meta:
        description = "Webshell - POST request to PHP file containing OS command strings"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1505.003"
    strings:
        $method = "POST" ascii
        $php = ".php" ascii
        $cmd1 = "/bin/sh" ascii
        $cmd2 = "/bin/bash" ascii
        $cmd3 = "cmd.exe" nocase
        $cmd4 = "powershell" nocase
        $cmd5 = "wget " ascii
        $cmd6 = "curl " ascii
    condition:
        $method and $php and any of ($cmd*)
}
