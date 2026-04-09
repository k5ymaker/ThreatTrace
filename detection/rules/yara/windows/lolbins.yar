/*
 * ThreatTrace YARA Rules - Living Off the Land Binaries (LOLBins)
 * Category: Windows
 * Author: ThreatTrace
 */

rule ThreatTrace_LOLBin_Certutil {
    meta:
        description = "LOLBin - certutil used for file download or base64 decode"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1105"
    strings:
        $c1 = "certutil -decode" nocase
        $c2 = "certutil -urlcache" nocase
        $c3 = "certutil -urlcache -split -f http" nocase
        $c4 = "certutil.exe -urlcache" nocase
        $c5 = "certutil -encode" nocase
        $c6 = "certutil /decode" nocase
        $c7 = "certutil /urlcache" nocase
    condition:
        any of them
}

rule ThreatTrace_LOLBin_Regsvr32Squiblydoo {
    meta:
        description = "LOLBin - regsvr32 Squiblydoo technique for remote script execution"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1218.010"
    strings:
        $r1 = "regsvr32 /s /n /u /i:http" nocase
        $r2 = "regsvr32.exe /s /n /u /i:" nocase
        $r3 = "regsvr32 /s /u /i:http" nocase
        $r4 = "regsvr32 /s /n /i:http" nocase
        $r5 = "regsvr32" nocase
        $http = "http" nocase
        $scrobj = "scrobj.dll" nocase
    condition:
        ($r1 or $r2 or $r3 or $r4) or ($r5 and $http and $scrobj)
}

rule ThreatTrace_LOLBin_Mshta {
    meta:
        description = "LOLBin - mshta used to execute remote HTA or JavaScript"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1218.005"
    strings:
        $m1 = "mshta http://" nocase
        $m2 = "mshta https://" nocase
        $m3 = "mshta javascript:" nocase
        $m4 = "mshta vbscript:" nocase
        $m5 = "mshta.exe http" nocase
        $m6 = "mshta.exe javascript:" nocase
    condition:
        any of them
}

rule ThreatTrace_LOLBin_WscriptCscript {
    meta:
        description = "LOLBin - wscript or cscript executing remote or obfuscated scripts"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1059.005"
    strings:
        $w1 = "wscript //e:" nocase
        $w2 = "wscript.exe //e:" nocase
        $w3 = "wscript //b" nocase
        $c1 = "cscript //e:" nocase
        $c2 = "cscript.exe //e:" nocase
        $c3 = "cscript //b" nocase
    condition:
        any of them
}

rule ThreatTrace_LOLBin_Rundll32 {
    meta:
        description = "LOLBin - rundll32 executing JavaScript or suspicious DLLs"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1218.011"
    strings:
        $r1 = "rundll32 javascript:" nocase
        $r2 = "rundll32.exe javascript:" nocase
        $r3 = "rundll32 advpack.dll" nocase
        $r4 = "rundll32 ieadvpack.dll" nocase
        $r5 = "rundll32 syssetup.dll" nocase
        $r6 = "rundll32 setupapi.dll" nocase
        $r7 = "rundll32 url.dll,OpenURL" nocase
    condition:
        any of them
}

rule ThreatTrace_LOLBin_BitsadminMsiexec {
    meta:
        description = "LOLBin - bitsadmin or msiexec used for remote file download and execution"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1197"
    strings:
        $b1 = "bitsadmin /transfer" nocase
        $b2 = "bitsadmin /download" nocase
        $b3 = "bitsadmin.exe /transfer" nocase
        $m1 = "msiexec /q /i http" nocase
        $m2 = "msiexec /quiet /i http" nocase
        $m3 = "msiexec.exe /q /i http" nocase
    condition:
        any of them
}

rule ThreatTrace_LOLBin_Forfiles {
    meta:
        description = "LOLBin - forfiles used to execute commands via /c parameter"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1218"
    strings:
        $f1 = "forfiles /p" nocase
        $f2 = "forfiles /m" nocase
        $f3 = "forfiles /c cmd" nocase
        $f4 = "forfiles.exe /c" nocase
    condition:
        any of them
}

rule ThreatTrace_LOLBin_MiscLolbins {
    meta:
        description = "LOLBin - Miscellaneous LOLBins (pcalua, esentutl, finger, desktopimgdownldr)"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1218"
    strings:
        $p1 = "pcalua.exe -a" nocase
        $e1 = "esentutl.exe /y" nocase
        $e2 = "esentutl /y /d" nocase
        $f1 = "finger.exe " nocase
        $d1 = "desktopimgdownldr.exe" nocase
        $a1 = "AppInstaller.exe http" nocase
        $x1 = "expand -R" nocase
        $cmd1 = "cmdkey.exe /list" nocase
    condition:
        any of them
}
