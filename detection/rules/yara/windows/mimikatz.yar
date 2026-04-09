/*
 * ThreatTrace YARA Rules - Mimikatz Credential Dumping Detection
 * Category: Windows
 * Author: ThreatTrace
 */

rule ThreatTrace_Mimikatz_CommandLineArgs {
    meta:
        description = "Mimikatz - Command-line arguments for credential dumping operations"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1003.001"
    strings:
        $cmd1 = "sekurlsa::logonpasswords" nocase
        $cmd2 = "sekurlsa::wdigest" nocase
        $cmd3 = "sekurlsa::kerberos" nocase
        $cmd4 = "sekurlsa::msv" nocase
        $cmd5 = "sekurlsa::tspkg" nocase
        $cmd6 = "sekurlsa::livessp" nocase
    condition:
        any of them
}

rule ThreatTrace_Mimikatz_DCSyncLSA {
    meta:
        description = "Mimikatz - DCSync and LSA dump commands for domain credential theft"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1003.006"
    strings:
        $lsa1 = "lsadump::dcsync" nocase
        $lsa2 = "lsadump::lsa" nocase
        $lsa3 = "lsadump::sam" nocase
        $lsa4 = "lsadump::secrets" nocase
        $lsa5 = "lsadump::cache" nocase
        $lsa6 = "lsadump::trust" nocase
    condition:
        any of them
}

rule ThreatTrace_Mimikatz_PrivilegeDebug {
    meta:
        description = "Mimikatz - Privilege escalation and debug token acquisition"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1134.001"
    strings:
        $priv1 = "privilege::debug" nocase
        $priv2 = "privilege::security" nocase
        $tok1  = "token::elevate" nocase
        $tok2  = "token::impersonate" nocase
        $tok3  = "token::list" nocase
        $tok4  = "token::run" nocase
    condition:
        any of them
}

rule ThreatTrace_Mimikatz_PassTheHash {
    meta:
        description = "Mimikatz - Pass-the-Hash command using sekurlsa::pth"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1550.002"
    strings:
        $pth1 = "sekurlsa::pth" nocase
        $pth2 = "/ntlm:" nocase
        $pth3 = "/aes256:" nocase
        $pth4 = "/user:" nocase
        $pth5 = "/domain:" nocase
        $pth6 = "sekurlsa::pth /user" nocase
    condition:
        $pth1 or ($pth2 and $pth4 and $pth5)
}

rule ThreatTrace_Mimikatz_KerberosTickets {
    meta:
        description = "Mimikatz - Kerberos ticket manipulation (golden, silver, list)"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1558.001"
    strings:
        $k1 = "kerberos::list" nocase
        $k2 = "kerberos::golden" nocase
        $k3 = "kerberos::silver" nocase
        $k4 = "kerberos::ptt" nocase
        $k5 = "kerberos::purge" nocase
        $k6 = "kerberos::tgt" nocase
    condition:
        any of them
}

rule ThreatTrace_Mimikatz_BinaryStrings {
    meta:
        description = "Mimikatz - Characteristic binary strings found in Mimikatz executable"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1003.001"
    strings:
        $bin1 = "mimikatz" nocase
        $bin2 = "mimilib" nocase
        $bin3 = "mimidrv" nocase
        $bin4 = "SEKURLSA_DATA" ascii
        $bin5 = "CREDENTIALS_DATA" ascii
        $bin6 = "gentilkiwi" ascii
        $bin7 = "benjamin@gentilkiwi.com" ascii
        $bin8 = "mimilove" ascii
    condition:
        2 of them
}

rule ThreatTrace_Mimikatz_DPAPIAndCrypto {
    meta:
        description = "Mimikatz - DPAPI and crypto module commands for credential decryption"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1555.004"
    strings:
        $d1 = "dpapi::chrome" nocase
        $d2 = "dpapi::cred" nocase
        $d3 = "dpapi::vault" nocase
        $d4 = "dpapi::masterkey" nocase
        $d5 = "crypto::capi" nocase
        $d6 = "crypto::cng" nocase
        $d7 = "dpapi::blob" nocase
    condition:
        any of them
}
