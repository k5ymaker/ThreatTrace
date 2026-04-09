rule ThreatTrace_Ransomware_ShadowCopy {
    meta:
        description = "Ransomware shadow copy deletion"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1490"
    strings:
        $vss1 = "vssadmin delete shadows" nocase
        $vss2 = "vssadmin Delete Shadows /All" nocase
        $vss3 = "wbadmin delete catalog" nocase
        $vss4 = "bcdedit /set recoveryenabled no" nocase
        $vss5 = "bcdedit /set bootstatuspolicy ignoreallfailures" nocase
    condition:
        any of ($vss*)
}

rule ThreatTrace_Ransomware_NoteFiles {
    meta:
        description = "Ransomware ransom note file names"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1486"
    strings:
        $note1 = "README.txt" nocase
        $note2 = "DECRYPT" nocase
        $note3 = "HOW_TO_DECRYPT" nocase
        $note4 = "YOUR_FILES_ARE_ENCRYPTED" nocase
        $note5 = "RECOVERY_KEY" nocase
        $note6 = "how_to_recover" nocase
        $note7 = "HELP_DECRYPT" nocase
        $note8 = "_readme.txt" nocase
    condition:
        any of ($note*)
}

rule ThreatTrace_Ransomware_Extensions {
    meta:
        description = "Known ransomware encrypted file extensions"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1486"
    strings:
        $ext1 = ".encrypted"
        $ext2 = ".locked"
        $ext3 = ".crypt"
        $ext4 = ".enc"
        $ext5 = ".crypted"
        $ext6 = ".ryk"
        $ext7 = ".maze"
        $ext8 = ".sodinokibi"
        $ext9 = ".revil"
        $ext10 = ".darkside"
        $ext11 = ".conti"
        $ext12 = ".lockbit"
        $ext13 = ".ryuk"
        $ext14 = ".wannacry"
    condition:
        any of ($ext*)
}

rule ThreatTrace_Ransomware_ProcessKill {
    meta:
        description = "Ransomware AV/backup process termination"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1489"
    strings:
        $kill1 = "taskkill /f /im" nocase
        $kill2 = "net stop" nocase
        $kill3 = "sc stop" nocase
    condition:
        any of ($kill*)
}

rule ThreatTrace_Ransomware_BackupDeletion {
    meta:
        description = "Ransomware backup deletion commands"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1490"
    strings:
        $bk1 = "del /f /s /q" nocase
        $bk2 = "wbadmin delete" nocase
        $bk3 = "ntbackup" nocase
        $bk4 = "diskshadow /s" nocase
    condition:
        any of ($bk*)
}
