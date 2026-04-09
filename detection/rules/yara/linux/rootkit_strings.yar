rule ThreatTrace_Rootkit_KnownNames {
    meta:
        description = "Known rootkit name strings"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1014"
    strings:
        $rk1 = "reptile" nocase
        $rk2 = "diamorphine" nocase
        $rk3 = "azazel" nocase
        $rk4 = "beurk" nocase
        $rk5 = "kovid" nocase
        $rk6 = "Adore-Ng" nocase
        $rk7 = "suckit" nocase
        $rk8 = "knark" nocase
    condition:
        any of ($rk*)
}

rule ThreatTrace_Rootkit_LDPreload {
    meta:
        description = "LD_PRELOAD rootkit injection"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1574.006"
    strings:
        $ldp1 = "LD_PRELOAD="
        $ldp2 = "/etc/ld.so.preload"
        $ldp3 = "ld.so.preload"
    condition:
        any of ($ldp*)
}

rule ThreatTrace_Rootkit_KernelHook {
    meta:
        description = "Kernel-level rootkit strings"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1014"
    strings:
        $kh1 = "sys_call_table"
        $kh2 = "kallsyms_lookup_name"
        $kh3 = "hide_pid"
        $kh4 = "hide_file"
        $kh5 = "module_hidden"
    condition:
        any of ($kh*)
}

rule ThreatTrace_Rootkit_LKM {
    meta:
        description = "Loadable Kernel Module rootkit indicators"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1547.006"
    strings:
        $lkm1 = "insmod"
        $lkm2 = "modprobe"
        $lkm3 = "init_module"
        $lkm4 = "cleanup_module"
        $lkm5 = "module_init("
    condition:
        any of ($lkm*)
}
