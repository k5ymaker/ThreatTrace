rule ThreatTrace_Miner_Stratum {
    meta:
        description = "Cryptocurrency mining pool stratum protocol"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1496"
    strings:
        $st1 = "stratum+tcp://" nocase
        $st2 = "stratum+ssl://" nocase
        $st3 = "pool.supportxmr.com" nocase
        $st4 = "xmrpool.eu" nocase
        $st5 = "c3pool.com" nocase
        $st6 = "minexmr.com" nocase
        $st7 = "hashvault.pro" nocase
    condition:
        any of ($st*)
}

rule ThreatTrace_Miner_XMRig {
    meta:
        description = "XMRig cryptocurrency miner"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1496"
    strings:
        $xmr1 = "xmrig" nocase
        $xmr2 = "xmrig-cpu" nocase
        $xmr3 = "xmrig-nvidia" nocase
        $xmr4 = "--donate-level 0" nocase
        $xmr5 = "RandomX" nocase
        $xmr6 = "cryptonight" nocase
    condition:
        any of ($xmr*)
}

rule ThreatTrace_Miner_WalletAddress {
    meta:
        description = "Monero wallet address in logs"
        author = "ThreatTrace"
        severity = "MEDIUM"
        mitre_technique = "T1496"
    strings:
        $wallet = /4[0-9A-Za-z]{94}/
    condition:
        $wallet
}

rule ThreatTrace_Miner_NiceHash {
    meta:
        description = "NiceHash mining service"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1496"
    strings:
        $nh1 = "nicehash" nocase
        $nh2 = "nanopool" nocase
        $nh3 = "ethermine" nocase
        $nh4 = "f2pool" nocase
        $nh5 = "antpool" nocase
    condition:
        any of ($nh*)
}
