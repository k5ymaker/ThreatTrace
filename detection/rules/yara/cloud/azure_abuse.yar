rule ThreatTrace_Azure_RoleEscalation {
    meta:
        description = "Azure role assignment for privilege escalation"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1098.003"
    strings:
        $role1 = "Microsoft.Authorization/roleAssignments/write" nocase
        $role2 = "roleAssignments" nocase
        $role3 = "Owner" nocase
        $role4 = "Contributor" nocase
    condition:
        any of ($role*)
}

rule ThreatTrace_Azure_KeyVaultAccess {
    meta:
        description = "Azure Key Vault suspicious access"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1552.001"
    strings:
        $kv1 = "Microsoft.KeyVault" nocase
        $kv2 = "vaults/secrets" nocase
        $kv3 = "KeyVaultGet" nocase
        $kv4 = "SecretGet" nocase
    condition:
        any of ($kv*)
}

rule ThreatTrace_Azure_StorageAbuse {
    meta:
        description = "Azure storage account key manipulation"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1530"
    strings:
        $sa1 = "Microsoft.Storage/storageAccounts/listkeys" nocase
        $sa2 = "regenerateKey" nocase
        $sa3 = "storageAccounts/write" nocase
    condition:
        any of ($sa*)
}
