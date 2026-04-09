rule ThreatTrace_IAM_AdminPolicyAttach {
    meta:
        description = "IAM admin policy attachment"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1098"
    strings:
        $iam1 = "AttachUserPolicy" nocase
        $iam2 = "AttachRolePolicy" nocase
        $iam3 = "AdministratorAccess" nocase
        $iam4 = "PutUserPolicy" nocase
        $iam5 = "arn:aws:iam::aws:policy/AdministratorAccess"
    condition:
        any of ($iam*)
}

rule ThreatTrace_IAM_CreateAccessKey {
    meta:
        description = "IAM access key creation"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1098"
    strings:
        $ak1 = "CreateAccessKey" nocase
        $ak2 = "access_key_id" nocase
        $ak3 = "AKIA"
        $ak4 = "secret_access_key" nocase
    condition:
        any of ($ak*)
}

rule ThreatTrace_IAM_TrailDeletion {
    meta:
        description = "CloudTrail deletion or disabling (audit evasion)"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1070"
    strings:
        $ct1 = "DeleteTrail" nocase
        $ct2 = "StopLogging" nocase
        $ct3 = "DisableLogging" nocase
        $ct4 = "UpdateTrail" nocase
        $ct5 = "PutBucketPolicy" nocase
    condition:
        any of ($ct*)
}
