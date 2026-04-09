rule ThreatTrace_AWS_IAMEnum {
    meta:
        description = "AWS IAM enumeration API calls"
        author = "ThreatTrace"
        severity = "MEDIUM"
        mitre_technique = "T1087.004"
    strings:
        $iam1 = "ListUsers" nocase
        $iam2 = "ListRoles" nocase
        $iam3 = "ListPolicies" nocase
        $iam4 = "ListGroups" nocase
        $iam5 = "GetAccountAuthorizationDetails" nocase
        $iam6 = "GetAccountSummary" nocase
    condition:
        any of ($iam*)
}

rule ThreatTrace_AWS_S3Enum {
    meta:
        description = "AWS S3 bucket enumeration"
        author = "ThreatTrace"
        severity = "MEDIUM"
        mitre_technique = "T1530"
    strings:
        $s3_1 = "ListBuckets" nocase
        $s3_2 = "GetBucketAcl" nocase
        $s3_3 = "GetBucketPolicy" nocase
        $s3_4 = "ListObjects" nocase
    condition:
        any of ($s3_*)
}

rule ThreatTrace_AWS_EC2Enum {
    meta:
        description = "AWS EC2 infrastructure enumeration"
        author = "ThreatTrace"
        severity = "MEDIUM"
        mitre_technique = "T1580"
    strings:
        $ec1 = "DescribeInstances" nocase
        $ec2 = "DescribeSecurityGroups" nocase
        $ec3 = "DescribeVpcs" nocase
        $ec4 = "DescribeSubnets" nocase
        $ec5 = "DescribeRouteTables" nocase
    condition:
        any of ($ec*)
}

rule ThreatTrace_AWS_CredentialAbuse {
    meta:
        description = "AWS credential abuse patterns"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1078.004"
    strings:
        $cred1 = "GetCallerIdentity" nocase
        $cred2 = "AssumeRole" nocase
        $cred3 = "GetSessionToken" nocase
        $cred4 = "ConsoleLogin" nocase
    condition:
        any of ($cred*)
}
