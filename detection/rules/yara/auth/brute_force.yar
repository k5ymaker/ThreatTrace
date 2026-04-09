rule ThreatTrace_BruteForce_FailedPassword {
    meta:
        description = "Failed password/authentication attempts"
        author = "ThreatTrace"
        severity = "MEDIUM"
        mitre_technique = "T1110.001"
    strings:
        $fp1 = "Failed password" nocase
        $fp2 = "authentication failure" nocase
        $fp3 = "Invalid user" nocase
        $fp4 = "Login incorrect" nocase
        $fp5 = "FAILED LOGIN"
        $fp6 = "auth error"
        $fp7 = "Permission denied"
    condition:
        any of ($fp*)
}

rule ThreatTrace_BruteForce_MaxAttempts {
    meta:
        description = "Maximum authentication attempts exceeded"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1110"
    strings:
        $ma1 = "Too many authentication failures" nocase
        $ma2 = "maximum authentication" nocase
        $ma3 = "account locked" nocase
        $ma4 = "Account Lockout" nocase
        $ma5 = "too many failed" nocase
    condition:
        any of ($ma*)
}

rule ThreatTrace_BruteForce_HTTP401 {
    meta:
        description = "HTTP 401/403 brute force pattern"
        author = "ThreatTrace"
        severity = "MEDIUM"
        mitre_technique = "T1110"
    strings:
        $http401 = /" 401 /
        $http403 = /" 403 /
        $login = "/login"
        $admin = "/admin"
        $wp = "/wp-login"
    condition:
        ($http401 or $http403) and ($login or $admin or $wp)
}
