/*
 * ThreatTrace YARA Rules - SQL Injection Detection
 * Category: Apache / Web Application
 * Author: ThreatTrace
 */

rule ThreatTrace_SQLi_UnionSelect {
    meta:
        description = "SQL Injection - UNION SELECT attack in HTTP request"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1190"
    strings:
        $union1 = "UNION SELECT" nocase
        $union2 = "UNION%20SELECT" nocase
        $union3 = "UNION+SELECT" nocase
        $union4 = "UNION/**/SELECT" nocase
        $union5 = "UNION%09SELECT" nocase
        $union6 = "UNION%0aSELECT" nocase
    condition:
        any of ($union*)
}

rule ThreatTrace_SQLi_BlindTimeBased {
    meta:
        description = "SQL Injection - Time-based blind injection using SLEEP or BENCHMARK"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1190"
    strings:
        $sleep1 = "SLEEP(" nocase
        $sleep2 = "SLEEP%28" nocase
        $bench1 = "BENCHMARK(" nocase
        $bench2 = "BENCHMARK%28" nocase
        $pg_sleep = "pg_sleep(" nocase
        $waitfor = "WAITFOR DELAY" nocase
    condition:
        any of them
}

rule ThreatTrace_SQLi_InformationSchema {
    meta:
        description = "SQL Injection - information_schema enumeration attempt"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1190"
    strings:
        $is1 = "information_schema" nocase
        $is2 = "information_schema.tables" nocase
        $is3 = "information_schema.columns" nocase
        $is4 = "schema_name" nocase
        $is5 = "table_name" nocase
        $is6 = "column_name" nocase
    condition:
        2 of them
}

rule ThreatTrace_SQLi_XpCmdshell {
    meta:
        description = "SQL Injection - xp_cmdshell OS command execution via MSSQL"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1190"
    strings:
        $xp1 = "xp_cmdshell" nocase
        $xp2 = "xp_cmdshell%20" nocase
        $xp3 = "sp_configure" nocase
        $xp4 = "EXEC xp_" nocase
        $xp5 = "exec%20xp_" nocase
        $xp6 = "EXECUTE xp_cmdshell" nocase
    condition:
        any of them
}

rule ThreatTrace_SQLi_CastObfuscation {
    meta:
        description = "SQL Injection - CAST/CONVERT/CHAR obfuscation technique"
        author = "ThreatTrace"
        severity = "MEDIUM"
        mitre_technique = "T1190"
    strings:
        $cast1 = "CAST(" nocase
        $cast2 = "CONVERT(" nocase
        $char1 = "CHAR(" nocase
        $char2 = "CHAR%28" nocase
        $chr1  = "CHR(" nocase
        $hex1  = "0x" ascii
        $nchar = "NCHAR(" nocase
    condition:
        2 of them
}

rule ThreatTrace_SQLi_BooleanInjection {
    meta:
        description = "SQL Injection - Boolean-based blind injection (1=1, 1=0)"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1190"
    strings:
        $bool1 = "' OR '1'='1"
        $bool2 = "' OR 1=1" nocase
        $bool3 = "\" OR \"1\"=\"1"
        $bool4 = "' OR 'x'='x"
        $bool5 = "1=1--"
        $bool6 = "1=0--"
        $bool7 = "or+1=1"
        $bool8 = "%27+OR+1=1" nocase
        $bool9 = "OR 1=1#" nocase
    condition:
        any of them
}

rule ThreatTrace_SQLi_UrlEncodedPayloads {
    meta:
        description = "SQL Injection - URL-encoded single quote and common SQLi payloads"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1190"
    strings:
        $enc1 = "%27%20OR" nocase
        $enc2 = "%27%20UNION" nocase
        $enc3 = "%27%20AND" nocase
        $enc4 = "%22%20OR" nocase
        $enc5 = "%27%20SELECT" nocase
        $enc6 = "%20UNION%20SELECT" nocase
        $enc7 = "%27--" nocase
        $enc8 = "%27%23" nocase
    condition:
        any of them
}

rule ThreatTrace_SQLi_StackedQueries {
    meta:
        description = "SQL Injection - Stacked queries attempting DROP, INSERT, or UPDATE"
        author = "ThreatTrace"
        severity = "CRITICAL"
        mitre_technique = "T1190"
    strings:
        $stacked1 = ";DROP TABLE" nocase
        $stacked2 = ";DROP DATABASE" nocase
        $stacked3 = ";INSERT INTO" nocase
        $stacked4 = ";UPDATE " nocase
        $stacked5 = ";DELETE FROM" nocase
        $stacked6 = ";EXEC " nocase
        $stacked7 = "%3BDROP%20TABLE" nocase
        $stacked8 = "%3BINSERT%20INTO" nocase
    condition:
        any of them
}

rule ThreatTrace_SQLi_ErrorBased {
    meta:
        description = "SQL Injection - Error-based injection using extractvalue or updatexml"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1190"
    strings:
        $err1 = "extractvalue(" nocase
        $err2 = "updatexml(" nocase
        $err3 = "exp(~(" nocase
        $err4 = "ST_LatFromGeoHash(" nocase
        $err5 = "GeometryCollection(" nocase
        $err6 = "linestring(" nocase
        $err7 = "floor(rand(" nocase
        $err8 = "NAME_CONST(" nocase
    condition:
        any of them
}
