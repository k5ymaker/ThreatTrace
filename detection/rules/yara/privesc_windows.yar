/*
 * privesc_windows.yar
 * Windows Privilege Escalation YARA Rules for ThreatTrace
 * Covers Potato attacks, UAC bypasses, kernel exploits, NTLM relay,
 * token abuse, service manipulation, and credential attacks.
 */

rule PrivEsc_JuicyPotato_AnonymousLogon
{
    meta:
        description = "JuicyPotato privilege escalation via DCOM/OXID anonymous logon"
        author      = "ThreatTrace"
        severity    = "CRITICAL"
        mitre_tactic    = "Privilege Escalation"
        mitre_technique = "T1134"
        log_type    = "windows_security"
        tags        = "potato,juicy,token,dcom"

    strings:
        $logon_anon  = "ANONYMOUS LOGON" nocase
        $eid_4624    = "EventID>4624" nocase
        $logon_type3 = "LogonType>3" nocase
        $logon_type9 = "LogonType>9" nocase
        $juicy1      = "juicypotato" nocase
        $juicy2      = "JuicyPotato.exe" nocase
        $oxid        = "OXIDResolver" nocase
        $dcom_err    = "0x80070776" nocase

    condition:
        ($eid_4624 and $logon_anon and ($logon_type3 or $logon_type9))
        or ($juicy1 or $juicy2)
        or ($oxid and $dcom_err)
}


rule PrivEsc_RottenPotato_RemoteThread
{
    meta:
        description = "RottenPotato/SweetPotato remote thread injection for token impersonation"
        author      = "ThreatTrace"
        severity    = "CRITICAL"
        mitre_tactic    = "Privilege Escalation"
        mitre_technique = "T1055.003"
        log_type    = "sysmon"
        tags        = "potato,rotten,sweet,remote_thread"

    strings:
        $eid_8       = "EventID>8" nocase
        $rotten1     = "rottenpotato" nocase
        $rotten2     = "SweetPotato" nocase
        $rotten3     = "MSFRottenPotato" nocase
        $spoolsv     = "spoolsv.exe" nocase
        $lsass       = "lsass.exe" nocase
        $winlogon    = "winlogon.exe" nocase
        $svchost     = "svchost.exe" nocase

    condition:
        $eid_8 and ($rotten1 or $rotten2 or $rotten3)
        or ($eid_8 and ($spoolsv or $lsass or $winlogon) and $svchost)
}


rule PrivEsc_RoguePotato_NamedPipe
{
    meta:
        description = "RoguePotato named pipe impersonation for SYSTEM privilege escalation"
        author      = "ThreatTrace"
        severity    = "CRITICAL"
        mitre_tactic    = "Privilege Escalation"
        mitre_technique = "T1134.001"
        log_type    = "sysmon"
        tags        = "potato,rogue,named_pipe"

    strings:
        $eid_17      = "EventID>17" nocase
        $eid_18      = "EventID>18" nocase
        $rogue1      = "roguepotato" nocase
        $rogue2      = "RoguePotato" nocase
        $pipe1       = "RoguePotato" nocase
        $pipe2       = "\\pipe\\RoguePotato" nocase
        $pipe3       = "\\RogueOxidResolver" nocase

    condition:
        ($eid_17 or $eid_18)
        and ($rogue1 or $rogue2 or $pipe1 or $pipe2 or $pipe3)
}


rule PrivEsc_EfsPotato_SrvSvc_Pipe
{
    meta:
        description = "EfsPotato abuse of EFS named pipe via SrvSvc for privilege escalation"
        author      = "ThreatTrace"
        severity    = "HIGH"
        mitre_tactic    = "Privilege Escalation"
        mitre_technique = "T1134.001"
        log_type    = "sysmon"
        tags        = "potato,efs,srvsvc,named_pipe"

    strings:
        $eid_17      = "EventID>17" nocase
        $eid_18      = "EventID>18" nocase
        $efs1        = "efspot" nocase
        $efs2        = "EfsPotato" nocase
        $pipe_efs    = "\\pipe\\lsarpc" nocase
        $pipe_srvsvc = "\\pipe\\srvsvc" nocase
        $pipe_efsrpc = "\\EFSRPC" nocase

    condition:
        ($eid_17 or $eid_18)
        and ($efs1 or $efs2 or $pipe_efsrpc)
        or ($pipe_efs and $pipe_srvsvc)
}


rule PrivEsc_SeImpersonate_SpoolSvc_Pipe
{
    meta:
        description = "SeImpersonatePrivilege abuse via spooler service named pipe"
        author      = "ThreatTrace"
        severity    = "HIGH"
        mitre_tactic    = "Privilege Escalation"
        mitre_technique = "T1134.001"
        log_type    = "sysmon"
        tags        = "seimpersonate,spooler,named_pipe,potato"

    strings:
        $eid_17      = "EventID>17" nocase
        $eid_18      = "EventID>18" nocase
        $spoolss     = "\\pipe\\spoolss" nocase
        $spooler     = "spoolsv.exe" nocase
        $seimpers    = "SeImpersonatePrivilege" nocase
        $printspoof  = "PrintSpoofer" nocase
        $pipe_spool  = "\\pipe\\print" nocase

    condition:
        ($eid_17 or $eid_18)
        and ($spoolss or $pipe_spool or $printspoof)
        or ($spooler and $seimpers)
}


rule PrivEsc_UAC_Bypass_SDCLT
{
    meta:
        description = "UAC bypass via sdclt.exe COM object hijack (fodhelper variant)"
        author      = "ThreatTrace"
        severity    = "HIGH"
        mitre_tactic    = "Privilege Escalation"
        mitre_technique = "T1548.002"
        log_type    = "sysmon"
        tags        = "uac_bypass,sdclt,com_hijack"

    strings:
        $sdclt       = "sdclt.exe" nocase
        $reg_key1    = "HKCU\\Software\\Classes\\exefile\\shell\\runas" nocase
        $reg_key2    = "HKCU\\Software\\Classes\\ms-settings" nocase
        $reg_key3    = "IsolatedCommand" nocase
        $eid_13      = "EventID>13" nocase
        $eid_1       = "EventID>1" nocase

    condition:
        $sdclt and ($reg_key1 or $reg_key2 or $reg_key3)
        or ($eid_13 and ($reg_key1 or $reg_key2))
}


rule PrivEsc_UAC_Bypass_EventViewer
{
    meta:
        description = "UAC bypass via eventvwr.exe registry hijack"
        author      = "ThreatTrace"
        severity    = "HIGH"
        mitre_tactic    = "Privilege Escalation"
        mitre_technique = "T1548.002"
        log_type    = "sysmon"
        tags        = "uac_bypass,eventvwr,registry_hijack"

    strings:
        $eventvwr    = "eventvwr.exe" nocase
        $reg_key     = "HKCU\\Software\\Classes\\mscfile\\shell\\open\\command" nocase
        $mmc         = "mmc.exe" nocase
        $eid_13      = "EventID>13" nocase
        $eid_1       = "EventID>1" nocase

    condition:
        ($eventvwr and $reg_key)
        or ($eid_13 and $reg_key)
        or ($eid_1 and $eventvwr and not $mmc)
}


rule PrivEsc_UAC_Bypass_WsReset
{
    meta:
        description = "UAC bypass via WSReset.exe COM object / App Paths registry hijack"
        author      = "ThreatTrace"
        severity    = "HIGH"
        mitre_tactic    = "Privilege Escalation"
        mitre_technique = "T1548.002"
        log_type    = "sysmon"
        tags        = "uac_bypass,wsreset,app_paths"

    strings:
        $wsreset     = "WSReset.exe" nocase
        $reg_key     = "HKCU\\Software\\Classes\\AppX" nocase
        $reg_key2    = "AppX82a6gwre4fdg3a1" nocase
        $eid_13      = "EventID>13" nocase

    condition:
        $wsreset and ($reg_key or $reg_key2)
        or ($eid_13 and $reg_key2)
}


rule PrivEsc_UAC_Bypass_CMSTP
{
    meta:
        description = "UAC bypass via cmstp.exe INF file execution"
        author      = "ThreatTrace"
        severity    = "HIGH"
        mitre_tactic    = "Privilege Escalation"
        mitre_technique = "T1218.003"
        log_type    = "sysmon"
        tags        = "uac_bypass,cmstp,lolbin"

    strings:
        $cmstp       = "cmstp.exe" nocase
        $flag_s      = "/s" nocase
        $flag_au     = "/au" nocase
        $inf         = ".inf" nocase
        $eid_1       = "EventID>1" nocase
        $autoru      = "AutoRun=" nocase
        $registersvc = "RegisterOCXSection" nocase

    condition:
        ($eid_1 and $cmstp and ($flag_s or $flag_au))
        or ($cmstp and $inf and ($autoru or $registersvc))
}


rule PrivEsc_UAC_Bypass_DLL_Hijack_Generic
{
    meta:
        description = "Generic UAC bypass via DLL hijacking in auto-elevated process"
        author      = "ThreatTrace"
        severity    = "HIGH"
        mitre_tactic    = "Privilege Escalation"
        mitre_technique = "T1548.002"
        log_type    = "sysmon"
        tags        = "uac_bypass,dll_hijack"

    strings:
        $eid_7       = "EventID>7" nocase
        $syswow64    = "SysWOW64" nocase
        $sys32       = "System32" nocase
        $not_signed  = "Signed>false" nocase
        $uac_dll1    = "colorui.dll" nocase
        $uac_dll2    = "wlbsctrl.dll" nocase
        $uac_dll3    = "dismcore.dll" nocase
        $uac_dll4    = "dbghelp.dll" nocase
        $uac_dll5    = "elsext.dll" nocase
        $auto_elev1  = "pkgmgr.exe" nocase
        $auto_elev2  = "dccw.exe" nocase

    condition:
        $eid_7 and ($uac_dll1 or $uac_dll2 or $uac_dll3 or $uac_dll4 or $uac_dll5)
        or ($eid_7 and ($auto_elev1 or $auto_elev2) and $not_signed)
}


rule PrivEsc_UAC_WindowsDirectoryMocking
{
    meta:
        description = "UAC bypass via Windows directory mocking (C:\\Windows \\ trick)"
        author      = "ThreatTrace"
        severity    = "HIGH"
        mitre_tactic    = "Privilege Escalation"
        mitre_technique = "T1548.002"
        log_type    = "sysmon"
        tags        = "uac_bypass,directory_mock,windows_dir"

    strings:
        $mock1       = "C:\\Windows \\" nocase
        $mock2       = "C:\\Windows  \\" nocase
        $mock3       = "\\Windows \\System32" nocase
        $eid_1       = "EventID>1" nocase
        $eid_11      = "EventID>11" nocase

    condition:
        $mock1 or $mock2 or $mock3
}


rule PrivEsc_UAC_USOClient_CVE20201313
{
    meta:
        description = "UAC bypass via USOClient.exe / UpdateOrchestrator service (CVE-2020-1313)"
        author      = "ThreatTrace"
        severity    = "HIGH"
        mitre_tactic    = "Privilege Escalation"
        mitre_technique = "T1548.002"
        cve         = "CVE-2020-1313"
        log_type    = "sysmon"
        tags        = "uac_bypass,usoclient,cve-2020-1313"

    strings:
        $usoclient   = "UsoClient.exe" nocase
        $uso_svc     = "UpdateOrchestrator" nocase
        $uso_cmd     = "StartScan" nocase
        $uso_cmd2    = "StartDownload" nocase
        $uso_cmd3    = "StartInstall" nocase
        $eid_1       = "EventID>1" nocase

    condition:
        $usoclient and ($uso_cmd or $uso_cmd2 or $uso_cmd3)
        or ($uso_svc and $usoclient)
}


rule PrivEsc_SMBGhost_CVE20200796
{
    meta:
        description = "SMBGhost local privilege escalation exploit (CVE-2020-0796)"
        author      = "ThreatTrace"
        severity    = "CRITICAL"
        mitre_tactic    = "Privilege Escalation"
        mitre_technique = "T1068"
        cve         = "CVE-2020-0796"
        log_type    = "windows_system"
        tags        = "smbghost,smb,kernel_exploit,cve-2020-0796"

    strings:
        $smbghost1   = "SMBGhost" nocase
        $smbghost2   = "CVE-2020-0796" nocase
        $smb3        = "srv2.sys" nocase
        $smb_port    = ":445" nocase
        $compress    = "LZ77+Huffman" nocase
        $eid_3       = "EventID>3" nocase

    condition:
        $smbghost1 or $smbghost2
        or ($smb3 and $compress)
}


rule PrivEsc_NoPac_SAMAccountSpoofing
{
    meta:
        description = "NoPac / SamAccountName spoofing attack for privilege escalation (CVE-2021-42278/42287)"
        author      = "ThreatTrace"
        severity    = "CRITICAL"
        mitre_tactic    = "Privilege Escalation"
        mitre_technique = "T1078.002"
        cve         = "CVE-2021-42278,CVE-2021-42287"
        log_type    = "windows_security"
        tags        = "nopac,samaccount,kerberos,spoofing"

    strings:
        $eid_4741    = "EventID>4741" nocase
        $eid_4742    = "EventID>4742" nocase
        $eid_4768    = "EventID>4768" nocase
        $eid_4769    = "EventID>4769" nocase
        $sam_change  = "SamAccountName" nocase
        $dc_suffix   = "SAMAccountName" nocase
        $nopac1      = "nopac" nocase
        $nopac2      = "NoPac" nocase
        $dc_strip    = "$" nocase

    condition:
        ($nopac1 or $nopac2)
        or ($eid_4742 and $sam_change)
        or ($eid_4768 and $eid_4769 and $dc_strip)
}


rule PrivEsc_SpoolFool_DLLWrite
{
    meta:
        description = "SpoolFool printer spooler DLL write for privilege escalation (CVE-2022-21999)"
        author      = "ThreatTrace"
        severity    = "HIGH"
        mitre_tactic    = "Privilege Escalation"
        mitre_technique = "T1068"
        cve         = "CVE-2022-21999"
        log_type    = "sysmon"
        tags        = "spoolfool,spooler,dll_write,cve-2022-21999"

    strings:
        $spooler     = "spoolsv.exe" nocase
        $spoolfool1  = "SpoolFool" nocase
        $spoolfool2  = "CVE-2022-21999" nocase
        $spool_dir   = "\\spool\\drivers\\" nocase
        $eid_11      = "EventID>11" nocase
        $dll_ext     = ".dll" nocase

    condition:
        ($spoolfool1 or $spoolfool2)
        or ($eid_11 and $spooler and $spool_dir and $dll_ext)
}


rule PrivEsc_RegistrySymlink_CVE20201377
{
    meta:
        description = "Registry symlink privilege escalation (CVE-2020-1377 / RpcSs)"
        author      = "ThreatTrace"
        severity    = "HIGH"
        mitre_tactic    = "Privilege Escalation"
        mitre_technique = "T1547.001"
        cve         = "CVE-2020-1377"
        log_type    = "sysmon"
        tags        = "registry_symlink,rpcss,cve-2020-1377"

    strings:
        $cve         = "CVE-2020-1377" nocase
        $symlink1    = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\RpcSs" nocase
        $symlink2    = "RegCreateKeyTransacted" nocase
        $symlink3    = "NtCreateKey" nocase
        $eid_13      = "EventID>13" nocase
        $eid_12      = "EventID>12" nocase

    condition:
        $cve
        or ($symlink1 and ($symlink2 or $symlink3))
        or (($eid_12 or $eid_13) and $symlink1)
}


rule PrivEsc_SIDHistory_Injection
{
    meta:
        description = "SID History injection for privilege escalation via golden ticket or DS replication"
        author      = "ThreatTrace"
        severity    = "CRITICAL"
        mitre_tactic    = "Privilege Escalation"
        mitre_technique = "T1134.005"
        log_type    = "windows_security"
        tags        = "sid_history,golden_ticket,dcsync,kerberos"

    strings:
        $eid_4765    = "EventID>4765" nocase
        $eid_4766    = "EventID>4766" nocase
        $sid_hist    = "SidHistory" nocase
        $sid_hist2   = "sIDHistory" nocase
        $mimikatz1   = "privilege::debug" nocase
        $mimikatz2   = "lsadump::dcsync" nocase
        $sid_inject  = "S-1-5-21" nocase

    condition:
        ($eid_4765 or $eid_4766)
        or ($sid_hist and $sid_inject)
        or ($mimikatz1 or $mimikatz2)
}


rule PrivEsc_KrbRelayUp
{
    meta:
        description = "KrbRelayUp Kerberos relay attack for local privilege escalation"
        author      = "ThreatTrace"
        severity    = "CRITICAL"
        mitre_tactic    = "Privilege Escalation"
        mitre_technique = "T1558"
        log_type    = "windows_security"
        tags        = "krbrelayup,kerberos,relay,spnego"

    strings:
        $krbrelayup1 = "KrbRelayUp" nocase
        $krbrelayup2 = "krbrelayup" nocase
        $spnego      = "SPNEGO" nocase
        $krb_add     = "ms-DS-AllowedToActOnBehalfOfOtherIdentity" nocase
        $krb_svc     = "msDS-AllowedToActOnBehalfOfOtherIdentity" nocase
        $eid_4769    = "EventID>4769" nocase
        $eid_4624    = "EventID>4624" nocase

    condition:
        ($krbrelayup1 or $krbrelayup2)
        or ($krb_add or $krb_svc)
}


rule PrivEsc_SeDebugPrivilege_Enabled
{
    meta:
        description = "SeDebugPrivilege enabled for a non-administrative process (token manipulation)"
        author      = "ThreatTrace"
        severity    = "HIGH"
        mitre_tactic    = "Privilege Escalation"
        mitre_technique = "T1134.002"
        log_type    = "windows_security"
        tags        = "sedebug,privilege,token"

    strings:
        $eid_4672    = "EventID>4672" nocase
        $sedebug     = "SeDebugPrivilege" nocase
        $sebackup    = "SeBackupPrivilege" nocase
        $setakeown   = "SeTakeOwnershipPrivilege" nocase
        $seload      = "SeLoadDriverPrivilege" nocase

    condition:
        $eid_4672 and ($sedebug or $sebackup or $setakeown or $seload)
}


rule PrivEsc_TokenDuplication_UAC_Bypass
{
    meta:
        description = "Token duplication via OpenProcessToken / DuplicateTokenEx for UAC bypass"
        author      = "ThreatTrace"
        severity    = "HIGH"
        mitre_tactic    = "Privilege Escalation"
        mitre_technique = "T1134.001"
        log_type    = "sysmon"
        tags        = "token_duplication,uac_bypass,open_process"

    strings:
        $eid_10      = "EventID>10" nocase
        $open_proc   = "OpenProcess" nocase
        $dup_tok     = "DuplicateTokenEx" nocase
        $open_tok    = "OpenProcessToken" nocase
        $adjust_tok  = "AdjustTokenPrivileges" nocase
        $lsass       = "lsass.exe" nocase
        $winlogon    = "winlogon.exe" nocase
        $services    = "services.exe" nocase

    condition:
        $eid_10 and ($lsass or $winlogon or $services)
        or ($dup_tok and ($open_tok or $adjust_tok))
}


rule PrivEsc_NewService_NamedPipe_Path
{
    meta:
        description = "New service creation with named pipe path for privilege escalation"
        author      = "ThreatTrace"
        severity    = "HIGH"
        mitre_tactic    = "Privilege Escalation"
        mitre_technique = "T1543.003"
        log_type    = "windows_system"
        tags        = "new_service,named_pipe,persistence"

    strings:
        $eid_7045    = "EventID>7045" nocase
        $eid_4697    = "EventID>4697" nocase
        $pipe        = "\\\\.\\pipe\\" nocase
        $local_svc   = "LocalSystem" nocase
        $net_svc     = "NT AUTHORITY\\SYSTEM" nocase
        $cmd         = "cmd.exe" nocase
        $ps          = "powershell" nocase

    condition:
        ($eid_7045 or $eid_4697)
        and ($pipe or ($local_svc and ($cmd or $ps)))
}


rule PrivEsc_UnquotedServicePath
{
    meta:
        description = "Service with unquoted executable path containing spaces (privilege escalation vector)"
        author      = "ThreatTrace"
        severity    = "MEDIUM"
        mitre_tactic    = "Privilege Escalation"
        mitre_technique = "T1574.009"
        log_type    = "windows_system"
        tags        = "unquoted_service_path,service_hijack"

    strings:
        $eid_7045    = "EventID>7045" nocase
        $eid_4697    = "EventID>4697" nocase
        $prog_files1 = "C:\\Program Files\\" nocase
        $prog_files2 = "C:\\Program Files (x86)\\" nocase
        $quote       = "\"" nocase

    condition:
        ($eid_7045 or $eid_4697)
        and ($prog_files1 or $prog_files2)
        and not $quote
}


rule PrivEsc_SeImpersonateReEnable_ScheduledTask
{
    meta:
        description = "SeImpersonatePrivilege re-enabled via scheduled task for escalation"
        author      = "ThreatTrace"
        severity    = "HIGH"
        mitre_tactic    = "Privilege Escalation"
        mitre_technique = "T1053.005"
        log_type    = "windows_security"
        tags        = "seimpersonate,scheduled_task,privilege"

    strings:
        $eid_4698    = "EventID>4698" nocase
        $eid_4702    = "EventID>4702" nocase
        $seimpers    = "SeImpersonatePrivilege" nocase
        $sys_ctx     = "SYSTEM" nocase
        $cmd_task    = "cmd.exe" nocase
        $ps_task     = "powershell" nocase

    condition:
        ($eid_4698 or $eid_4702)
        and $seimpers
        or (($eid_4698 or $eid_4702) and $sys_ctx and ($cmd_task or $ps_task))
}


rule PrivEsc_NTLM_SelfRelay
{
    meta:
        description = "NTLM self-relay attack for local privilege escalation"
        author      = "ThreatTrace"
        severity    = "HIGH"
        mitre_tactic    = "Privilege Escalation"
        mitre_technique = "T1187"
        log_type    = "windows_security"
        tags        = "ntlm,self_relay,responder,relay"

    strings:
        $eid_4624    = "EventID>4624" nocase
        $ntlm        = "NTLM" nocase
        $logon_type3 = "LogonType>3" nocase
        $loopback    = "127.0.0.1" nocase
        $loopback6   = "::1" nocase
        $self_relay  = "NtlmSelfRelay" nocase
        $internal    = "localhost" nocase

    condition:
        ($self_relay)
        or ($eid_4624 and $ntlm and $logon_type3 and ($loopback or $loopback6 or $internal))
}


rule PrivEsc_RogueWinRM
{
    meta:
        description = "Rogue WinRM endpoint for credential capture / privilege escalation"
        author      = "ThreatTrace"
        severity    = "HIGH"
        mitre_tactic    = "Privilege Escalation"
        mitre_technique = "T1021.006"
        log_type    = "windows_security"
        tags        = "winrm,rogue_endpoint,ntlm_capture"

    strings:
        $winrm1      = "winrm" nocase
        $winrm2      = "WinRM" nocase
        $port5985    = ":5985" nocase
        $port5986    = ":5986" nocase
        $ntlm_auth   = "NTLMAuthentication" nocase
        $rogue       = "RogueWinRM" nocase

    condition:
        $rogue
        or ($winrm2 and ($port5985 or $port5986) and $ntlm_auth)
}


rule PrivEsc_PrivExchange_NTLMCoerce
{
    meta:
        description = "PrivExchange / NTLM coerce attack for privilege escalation via Exchange"
        author      = "ThreatTrace"
        severity    = "CRITICAL"
        mitre_tactic    = "Privilege Escalation"
        mitre_technique = "T1557.001"
        log_type    = "windows_security"
        tags        = "privexchange,ntlm_coerce,exchange,relay"

    strings:
        $privexch1   = "PrivExchange" nocase
        $privexch2   = "PushSubscription" nocase
        $coerce1     = "PetitPotam" nocase
        $coerce2     = "PrinterBug" nocase
        $coerce3     = "DFSCoerce" nocase
        $coerce4     = "ShadowCoerce" nocase
        $coerce5     = "EfsRpcOpenFileRaw" nocase
        $ntlm_relay  = "ntlmrelayx" nocase

    condition:
        $privexch1 or $privexch2 or $coerce1 or $coerce2
        or $coerce3 or $coerce4 or $coerce5 or $ntlm_relay
}


rule PrivEsc_PsExec_SystemExecution
{
    meta:
        description = "PsExec / remote service execution as SYSTEM for privilege escalation"
        author      = "ThreatTrace"
        severity    = "HIGH"
        mitre_tactic    = "Privilege Escalation"
        mitre_technique = "T1569.002"
        log_type    = "windows_security"
        tags        = "psexec,system_execution,lateral_movement"

    strings:
        $psexec1     = "psexec" nocase
        $psexec2     = "PsExec" nocase
        $psexesvc    = "PSEXESVC" nocase
        $eid_7045    = "EventID>7045" nocase
        $eid_4697    = "EventID>4697" nocase
        $sys_ctx     = "LocalSystem" nocase
        $pipe_psexec = "\\pipe\\psexesvc" nocase

    condition:
        $psexesvc or $pipe_psexec
        or ($psexec1 and ($eid_7045 or $eid_4697) and $sys_ctx)
}
