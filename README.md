# Detection Engineering — Sigma Rules

Cross-source unified Sigma rules for threat detection, built by aggregating and analyzing detection logic from SigmaHQ, Elastic, Splunk ESCU, and Azure Sentinel.

## Repository Structure

```
detection-engineering-sigma-rules/
├── rules/                          # Sigma detection rules (YAML)
│   ├── t1003_001_lsass_memory/
│   ├── t1003_002_sam_database/
│   ├── t1003_003_ntds/
│   ├── t1003_006_dcsync/
│   ├── t1018_remote_system_discovery/
│   ├── t1021_001_remote_desktop_protocol/
│   ├── t1021_002_smb_windows_admin_shares/
│   ├── t1027_obfuscated_files/
│   ├── t1033_system_owner_user_discovery/
│   ├── t1047_wmi/
│   ├── t1053_005_scheduled_task/
│   ├── t1059_001_powershell/
│   ├── t1059_003_windows_command_shell/
│   ├── t1068_exploitation_privilege_escalation/
│   ├── t1070_004_file_deletion/
│   ├── t1071_001_web_protocols/
│   ├── t1078_valid_accounts/
│   ├── t1078_004_cloud_accounts/
│   ├── t1083_file_and_directory_discovery/
│   ├── t1087_001_local_account_discovery/
│   ├── t1087_002_domain_account_discovery/
│   ├── t1090_proxy/
│   ├── t1105_ingress_tool_transfer/
│   ├── t1133_external_remote_services/
│   ├── t1134_access_token_manipulation/
│   ├── t1134_t1558_unconstrained_delegation/
│   ├── t1136_001_local_account/
│   ├── t1140_deobfuscate_decode/
│   ├── t1190_exploit_public_facing/
│   ├── t1197_bits_jobs/
│   ├── t1204_002_malicious_file/
│   ├── t1218_system_binary_proxy_execution/
│   ├── t1218_011_rundll32/
│   ├── t1219_remote_access_software/
│   ├── t1482_domain_trust_discovery/
│   ├── t1486_data_encrypted_for_impact/
│   ├── t1489_service_stop/
│   ├── t1490_inhibit_system_recovery/
│   ├── t1543_003_windows_service_persistence/
│   ├── t1546_011_application_shimming/
│   ├── t1547_001_registry_run_keys/
│   ├── t1550_002_pass_the_hash/
│   ├── t1552_001_credentials_in_files/
│   ├── t1552_006_gpp_credentials/
│   ├── t1555_credentials_from_password_stores/
│   ├── t1557_001_llmnr_nbtns_poisoning/
│   ├── t1558_001_golden_ticket/
│   ├── t1558_003_kerberoasting/
│   ├── t1560_archive_collected_data/
│   ├── t1566_001_spearphishing_attachment/
│   ├── t1567_002_exfil_to_cloud_storage/
│   ├── t1569_002_service_execution/
│   ├── t1570_lateral_tool_transfer/
│   ├── t1572_protocol_tunneling/
│   ├── t1649_steal_forge_certificates/
│   └── t1685_disable_modify_tools/
└── docs/                           # Cross-source analysis (per technique)
    └── t{XXXX}_cross_source_analysis.md
```

## Rule Sets

### T1059.001 — PowerShell Execution

6 unified Sigma rules covering the full attack lifecycle for PowerShell-based threats.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Base64 Encoded Command](rules/t1059_001_powershell/tier1_base64_encoded_powershell.yml) | 1 | High | process_creation | Medium |
| [Suspicious Parameter Combination](rules/t1059_001_powershell/tier1_susp_parameter_combination.yml) | 1 | High | process_creation | Medium |
| [Download and Execute Pattern](rules/t1059_001_powershell/tier1_download_execute_pattern.yml) | 1 | High | process_creation | Medium |
| [Suspicious Parent Process](rules/t1059_001_powershell/tier2_suspicious_parent_process.yml) | 2 | Critical | process_creation | High |
| [AMSI Bypass Attempt](rules/t1059_001_powershell/tier2_amsi_bypass_attempt.yml) | 2 | Critical | ps_script | High |
| [Malicious Cmdlets via ScriptBlock](rules/t1059_001_powershell/tier2_scriptblock_malicious_cmdlets.yml) | 2 | Critical | ps_script | High |

### T1003.006 — DCSync

5 unified Sigma rules detecting DCSync attacks across the full kill chain: permission delegation, tool execution, protocol-level replication, and PowerShell-based attacks.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Replication Rights (4662)](rules/t1003_006_dcsync/tier1_dcsync_replication_rights.yml) | 1 | Critical | security (4662) | High |
| [Tool Execution](rules/t1003_006_dcsync/tier1_dcsync_tool_execution.yml) | 1 | Critical | process_creation | Medium |
| [ScriptBlock DCSync](rules/t1003_006_dcsync/tier2_dcsync_scriptblock.yml) | 2 | Critical | ps_script (4104) | High |
| [Network DRSUAPI Anomaly](rules/t1003_006_dcsync/tier2_dcsync_network_drsuapi.yml) | 2 | High | network_connection | High |
| [Permission Delegation (5136)](rules/t1003_006_dcsync/tier2_dcsync_permission_delegation.yml) | 2 | Critical | security (5136) | High |

### T1190 — Exploit Public-Facing Application

3 unified Sigma rules detecting webshell deployment and exploitation of public-facing web applications.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Web Server Suspicious Child Process](rules/t1190_exploit_public_facing/tier1_webserver_suspicious_child_process.yml) | 1 | Critical | process_creation | High |
| [Webshell File Creation](rules/t1190_exploit_public_facing/tier1_webshell_file_creation.yml) | 1 | High | file_event | High |
| [Known Exploit Indicators](rules/t1190_exploit_public_facing/tier2_known_exploit_indicators.yml) | 2 | Critical | process_creation | Medium |

### T1133 — External Remote Services

3 unified Sigma rules detecting unauthorized use of external remote services (RDP, VPN).

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [RDP Brute Force](rules/t1133_external_remote_services/tier1_rdp_bruteforce_logon_failure.yml) | 1 | High | security (4625) | High |
| [RDP from Public IP](rules/t1133_external_remote_services/tier1_rdp_logon_from_public_ip.yml) | 1 | Critical | security (4624) | High |
| [VPN Suspicious Logon](rules/t1133_external_remote_services/tier2_vpn_suspicious_logon_pattern.yml) | 2 | Medium | security (6272/6273) | Medium |

### T1078 — Valid Accounts

3 unified Sigma rules detecting abuse of valid credentials through brute force, dormant accounts, and privileged account anomalies.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Multiple Failed then Success](rules/t1078_valid_accounts/tier1_multiple_failed_then_success.yml) | 1 | High | security (4625) | High |
| [Dormant Account Logon](rules/t1078_valid_accounts/tier1_dormant_account_logon.yml) | 1 | Medium | security (4722/4724) | Medium |
| [Admin Logon Anomaly](rules/t1078_valid_accounts/tier2_admin_logon_anomaly.yml) | 2 | High | security (4672/4624) | High |

### T1566.001 — Spearphishing Attachment

3 unified Sigma rules detecting malicious email attachment execution chains.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Office Suspicious Child Process](rules/t1566_001_spearphishing_attachment/tier1_office_suspicious_child_process.yml) | 1 | Critical | process_creation | High |
| [Office Macro Execution Indicators](rules/t1566_001_spearphishing_attachment/tier1_office_macro_execution_indicators.yml) | 1 | Medium | image_load | High |
| [Suspicious Attachment File Write](rules/t1566_001_spearphishing_attachment/tier2_suspicious_attachment_file_write.yml) | 2 | High | file_event | High |

### T1078.004 — Valid Accounts: Cloud Accounts

3 unified Sigma rules detecting cloud account compromise via impossible travel, MFA fatigue, and service principal abuse.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Cloud Impossible Travel](rules/t1078_004_cloud_accounts/tier1_cloud_impossible_travel.yml) | 1 | High | azure/signinlogs | Medium |
| [MFA Fatigue Attack](rules/t1078_004_cloud_accounts/tier1_cloud_mfa_fatigue_attack.yml) | 1 | High | azure/signinlogs | High |
| [Suspicious Service Principal](rules/t1078_004_cloud_accounts/tier2_cloud_suspicious_service_principal.yml) | 2 | High | azure/auditlogs | High |

### T1059.003 — Windows Command Shell

3 unified Sigma rules detecting malicious cmd.exe usage including reconnaissance chains, suspicious parents, and obfuscation.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Suspicious Execution Pattern](rules/t1059_003_windows_command_shell/tier1_cmd_suspicious_execution_pattern.yml) | 1 | Medium | process_creation | Medium |
| [Suspicious Parent Process](rules/t1059_003_windows_command_shell/tier1_cmd_spawned_by_suspicious_parent.yml) | 1 | High | process_creation | High |
| [Obfuscation Techniques](rules/t1059_003_windows_command_shell/tier2_cmd_obfuscation_techniques.yml) | 2 | High | process_creation | Medium |

### T1204.002 — User Execution: Malicious File

3 unified Sigma rules detecting user execution of malicious files via suspicious directories, container mounts, and weaponized LNK files.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Execution from User Directory](rules/t1204_002_malicious_file/tier1_suspicious_file_execution_from_user_dir.yml) | 1 | Medium | process_creation | Medium |
| [ISO/IMG/VHD Mount Execution](rules/t1204_002_malicious_file/tier1_iso_img_vhd_mount_execution.yml) | 1 | High | process_creation | High |
| [LNK Suspicious Target](rules/t1204_002_malicious_file/tier2_lnk_file_suspicious_target.yml) | 2 | High | process_creation | Medium |

### T1569.002 — System Services: Service Execution

3 unified Sigma rules detecting malicious service installation and execution.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Suspicious Service Installation (7045)](rules/t1569_002_service_execution/tier1_suspicious_service_installation.yml) | 1 | High | system (7045) | High |
| [SC.exe Service Creation](rules/t1569_002_service_execution/tier1_sc_exe_service_creation.yml) | 1 | High | process_creation | Medium |
| [Service Unusual Child Process](rules/t1569_002_service_execution/tier2_service_execution_from_unusual_process.yml) | 2 | Critical | process_creation | High |

### T1053.005 — Scheduled Task

3 unified Sigma rules detecting malicious scheduled task creation for persistence and lateral movement.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [schtasks.exe Suspicious Creation](rules/t1053_005_scheduled_task/tier1_schtasks_suspicious_creation.yml) | 1 | High | process_creation | Medium |
| [Task Scheduler Event (4698)](rules/t1053_005_scheduled_task/tier1_taskscheduler_event_suspicious.yml) | 1 | High | security (4698) | High |
| [Remote Task Creation](rules/t1053_005_scheduled_task/tier2_schtasks_remote_creation.yml) | 2 | High | process_creation | High |

### T1047 — Windows Management Instrumentation

3 unified Sigma rules detecting WMI abuse for execution, lateral movement, and persistence.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [WMIC Suspicious Execution](rules/t1047_wmi/tier1_wmic_suspicious_execution.yml) | 1 | High | process_creation | Medium |
| [WmiPrvSE Suspicious Child](rules/t1047_wmi/tier1_wmiprvse_suspicious_child.yml) | 1 | High | process_creation | High |
| [WMI Event Subscription](rules/t1047_wmi/tier2_wmi_event_subscription_persistence.yml) | 2 | Critical | sysmon (19/20/21) | High |

### T1543.003 — Windows Service Persistence

3 unified Sigma rules detecting malicious service persistence via registry modification, suspicious service paths, and DLL hijacking.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Service Registry Modification](rules/t1543_003_windows_service_persistence/tier1_service_registry_modification.yml) | 1 | High | sysmon (13) | High |
| [New Service in Suspicious Location](rules/t1543_003_windows_service_persistence/tier1_new_service_in_suspicious_location.yml) | 1 | High | system (7045) | High |
| [Service DLL Hijack](rules/t1543_003_windows_service_persistence/tier2_service_dll_hijack.yml) | 2 | Critical | sysmon (7) | High |

### T1547.001 — Registry Run Keys / Startup Folder

3 unified Sigma rules detecting persistence via Run/RunOnce registry keys and Startup folder file creation.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Run Key Modification](rules/t1547_001_registry_run_keys/tier1_registry_run_key_modification.yml) | 1 | High | sysmon (13) | High |
| [Startup Folder File Creation](rules/t1547_001_registry_run_keys/tier1_startup_folder_file_creation.yml) | 1 | High | sysmon (11) | High |
| [Run Key via Unusual Process](rules/t1547_001_registry_run_keys/tier2_registry_run_key_via_unusual_process.yml) | 2 | Critical | sysmon (13) | High |

### T1136.001 — Create Account: Local Account

3 unified Sigma rules detecting local account creation via command-line tools, event logs, and hidden account techniques.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Local Account Creation (CLI)](rules/t1136_001_local_account/tier1_local_account_creation.yml) | 1 | High | process_creation | Medium |
| [Account Event Log (4720/4732)](rules/t1136_001_local_account/tier1_local_account_event_log.yml) | 1 | High | security (4720/4732) | High |
| [Hidden Account Creation](rules/t1136_001_local_account/tier2_hidden_account_creation.yml) | 2 | Critical | process_creation / sysmon (13) | High |

### T1197 — BITS Jobs

3 unified Sigma rules detecting BITS abuse for download, persistence, and evasion.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [BITSAdmin Suspicious Usage](rules/t1197_bits_jobs/tier1_bitsadmin_suspicious_usage.yml) | 1 | High | process_creation | Medium |
| [BITS Persistence via Notify](rules/t1197_bits_jobs/tier1_bits_persistence_via_notify.yml) | 1 | Critical | process_creation | High |
| [BITS Unusual Job Creation](rules/t1197_bits_jobs/tier2_bits_unusual_job_creation.yml) | 2 | Medium | bits-client (3) | High |

### T1068 — Exploitation for Privilege Escalation

3 unified Sigma rules detecting privilege escalation via token elevation anomalies, known exploit tools, and vulnerable driver loading (BYOVD).

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Suspicious Token Elevation](rules/t1068_exploitation_privilege_escalation/tier1_suspicious_process_token_elevation.yml) | 1 | High | security (4688) | High |
| [Known Exploit Tool Execution](rules/t1068_exploitation_privilege_escalation/tier1_known_exploit_tool_execution.yml) | 1 | Critical | process_creation | Medium |
| [Vulnerable Driver Load (BYOVD)](rules/t1068_exploitation_privilege_escalation/tier2_vulnerable_driver_load.yml) | 2 | Critical | sysmon (6) | High |

### T1134 — Access Token Manipulation

3 unified Sigma rules detecting token manipulation via known tools, privilege adjustment events, and Parent PID spoofing.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Token Impersonation Tools](rules/t1134_access_token_manipulation/tier1_token_impersonation_tools.yml) | 1 | High | process_creation | Medium |
| [Token Privilege Adjustment (4703)](rules/t1134_access_token_manipulation/tier1_suspicious_process_token_change.yml) | 1 | High | security (4703) | High |
| [Parent PID Spoofing](rules/t1134_access_token_manipulation/tier2_parent_pid_spoofing.yml) | 2 | Critical | process_creation | High |

### T1546.011 — Application Shimming

3 unified Sigma rules detecting persistence via application compatibility shim databases.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [sdbinst Shim Installation](rules/t1546_011_application_shimming/tier1_sdbinst_shim_installation.yml) | 1 | High | process_creation | Medium |
| [Shim Registry Modification](rules/t1546_011_application_shimming/tier1_shim_database_registry_modification.yml) | 1 | High | sysmon (13) | High |
| [Suspicious SDB File Creation](rules/t1546_011_application_shimming/tier2_sdb_file_creation_suspicious.yml) | 2 | High | sysmon (11) | High |

### T1070.004 — Indicator Removal: File Deletion

3 unified Sigma rules detecting evidence destruction via file deletion, event log clearing, and timestomping.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Suspicious File Deletion Tools](rules/t1070_004_file_deletion/tier1_suspicious_file_deletion_tools.yml) | 1 | High | process_creation | Medium |
| [Event Log Cleared (1102)](rules/t1070_004_file_deletion/tier1_event_log_cleared.yml) | 1 | Critical | security (1102) | High |
| [Timestomping](rules/t1070_004_file_deletion/tier2_timestomp_file_time_modification.yml) | 2 | High | sysmon (2) | High |

### T1027 — Obfuscated Files or Information

3 unified Sigma rules detecting payload obfuscation via encoding, file extension spoofing, and PowerShell deobfuscation.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Encoded/Compressed Content](rules/t1027_obfuscated_files/tier1_suspicious_encoded_content.yml) | 1 | Medium | process_creation | Medium |
| [Double Extension / RTLO](rules/t1027_obfuscated_files/tier1_double_extension_or_rtlo.yml) | 1 | Critical | process_creation | High |
| [ScriptBlock Deobfuscation Indicators](rules/t1027_obfuscated_files/tier2_scriptblock_deobfuscation_indicators.yml) | 2 | High | ps_script (4104) | High |

### T1218 — System Binary Proxy Execution

3 unified Sigma rules detecting LOLBin abuse for proxy execution via mshta, rundll32, regsvr32, CMSTP, msiexec, and network connections.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Mshta/Rundll32/Regsvr32 Proxy](rules/t1218_system_binary_proxy_execution/tier1_mshta_suspicious_execution.yml) | 1 | High | process_creation | Medium |
| [CMSTP/MSIExec/InstallUtil Proxy](rules/t1218_system_binary_proxy_execution/tier1_cmstp_msiexec_proxy_execution.yml) | 1 | High | process_creation | Medium |
| [LOLBin Network Connection](rules/t1218_system_binary_proxy_execution/tier2_lolbin_unusual_network_connection.yml) | 2 | High | sysmon (3) | High |

### T1218.011 — Rundll32

3 unified Sigma rules detecting rundll32.exe abuse for proxy execution, suspicious DLL loading, and abnormal process relationships.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Rundll32 Suspicious Execution](rules/t1218_011_rundll32/tier1_rundll32_suspicious_execution.yml) | 1 | High | process_creation | Medium |
| [Rundll32 Suspicious DLL Path](rules/t1218_011_rundll32/tier1_rundll32_suspicious_dll_path.yml) | 1 | High | process_creation | High |
| [Rundll32 Abnormal Parent/Network](rules/t1218_011_rundll32/tier2_rundll32_abnormal_parent_or_network.yml) | 2 | Critical | process_creation | High |

### T1140 — Deobfuscate/Decode Files or Information

3 unified Sigma rules detecting payload deobfuscation via certutil, PowerShell decode-execute chains, and CHM/XSL script processing.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Certutil Decode Operations](rules/t1140_deobfuscate_decode/tier1_certutil_decode_operations.yml) | 1 | High | process_creation | Medium |
| [PowerShell Decode and Execute](rules/t1140_deobfuscate_decode/tier1_powershell_decode_and_execute.yml) | 1 | High | ps_script (4104) | High |
| [CHM/XSL Script Processing](rules/t1140_deobfuscate_decode/tier2_compiled_html_or_xsl_decode.yml) | 2 | High | process_creation | Medium |

### T1685 — Disable or Modify Tools (旧T1562.001)

3 unified Sigma rules detecting security tool disabling via service manipulation, Defender registry tampering, and ETW/AMSI subversion.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Security Tool Service Disabled](rules/t1685_disable_modify_tools/tier1_security_tool_service_disabled.yml) | 1 | Critical | process_creation | Medium |
| [Defender Registry Tamper](rules/t1685_disable_modify_tools/tier1_windows_defender_registry_tamper.yml) | 1 | Critical | sysmon (13) | High |
| [ETW/AMSI Tampering](rules/t1685_disable_modify_tools/tier2_etw_or_amsi_tampering.yml) | 2 | Critical | process_creation | High |

### T1003.001 — OS Credential Dumping: LSASS Memory

3 unified Sigma rules detecting LSASS credential dumping via process access monitoring, known tool execution, and dump file creation.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [LSASS Memory Access](rules/t1003_001_lsass_memory/tier1_lsass_memory_access_suspicious.yml) | 1 | Critical | sysmon (10) | High |
| [Credential Dumping Tool](rules/t1003_001_lsass_memory/tier1_credential_dumping_tool_execution.yml) | 1 | Critical | process_creation | Medium |
| [LSASS Dump File Creation](rules/t1003_001_lsass_memory/tier2_lsass_dump_file_creation.yml) | 2 | Critical | sysmon (11) | High |

### T1558.003 — Kerberoasting

3 unified Sigma rules detecting Kerberoasting via anomalous TGS requests, known tool execution, and RC4 encryption downgrade.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [TGS Request Anomaly (RC4)](rules/t1558_003_kerberoasting/tier1_kerberos_tgs_request_anomaly.yml) | 1 | High | security (4769) | High |
| [Kerberoasting Tool Execution](rules/t1558_003_kerberoasting/tier1_kerberoasting_tool_execution.yml) | 1 | High | process_creation | Medium |
| [RC4 Encryption Downgrade](rules/t1558_003_kerberoasting/tier2_kerberos_rc4_downgrade.yml) | 2 | Medium | security (4769) | High |

### T1555 — Credentials from Password Stores

3 unified Sigma rules detecting credential theft from browser password stores, Windows Credential Manager, and DPAPI master keys.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Browser Credential Access](rules/t1555_credentials_from_password_stores/tier1_browser_credential_access.yml) | 1 | High | process_creation | Medium |
| [Credential Manager Access](rules/t1555_credentials_from_password_stores/tier1_credential_manager_access.yml) | 1 | High | process_creation | Medium |
| [DPAPI Master Key Access](rules/t1555_credentials_from_password_stores/tier2_dpapi_masterkey_access.yml) | 2 | High | process_creation | High |

### T1552.001 — Unsecured Credentials: Credentials In Files

3 unified Sigma rules detecting credential harvesting from files via password searches, unattend.xml access, and SSH key theft.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Sensitive File Search Commands](rules/t1552_001_credentials_in_files/tier1_sensitive_file_search_commands.yml) | 1 | Medium | process_creation | Medium |
| [Unattend XML Access](rules/t1552_001_credentials_in_files/tier1_unattend_xml_access.yml) | 1 | High | process_creation | High |
| [SSH Key / Config File Access](rules/t1552_001_credentials_in_files/tier2_ssh_key_or_config_file_access.yml) | 2 | High | process_creation | High |

### T1003.002 — OS Credential Dumping: SAM

3 unified Sigma rules detecting SAM database credential dumping via registry export, known tools, and file copy.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [SAM Registry Hive Export](rules/t1003_002_sam_database/tier1_sam_registry_hive_export.yml) | 1 | Critical | process_creation | High |
| [SAM Dump Tool Execution](rules/t1003_002_sam_database/tier1_sam_dump_tool_execution.yml) | 1 | Critical | process_creation | Medium |
| [SAM File Copy from Disk](rules/t1003_002_sam_database/tier2_sam_file_copy_from_disk.yml) | 2 | Critical | sysmon (11) | High |

### T1003.003 — OS Credential Dumping: NTDS

3 unified Sigma rules detecting NTDS.dit credential dumping via ntdsutil, file access tools, and dump file creation.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [ntdsutil Credential Dump](rules/t1003_003_ntds/tier1_ntdsutil_credential_dump.yml) | 1 | Critical | process_creation | High |
| [NTDS.dit File Access](rules/t1003_003_ntds/tier1_ntds_file_access_suspicious.yml) | 1 | Critical | process_creation | Medium |
| [NTDS Dump File Creation](rules/t1003_003_ntds/tier2_ntds_dump_file_creation.yml) | 2 | Critical | sysmon (11) | High |

### T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay

3 unified Sigma rules detecting name resolution poisoning via Responder/Inveigh tools, protocol config changes, and NTLM relay attacks.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Responder/Inveigh Tool Execution](rules/t1557_001_llmnr_nbtns_poisoning/tier1_responder_tool_execution.yml) | 1 | Critical | process_creation | Medium |
| [LLMNR/NBT-NS Config Change](rules/t1557_001_llmnr_nbtns_poisoning/tier1_llmnr_nbtns_config_change.yml) | 1 | High | sysmon (13) | High |
| [SMB/NTLM Relay Indicators](rules/t1557_001_llmnr_nbtns_poisoning/tier2_smb_ntlm_relay_indicators.yml) | 2 | Critical | process_creation | Medium |

### T1552.006 — Unsecured Credentials: Group Policy Preferences

3 unified Sigma rules detecting GPP credential extraction via password discovery tools, SYSVOL file access, and cpassword decryption.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [GPP Password Discovery](rules/t1552_006_gpp_credentials/tier1_gpp_password_discovery.yml) | 1 | High | process_creation | Medium |
| [SYSVOL GPP File Access](rules/t1552_006_gpp_credentials/tier1_sysvol_gpp_file_access.yml) | 1 | High | process_creation | High |
| [GPP cpassword Decryption](rules/t1552_006_gpp_credentials/tier2_gpp_cpassword_decryption.yml) | 2 | Critical | ps_script (4104) | High |

### T1649 — Steal or Forge Authentication Certificates (AD CS)

3 unified Sigma rules detecting AD CS certificate abuse including certificate export, ESC1-ESC8 exploitation tools, and certificate template abuse.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Certificate Export/Request](rules/t1649_steal_forge_certificates/tier1_certutil_certificate_export.yml) | 1 | High | process_creation | Medium |
| [AD CS Abuse Tool Execution](rules/t1649_steal_forge_certificates/tier1_adcs_abuse_tool_execution.yml) | 1 | Critical | process_creation | Medium |
| [Certificate Template Abuse (ESC1-8)](rules/t1649_steal_forge_certificates/tier2_adcs_certificate_template_abuse.yml) | 2 | High | security (4886/4887) | High |

### T1558.001 — Golden Ticket (KRBTGT偽造)

3 unified Sigma rules detecting Golden Ticket attacks via KRBTGT hash extraction, anomalous TGT usage, and PowerShell ticket manipulation.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [KRBTGT Hash Extraction Tools](rules/t1558_001_golden_ticket/tier1_krbtgt_hash_extraction_tools.yml) | 1 | Critical | process_creation | Medium |
| [Golden Ticket Usage Anomaly](rules/t1558_001_golden_ticket/tier1_golden_ticket_usage_anomaly.yml) | 1 | High | security (4768/4769) | High |
| [Golden Ticket ScriptBlock](rules/t1558_001_golden_ticket/tier2_golden_ticket_scriptblock.yml) | 2 | Critical | ps_script (4104) | High |

### T1134/T1558 — Unconstrained Delegation Abuse

3 unified Sigma rules detecting unconstrained delegation abuse including delegation enumeration, TGT extraction, and authentication coercion attacks.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Delegation Enumeration](rules/t1134_t1558_unconstrained_delegation/tier1_unconstrained_delegation_enumeration.yml) | 1 | High | process_creation | Medium |
| [TGT Extraction from Delegation](rules/t1134_t1558_unconstrained_delegation/tier1_tgt_extraction_from_delegation.yml) | 1 | Critical | process_creation | Medium |
| [Authentication Coercion Attack](rules/t1134_t1558_unconstrained_delegation/tier2_delegation_coercion_attack.yml) | 2 | Critical | process_creation | High |

### T1018 — Remote System Discovery

3 unified Sigma rules detecting remote system discovery via network scanning commands, AD computer enumeration, and network scanner tools.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Network Scanning Commands](rules/t1018_remote_system_discovery/tier1_network_scanning_commands.yml) | 1 | Medium | process_creation | Medium |
| [AD Computer Enumeration](rules/t1018_remote_system_discovery/tier1_ad_computer_enumeration.yml) | 1 | Medium | process_creation | Medium |
| [Network Scanner Tool Execution](rules/t1018_remote_system_discovery/tier2_network_scanner_tool_execution.yml) | 2 | High | process_creation | Medium |

### T1087.002 — Account Discovery: Domain Account

3 unified Sigma rules detecting domain account enumeration via net/WMIC, PowerShell/LDAP, and targeted privileged account discovery.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Net Domain User Enumeration](rules/t1087_002_domain_account_discovery/tier1_net_domain_user_enumeration.yml) | 1 | Medium | process_creation | Medium |
| [AD User Enumeration (PowerShell)](rules/t1087_002_domain_account_discovery/tier1_ad_user_enumeration_powershell.yml) | 1 | Medium | process_creation | Medium |
| [Privileged Account Targeted Enumeration](rules/t1087_002_domain_account_discovery/tier2_privileged_account_targeted_enumeration.yml) | 2 | High | ps_script (4104) | High |

### T1482 — Domain Trust Discovery

3 unified Sigma rules detecting domain trust enumeration via built-in commands, PowerShell/ADFind, and cross-domain trust abuse indicators.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Trust Enumeration Commands](rules/t1482_domain_trust_discovery/tier1_domain_trust_enumeration_commands.yml) | 1 | Medium | process_creation | Medium |
| [Trust PowerShell/ADFind Enumeration](rules/t1482_domain_trust_discovery/tier1_domain_trust_powershell_enumeration.yml) | 1 | Medium | process_creation | Medium |
| [Cross-Domain Trust Abuse](rules/t1482_domain_trust_discovery/tier2_cross_domain_trust_abuse_indicators.yml) | 2 | Critical | process_creation | High |

### T1033 — System Owner/User Discovery

3 unified Sigma rules detecting system owner discovery via whoami/user commands, environment variables, and rapid reconnaissance sequences.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [whoami/System Info Commands](rules/t1033_system_owner_user_discovery/tier1_whoami_system_info_commands.yml) | 1 | Medium | process_creation | Medium |
| [Environment Variable User Discovery](rules/t1033_system_owner_user_discovery/tier1_environment_variable_user_discovery.yml) | 1 | Low | process_creation | Medium |
| [Rapid Recon Command Sequence](rules/t1033_system_owner_user_discovery/tier2_rapid_recon_command_sequence.yml) | 2 | High | process_creation | High |

### T1087.001 — Account Discovery: Local Account

3 unified Sigma rules detecting local account enumeration via net/WMIC commands, PowerShell/WMI, and targeted local administrator discovery.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Local Account Enumeration Commands](rules/t1087_001_local_account_discovery/tier1_local_account_enumeration_commands.yml) | 1 | Medium | process_creation | Medium |
| [Local Account PowerShell Enumeration](rules/t1087_001_local_account_discovery/tier1_local_account_powershell_enumeration.yml) | 1 | Medium | process_creation | Medium |
| [Local Admin Targeted Enumeration](rules/t1087_001_local_account_discovery/tier2_local_admin_targeted_enumeration.yml) | 2 | High | ps_script (4104) | High |

### T1083 — File and Directory Discovery

3 unified Sigma rules detecting file/directory discovery via directory listing, share enumeration, and sensitive file search patterns.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Suspicious Directory Listing](rules/t1083_file_and_directory_discovery/tier1_suspicious_directory_listing_commands.yml) | 1 | Medium | process_creation | Medium |
| [Share/Network Drive Enumeration](rules/t1083_file_and_directory_discovery/tier1_share_and_network_drive_enumeration.yml) | 1 | Medium | process_creation | Medium |
| [Sensitive File Discovery ScriptBlock](rules/t1083_file_and_directory_discovery/tier2_sensitive_file_discovery_scriptblock.yml) | 2 | High | ps_script (4104) | High |

### T1021.002 — SMB/Windows Admin Shares

3 unified Sigma rules detecting SMB lateral movement via PsExec, admin share access, and remote service installation.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [PsExec/SMB Lateral Movement](rules/t1021_002_smb_windows_admin_shares/tier1_psexec_smb_lateral_movement.yml) | 1 | High | process_creation | Medium |
| [Admin Share Access](rules/t1021_002_smb_windows_admin_shares/tier1_admin_share_access_suspicious.yml) | 1 | High | process_creation | Medium |
| [SMB Remote Service Install (7045)](rules/t1021_002_smb_windows_admin_shares/tier2_smb_lateral_movement_service_install.yml) | 2 | Critical | system (7045) | High |

### T1021.001 — Remote Desktop Protocol

3 unified Sigma rules detecting RDP lateral movement via suspicious connections, session hijacking, and RDP enable/configuration changes.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [RDP Suspicious Connection](rules/t1021_001_remote_desktop_protocol/tier1_rdp_suspicious_connection.yml) | 1 | Medium | process_creation | Medium |
| [RDP Session Hijacking (tscon)](rules/t1021_001_remote_desktop_protocol/tier1_rdp_session_hijacking.yml) | 1 | Critical | process_creation | High |
| [RDP Registry/Firewall Modification](rules/t1021_001_remote_desktop_protocol/tier2_rdp_registry_and_firewall_modification.yml) | 2 | High | process_creation | High |

### T1570 — Lateral Tool Transfer

3 unified Sigma rules detecting lateral tool transfer via file copy commands, SMB executable writes, and WMI/WinRM file operations.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Lateral File Copy Commands](rules/t1570_lateral_tool_transfer/tier1_lateral_file_copy_commands.yml) | 1 | Medium | process_creation | Medium |
| [SMB Executable File Write](rules/t1570_lateral_tool_transfer/tier1_smb_executable_file_write.yml) | 1 | High | file_event | High |
| [WMI/WinRM File Transfer](rules/t1570_lateral_tool_transfer/tier2_lateral_transfer_via_wmi_or_winrm.yml) | 2 | High | process_creation | High |

### T1550.002 — Pass the Hash

3 unified Sigma rules detecting Pass-the-Hash attacks via PtH tool execution, NTLM logon anomalies, and Logon Type 9 / explicit credential abuse.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [PtH Tool Execution](rules/t1550_002_pass_the_hash/tier1_pth_tool_execution.yml) | 1 | Critical | process_creation | Medium |
| [NTLM Logon Anomaly](rules/t1550_002_pass_the_hash/tier1_ntlm_logon_anomaly.yml) | 1 | High | security (4624) | High |
| [PtH Process Creation Anomaly](rules/t1550_002_pass_the_hash/tier2_pth_process_creation_anomaly.yml) | 2 | High | security (4624/4648/4768) | High |

### T1560 — Archive Collected Data

3 unified Sigma rules detecting data archiving for exfiltration via archive tools, PowerShell compression, and staging directory file creation.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Archive Tool Suspicious Execution](rules/t1560_archive_collected_data/tier1_archive_tool_suspicious_execution.yml) | 1 | High | process_creation | Medium |
| [PowerShell Compress-Archive](rules/t1560_archive_collected_data/tier1_powershell_compress_archive.yml) | 1 | Medium | process_creation | Medium |
| [Large Archive in Staging Dir](rules/t1560_archive_collected_data/tier2_large_archive_creation_exfil_staging.yml) | 2 | High | file_event | High |

### T1071.001 — Application Layer Protocol: Web Protocols

3 unified Sigma rules detecting C2 communication over HTTP/HTTPS via LOLBin downloads, known C2 framework indicators, and LOLBin outbound connections.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Suspicious HTTP C2 Patterns](rules/t1071_001_web_protocols/tier1_suspicious_http_c2_patterns.yml) | 1 | High | process_creation | Medium |
| [Known C2 Framework Indicators](rules/t1071_001_web_protocols/tier1_known_c2_framework_indicators.yml) | 1 | Critical | process_creation | Medium |
| [LOLBin Outbound Connection](rules/t1071_001_web_protocols/tier2_suspicious_outbound_connection_lolbin.yml) | 2 | High | network_connection | High |

### T1219 — Remote Access Software

3 unified Sigma rules detecting unauthorized remote access tool usage via RAT execution, relay server connections, and silent/portable installations.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Remote Access Tool Execution](rules/t1219_remote_access_software/tier1_remote_access_tool_execution.yml) | 1 | High | process_creation | Medium |
| [RAT Network Connection](rules/t1219_remote_access_software/tier1_rat_network_connection.yml) | 1 | High | network_connection | High |
| [RAT Silent Install / Portable](rules/t1219_remote_access_software/tier2_rat_silent_install_or_portable.yml) | 2 | High | process_creation | High |

### T1572 — Protocol Tunneling

3 unified Sigma rules detecting protocol tunneling via SSH/tunnel tools, DNS tunneling indicators, and tunnel network connection anomalies.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [SSH Tunnel Suspicious Execution](rules/t1572_protocol_tunneling/tier1_ssh_tunnel_suspicious_execution.yml) | 1 | High | process_creation | Medium |
| [DNS Tunnel Indicators](rules/t1572_protocol_tunneling/tier1_dns_tunnel_indicators.yml) | 1 | High | process_creation | Medium |
| [Tunnel Network Connection Anomaly](rules/t1572_protocol_tunneling/tier2_tunnel_network_connection_anomaly.yml) | 2 | High | network_connection | High |

### T1090 — Proxy

3 unified Sigma rules detecting proxy usage via proxy tool execution, web shell proxy file creation, and multi-hop proxy/Tor indicators.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Proxy Tool Execution](rules/t1090_proxy/tier1_proxy_tool_execution.yml) | 1 | High | process_creation | Medium |
| [Web Shell Proxy Traffic](rules/t1090_proxy/tier1_web_shell_proxy_traffic.yml) | 1 | Critical | file_event | High |
| [Multi-Hop Proxy / Tor](rules/t1090_proxy/tier2_multi_hop_proxy_indicators.yml) | 2 | High | process_creation | High |

### T1105 — Ingress Tool Transfer

3 unified Sigma rules detecting tool transfer via LOLBin downloads, suspicious file creation in user directories, and LOLBin outbound network connections.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Remote File Download Tools](rules/t1105_ingress_tool_transfer/tier1_remote_file_download_tools.yml) | 1 | High | process_creation | Medium |
| [File Download from External IP](rules/t1105_ingress_tool_transfer/tier1_file_download_from_external_ip.yml) | 1 | High | file_event | High |
| [Tool Transfer Network Connection](rules/t1105_ingress_tool_transfer/tier2_tool_transfer_network_connection.yml) | 2 | High | network_connection | High |

### T1567.002 — Exfiltration to Cloud Storage

3 unified Sigma rules detecting data exfiltration to cloud storage via CLI tools (rclone, aws, azcopy), PowerShell/curl uploads, and Rclone renamed binary execution.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Cloud Storage Upload Commands](rules/t1567_002_exfil_to_cloud_storage/tier1_cloud_storage_upload_commands.yml) | 1 | High | process_creation | Medium |
| [Web Upload to Cloud Storage](rules/t1567_002_exfil_to_cloud_storage/tier1_browser_bulk_upload_to_cloud.yml) | 1 | High | process_creation | Medium |
| [Rclone Config / Renamed Execution](rules/t1567_002_exfil_to_cloud_storage/tier2_rclone_config_or_renamed_execution.yml) | 2 | High | process_creation | High |

### T1486 — Data Encrypted for Impact

3 unified Sigma rules detecting ransomware encryption via file extension changes, encryption tool execution, and PowerShell encryption behavioral patterns.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Ransomware File Extension Change](rules/t1486_data_encrypted_for_impact/tier1_ransomware_file_extension_change.yml) | 1 | Critical | file_event | High |
| [Encryption Tool Execution](rules/t1486_data_encrypted_for_impact/tier1_ransomware_encryption_tool_execution.yml) | 1 | High | process_creation | Medium |
| [Ransomware Behavioral Indicators](rules/t1486_data_encrypted_for_impact/tier2_ransomware_behavioral_indicators.yml) | 2 | Critical | ps_script (4104) | High |

### T1490 — Inhibit System Recovery

3 unified Sigma rules detecting system recovery inhibition via VSS deletion, boot configuration tampering, and multiple recovery inhibition command sequences.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [VSS Shadow Copy Delete](rules/t1490_inhibit_system_recovery/tier1_vssadmin_shadow_delete.yml) | 1 | Critical | process_creation | High |
| [BCDEdit/Recovery Disable](rules/t1490_inhibit_system_recovery/tier1_bcdedit_recovery_disable.yml) | 1 | Critical | process_creation | High |
| [Multiple Recovery Inhibition](rules/t1490_inhibit_system_recovery/tier2_multiple_recovery_inhibition_commands.yml) | 2 | Critical | process_creation | High |

### T1489 — Service Stop

3 unified Sigma rules detecting malicious service stopping via CLI commands, PowerShell/WMI, and mass service stop sequences indicating ransomware activity.

| Rule | Tier | Level | Log Source | Evasion Resistance |
|---|---|---|---|---|
| [Critical Service Stop Commands](rules/t1489_service_stop/tier1_critical_service_stop_commands.yml) | 1 | High | process_creation | Medium |
| [PowerShell/WMI Service Stop](rules/t1489_service_stop/tier1_powershell_service_stop.yml) | 1 | High | process_creation | Medium |
| [Mass Service Stop Sequence](rules/t1489_service_stop/tier2_mass_service_stop_sequence.yml) | 2 | Critical | process_creation | High |

### Tiering Strategy

- **Tier 1**: High-confidence, broad-coverage rules. Deploy immediately with minimal tuning.
- **Tier 2**: High-value rules requiring environment-specific tuning. ScriptBlock Logging (EventID 4104) must be enabled.

## Custom Metadata Tags

Rules use extended tags to encode detection quality dimensions:

| Tag | Meaning |
|---|---|
| `x-source.sigmahq` | Logic derived from SigmaHQ |
| `x-source.elastic-detection-rules` | Logic derived from Elastic detection-rules |
| `x-source.splunk-escu` | Logic derived from Splunk ESCU |
| `x-source.azure-sentinel` | Logic derived from Azure Sentinel |
| `x-evasion-resistance.high` | Architecturally difficult for adversaries to avoid |
| `x-evasion-resistance.medium` | Bypassable with obfuscation or tool changes |
| `x-drs.dq-coverage` | Mapped to DRS Detection Quality: Coverage dimension |
| `x-drs.dq-precision` | Mapped to DRS Detection Quality: Precision dimension |
| `x-drs.ed-log-evasion-resistance` | Mapped to DRS Evasion Difficulty: Log evasion resistance |
| `x-drs.ed-tool-change-resistance` | Mapped to DRS Evasion Difficulty: Tool change resistance |

## Log Source Requirements

| Log Source | EventID | Required For |
|---|---|---|
| Sysmon EventID 1 / Security 4688 | process_creation | Tier 1 process rules |
| PowerShell ScriptBlock Logging | 4104 | Tier 2 ScriptBlock rules |
| Windows Security DS Access | 4662 | DCSync replication detection |
| Windows Security DS Changes | 5136 | DCSync permission delegation |
| Sysmon NetworkConnect | 3 | DCSync network anomaly |
| Sysmon FileCreate | 11 | Webshell / attachment file write |
| Sysmon ImageLoad | 7 | Office macro DLL detection |
| Windows Security Logon | 4624/4625 | RDP, brute force, valid account rules |
| Windows Security Account Mgmt | 4672/4722/4724 | Privilege / dormant account rules |
| Windows Security NPS | 6272/6273 | VPN authentication anomaly |
| Azure AD SigninLogs | — | Cloud impossible travel, MFA fatigue |
| Azure AD AuditLogs | — | Service principal abuse |
| Windows System EventLog | 7045 | Service installation detection |
| Windows Security Task Scheduler | 4698 | Scheduled task registration |
| Sysmon WMI Events | 19/20/21 | WMI event subscription persistence |
| Sysmon RegistryEvent | 13 | Service registry, Run key modification |
| Sysmon DriverLoad | 6 | Vulnerable driver load detection |
| Windows Security Account Mgmt | 4720/4732 | Local account creation / group add |
| BITS Client | 3 | BITS job creation monitoring |
| Security Token Adjustment | 4703 | Token privilege adjustment |
| Security Event Log Cleared | 1102 | Event log clearing detection |
| Sysmon FileCreateTimeChanged | 2 | Timestomping detection |
| Windows Defender Operational | 5001/5007 | Defender protection state changes |
| Sysmon ProcessAccess | 10 | LSASS memory access monitoring |
| Windows Security Kerberos | 4769 | Kerberos TGS request (Kerberoasting) |
| Sysmon FileAccess | — | Browser credential / DPAPI / SSH key access |
| Sysmon FileCreate | 11 | SAM/NTDS file copy detection |
| AD CS Audit | 4886/4887 | Certificate request/issuance |
| AD CS Audit | 4898/4899 | Certificate template load/modify |
| Windows Security Kerberos | 4768 | TGT request (Golden Ticket / Overpass-the-Hash) |
| Windows Security Logon | 4648 | Explicit credential use (Pass the Hash) |

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [SigmaHQ](https://github.com/SigmaHQ/sigma)
- [Elastic detection-rules](https://github.com/elastic/detection-rules)
- [Splunk security_content](https://github.com/splunk/security_content)
- [Azure Sentinel Detections](https://github.com/Azure/Azure-Sentinel)
