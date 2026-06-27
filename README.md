# Detection Engineering — Sigma Rules

Cross-source unified Sigma rules for threat detection, built by aggregating and analyzing detection logic from SigmaHQ, Elastic, Splunk ESCU, and Azure Sentinel.

## Repository Structure

```
detection-engineering-sigma-rules/
├── rules/
│   ├── t1059_001_powershell/       # MITRE ATT&CK T1059.001
│   │   ├── tier1_base64_encoded_powershell.yml
│   │   ├── tier1_susp_parameter_combination.yml
│   │   ├── tier1_download_execute_pattern.yml
│   │   ├── tier2_suspicious_parent_process.yml
│   │   ├── tier2_amsi_bypass_attempt.yml
│   │   └── tier2_scriptblock_malicious_cmdlets.yml
│   ├── t1003_006_dcsync/           # MITRE ATT&CK T1003.006
│   │   ├── tier1_dcsync_replication_rights.yml
│   │   ├── tier1_dcsync_tool_execution.yml
│   │   ├── tier2_dcsync_scriptblock.yml
│   │   ├── tier2_dcsync_network_drsuapi.yml
│   │   └── tier2_dcsync_permission_delegation.yml
│   ├── t1190_exploit_public_facing/  # MITRE ATT&CK T1190
│   │   ├── tier1_webserver_suspicious_child_process.yml
│   │   ├── tier1_webshell_file_creation.yml
│   │   └── tier2_known_exploit_indicators.yml
│   ├── t1133_external_remote_services/ # MITRE ATT&CK T1133
│   │   ├── tier1_rdp_bruteforce_logon_failure.yml
│   │   ├── tier1_rdp_logon_from_public_ip.yml
│   │   └── tier2_vpn_suspicious_logon_pattern.yml
│   ├── t1078_valid_accounts/         # MITRE ATT&CK T1078
│   │   ├── tier1_multiple_failed_then_success.yml
│   │   ├── tier1_dormant_account_logon.yml
│   │   └── tier2_admin_logon_anomaly.yml
│   ├── t1566_001_spearphishing_attachment/ # MITRE ATT&CK T1566.001
│   │   ├── tier1_office_suspicious_child_process.yml
│   │   ├── tier1_office_macro_execution_indicators.yml
│   │   └── tier2_suspicious_attachment_file_write.yml
│   ├── t1078_004_cloud_accounts/     # MITRE ATT&CK T1078.004
│   │   ├── tier1_cloud_impossible_travel.yml
│   │   ├── tier1_cloud_mfa_fatigue_attack.yml
│   │   └── tier2_cloud_suspicious_service_principal.yml
│   ├── t1059_003_windows_command_shell/ # MITRE ATT&CK T1059.003
│   │   ├── tier1_cmd_suspicious_execution_pattern.yml
│   │   ├── tier1_cmd_spawned_by_suspicious_parent.yml
│   │   └── tier2_cmd_obfuscation_techniques.yml
│   ├── t1204_002_malicious_file/     # MITRE ATT&CK T1204.002
│   │   ├── tier1_suspicious_file_execution_from_user_dir.yml
│   │   ├── tier1_iso_img_vhd_mount_execution.yml
│   │   └── tier2_lnk_file_suspicious_target.yml
│   ├── t1569_002_service_execution/  # MITRE ATT&CK T1569.002
│   │   ├── tier1_suspicious_service_installation.yml
│   │   ├── tier1_sc_exe_service_creation.yml
│   │   └── tier2_service_execution_from_unusual_process.yml
│   ├── t1053_005_scheduled_task/     # MITRE ATT&CK T1053.005
│   │   ├── tier1_schtasks_suspicious_creation.yml
│   │   ├── tier1_taskscheduler_event_suspicious.yml
│   │   └── tier2_schtasks_remote_creation.yml
│   ├── t1047_wmi/                    # MITRE ATT&CK T1047
│   │   ├── tier1_wmic_suspicious_execution.yml
│   │   ├── tier1_wmiprvse_suspicious_child.yml
│   │   └── tier2_wmi_event_subscription_persistence.yml
│   ├── t1543_003_windows_service_persistence/ # MITRE ATT&CK T1543.003
│   │   ├── tier1_service_registry_modification.yml
│   │   ├── tier1_new_service_in_suspicious_location.yml
│   │   └── tier2_service_dll_hijack.yml
│   ├── t1547_001_registry_run_keys/  # MITRE ATT&CK T1547.001
│   │   ├── tier1_registry_run_key_modification.yml
│   │   ├── tier1_startup_folder_file_creation.yml
│   │   └── tier2_registry_run_key_via_unusual_process.yml
│   ├── t1136_001_local_account/      # MITRE ATT&CK T1136.001
│   │   ├── tier1_local_account_creation.yml
│   │   ├── tier1_local_account_event_log.yml
│   │   └── tier2_hidden_account_creation.yml
│   ├── t1197_bits_jobs/              # MITRE ATT&CK T1197
│   │   ├── tier1_bitsadmin_suspicious_usage.yml
│   │   ├── tier1_bits_persistence_via_notify.yml
│   │   └── tier2_bits_unusual_job_creation.yml
│   └── t1068_exploitation_privilege_escalation/ # MITRE ATT&CK T1068
│       ├── tier1_suspicious_process_token_elevation.yml
│       ├── tier1_known_exploit_tool_execution.yml
│       └── tier2_vulnerable_driver_load.yml
└── docs/
    ├── t1059_001_cross_source_analysis.md
    ├── t1003_006_cross_source_analysis.md
    ├── t1190_cross_source_analysis.md
    ├── t1133_cross_source_analysis.md
    ├── t1078_cross_source_analysis.md
    ├── t1566_001_cross_source_analysis.md
    ├── t1078_004_cross_source_analysis.md
    ├── t1059_003_cross_source_analysis.md
    ├── t1204_002_cross_source_analysis.md
    ├── t1569_002_cross_source_analysis.md
    ├── t1053_005_cross_source_analysis.md
    ├── t1047_cross_source_analysis.md
    ├── t1543_003_cross_source_analysis.md
    ├── t1547_001_cross_source_analysis.md
    ├── t1136_001_cross_source_analysis.md
    ├── t1197_cross_source_analysis.md
    └── t1068_cross_source_analysis.md
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

## References

- [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK T1003.006](https://attack.mitre.org/techniques/T1003/006/)
- [MITRE ATT&CK T1190](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1133](https://attack.mitre.org/techniques/T1133/)
- [MITRE ATT&CK T1078](https://attack.mitre.org/techniques/T1078/)
- [MITRE ATT&CK T1566.001](https://attack.mitre.org/techniques/T1566/001/)
- [MITRE ATT&CK T1078.004](https://attack.mitre.org/techniques/T1078/004/)
- [MITRE ATT&CK T1059.003](https://attack.mitre.org/techniques/T1059/003/)
- [MITRE ATT&CK T1204.002](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK T1569.002](https://attack.mitre.org/techniques/T1569/002/)
- [MITRE ATT&CK T1053.005](https://attack.mitre.org/techniques/T1053/005/)
- [MITRE ATT&CK T1047](https://attack.mitre.org/techniques/T1047/)
- [MITRE ATT&CK T1543.003](https://attack.mitre.org/techniques/T1543/003/)
- [MITRE ATT&CK T1547.001](https://attack.mitre.org/techniques/T1547/001/)
- [MITRE ATT&CK T1136.001](https://attack.mitre.org/techniques/T1136/001/)
- [MITRE ATT&CK T1197](https://attack.mitre.org/techniques/T1197/)
- [MITRE ATT&CK T1068](https://attack.mitre.org/techniques/T1068/)
- [SigmaHQ](https://github.com/SigmaHQ/sigma)
- [Elastic detection-rules](https://github.com/elastic/detection-rules)
- [Splunk security_content](https://github.com/splunk/security_content)
- [Azure Sentinel Detections](https://github.com/Azure/Azure-Sentinel)
- [T1059.001 Cross-source analysis](docs/t1059_001_cross_source_analysis.md)
- [T1003.006 Cross-source analysis](docs/t1003_006_cross_source_analysis.md)
- [T1190 Cross-source analysis](docs/t1190_cross_source_analysis.md)
- [T1133 Cross-source analysis](docs/t1133_cross_source_analysis.md)
- [T1078 Cross-source analysis](docs/t1078_cross_source_analysis.md)
- [T1566.001 Cross-source analysis](docs/t1566_001_cross_source_analysis.md)
- [T1078.004 Cross-source analysis](docs/t1078_004_cross_source_analysis.md)
- [T1059.003 Cross-source analysis](docs/t1059_003_cross_source_analysis.md)
- [T1204.002 Cross-source analysis](docs/t1204_002_cross_source_analysis.md)
- [T1569.002 Cross-source analysis](docs/t1569_002_cross_source_analysis.md)
- [T1053.005 Cross-source analysis](docs/t1053_005_cross_source_analysis.md)
- [T1047 Cross-source analysis](docs/t1047_cross_source_analysis.md)
- [T1543.003 Cross-source analysis](docs/t1543_003_cross_source_analysis.md)
- [T1547.001 Cross-source analysis](docs/t1547_001_cross_source_analysis.md)
- [T1136.001 Cross-source analysis](docs/t1136_001_cross_source_analysis.md)
- [T1197 Cross-source analysis](docs/t1197_cross_source_analysis.md)
- [T1068 Cross-source analysis](docs/t1068_cross_source_analysis.md)

## Author

Yuhei Tanaka
