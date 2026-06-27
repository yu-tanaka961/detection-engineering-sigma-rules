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
│   └── t1003_006_dcsync/           # MITRE ATT&CK T1003.006
│       ├── tier1_dcsync_replication_rights.yml
│       ├── tier1_dcsync_tool_execution.yml
│       ├── tier2_dcsync_scriptblock.yml
│       ├── tier2_dcsync_network_drsuapi.yml
│       └── tier2_dcsync_permission_delegation.yml
└── docs/
    ├── t1059_001_cross_source_analysis.md
    └── t1003_006_cross_source_analysis.md
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

## References

- [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK T1003.006](https://attack.mitre.org/techniques/T1003/006/)
- [SigmaHQ](https://github.com/SigmaHQ/sigma)
- [Elastic detection-rules](https://github.com/elastic/detection-rules)
- [Splunk security_content](https://github.com/splunk/security_content)
- [Azure Sentinel Detections](https://github.com/Azure/Azure-Sentinel)
- [T1059.001 Cross-source analysis](docs/t1059_001_cross_source_analysis.md)
- [T1003.006 Cross-source analysis](docs/t1003_006_cross_source_analysis.md)

## Author

Yuhei Tanaka
