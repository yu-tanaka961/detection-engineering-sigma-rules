# T1558.001 Golden Ticket (KRBTGT偽造) — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_mimikatz_golden.yml`, `posh_ps_golden_ticket.yml`
- **検知対象**: Mimikatz kerberos::golden実行、PowerShellゴールデンチケット
- **強み**: ツールベースの検知パターンが豊富

### 1.2 elastic/detection-rules
- **代表的なルール**: `credential_access_golden_ticket.toml`, `credential_access_kerberos_anomaly.toml`
- **検知対象**: ゴールデンチケットツール、Kerberos TGT異常
- **強み**: RC4暗号化TGTの異常検知

### 1.3 splunk/security_content
- **代表的なルール**: Golden Ticket Attack, KRBTGT Account Hash
- **検知対象**: KRBTGT抽出、チケット偽造
- **強み**: Kerberos認証イベントの統計分析

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Golden Ticket Detection, Kerberos TGT Anomaly
- **検知対象**: TGT異常使用、ドメイン不一致
- **強み**: Azure AD/ADのハイブリッド認証異常検知

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. KRBTGT抽出ツール** | Mimikatz lsadump::dcsync /user:krbtgt | 中（ツール名変更で回避可能） | Sigma, Elastic, Splunk |
| **B. ゴールデンチケット使用異常** | RC4 TGT、有効期限異常、ドメイン不一致 | 高（Kerberosイベントログは回避困難） | Elastic, Sigma, Sentinel |
| **C. ScriptBlockチケット操作** | PowerShellでのKerberosチケット生成 | 高（ScriptBlock Loggingは難読化解除後を記録） | Sigma, Splunk |

## 3. 統合優先度

### Tier 1: 基礎ルール
1. KRBTGT抽出ツール実行
2. ゴールデンチケット使用異常（RC4 TGT）

### Tier 2: 高価値ルール
3. ScriptBlockでのチケット操作

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（ツール実行） | 必須 |
| Windows Security Kerberos | 4768 | TGT要求（暗号化タイプ監視） | 必須 |
| Windows Security Kerberos | 4769 | TGS要求 | 推奨 |
| PowerShell ScriptBlock | 4104 | ScriptBlockチケット操作 | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1558.001](https://attack.mitre.org/techniques/T1558/001/)
- [Golden Ticket - ADSecurity](https://adsecurity.org/?p=1640)
- [Kerberos Golden Ticket Detection](https://adsecurity.org/?p=1515)
