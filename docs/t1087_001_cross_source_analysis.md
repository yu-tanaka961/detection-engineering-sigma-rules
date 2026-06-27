# T1087.001 Account Discovery: Local Account — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_net_user.yml`, `posh_ps_local_user_enum.yml`
- **検知対象**: net user、Get-LocalUser実行
- **強み**: net/net1コマンドのローカルアカウント列挙パターン

### 1.2 elastic/detection-rules
- **代表的なルール**: `discovery_local_account_enum.toml`, `discovery_local_admin.toml`
- **検知対象**: ローカルアカウント列挙、ローカル管理者発見
- **強み**: PowerView Find-LocalAdminAccessの検知

### 1.3 splunk/security_content
- **代表的なルール**: Local Account Discovery, Local Admin Enumeration
- **検知対象**: ローカルユーザー/グループ列挙
- **強み**: WMI/CIMベースのアカウント列挙検知

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Local Account Discovery
- **検知対象**: ローカルアカウント発見活動
- **強み**: MDEテレメトリによる発見コマンドの統計分析

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. Net/WMICコマンド** | net user, net localgroup, wmic | 中（代替ツールで回避可能） | Sigma, Elastic, Splunk, Sentinel |
| **B. PowerShell/WMI列挙** | Get-LocalUser, Win32_UserAccount | 中（カスタムスクリプトで回避可能） | Sigma, Elastic, Splunk |
| **C. ローカル管理者ターゲット** | Find-LocalAdminAccess, SAM列挙 | 高（ScriptBlock Loggingで記録） | Elastic, Splunk |

## 3. 統合優先度

### Tier 1: 基礎ルール
1. net user / net localgroupコマンド
2. PowerShell/WMIローカルアカウント列挙

### Tier 2: 高価値ルール
3. ローカル管理者アカウントの標的型列挙

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（コマンド実行） | 必須 |
| PowerShell ScriptBlock | 4104 | ScriptBlockでの列挙活動 | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1087.001](https://attack.mitre.org/techniques/T1087/001/)
