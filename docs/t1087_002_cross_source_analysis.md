# T1087.002 Account Discovery: Domain Account — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_net_user_domain.yml`, `proc_creation_win_powerview.yml`
- **検知対象**: net user /domain、PowerView列挙
- **強み**: net/net1コマンドの詳細なフラグ分析

### 1.2 elastic/detection-rules
- **代表的なルール**: `discovery_domain_account_enum.toml`, `discovery_privileged_account.toml`
- **検知対象**: ドメインアカウント列挙、特権アカウント発見
- **強み**: LDAP検索フィルタによるadminCount=1ターゲット検知

### 1.3 splunk/security_content
- **代表的なルール**: Domain Account Enumeration, Privileged Account Discovery
- **検知対象**: ドメインユーザー列挙、グループメンバーシップ検索
- **強み**: WMICによるアカウント列挙の検知

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Domain Account Discovery
- **検知対象**: ドメインアカウント発見活動
- **強み**: Azure ADとの相関分析

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. Net/WMICコマンド** | net user /domain, wmic useraccount | 中（代替ツールで回避可能） | Sigma, Elastic, Splunk, Sentinel |
| **B. PowerShell/LDAP列挙** | Get-ADUser, Get-DomainUser, ADFind | 中（カスタムクエリで回避可能） | Sigma, Elastic, Splunk |
| **C. 特権アカウントターゲット** | adminCount=1、Domain Admins列挙 | 高（ScriptBlock Loggingで記録） | Elastic, Splunk, Sentinel |

## 3. 統合優先度

### Tier 1: 基礎ルール
1. net user /domain等の組み込みコマンド
2. PowerShell/LDAP/ADFindでのドメインアカウント列挙

### Tier 2: 高価値ルール
3. 特権アカウントに対する標的型列挙

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（コマンド実行） | 必須 |
| PowerShell ScriptBlock | 4104 | ScriptBlockでの列挙活動 | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1087.002](https://attack.mitre.org/techniques/T1087/002/)
- [BloodHound](https://github.com/BloodHoundAD/BloodHound)
