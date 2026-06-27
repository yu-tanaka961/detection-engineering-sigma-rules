# T1018 Remote System Discovery — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_net_view.yml`, `proc_creation_win_nltest.yml`
- **検知対象**: net view、nltest、arp列挙
- **強み**: Windows組み込みコマンドの詳細パターン検知

### 1.2 elastic/detection-rules
- **代表的なルール**: `discovery_remote_system.toml`, `discovery_ad_computer_enum.toml`
- **検知対象**: リモートシステム発見、AD コンピュータ列挙
- **強み**: PowerShell ADモジュールとLDAP検索の検知

### 1.3 splunk/security_content
- **代表的なルール**: Remote System Discovery, Network Scanner Execution
- **検知対象**: ネットワーク発見コマンド、スキャナーツール
- **強み**: ネットワークスキャナーツールの包括的カバー

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Network Discovery Activity
- **検知対象**: ネットワーク発見活動
- **強み**: MDEテレメトリによる発見コマンドの相関分析

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. ネットワークスキャンコマンド** | net view, nltest, dsquery, arp | 中（代替コマンドで回避可能） | Sigma, Elastic, Splunk, Sentinel |
| **B. AD コンピュータ列挙** | Get-ADComputer, AdFind, LDAP | 中（カスタムクエリで回避可能） | Sigma, Elastic, Splunk |
| **C. ネットワークスキャナーツール** | nmap, masscan, Advanced IP Scanner | 中（ツール名変更で回避可能） | Sigma, Splunk |

## 3. 統合優先度

### Tier 1: 基礎ルール
1. ネットワークスキャンコマンド（net view, nltest等）
2. AD コンピュータオブジェクト列挙

### Tier 2: 高価値ルール
3. ネットワークスキャナーツール実行

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（コマンド・ツール実行） | 必須 |

## 5. 参考資料
- [MITRE ATT&CK T1018](https://attack.mitre.org/techniques/T1018/)
