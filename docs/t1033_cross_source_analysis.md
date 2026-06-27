# T1033 System Owner/User Discovery — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_whoami.yml`, `proc_creation_win_recon_sequence.yml`
- **検知対象**: whoami実行、偵察コマンドシーケンス
- **強み**: 不審な親プロセスからのwhoami実行検知

### 1.2 elastic/detection-rules
- **代表的なルール**: `discovery_system_owner.toml`, `discovery_recon_sequence.toml`
- **検知対象**: ユーザー発見コマンド、偵察シーケンス
- **強み**: 短時間内の複数偵察コマンド実行パターン検知

### 1.3 splunk/security_content
- **代表的なルール**: System Owner Discovery, Rapid Recon Sequence
- **検知対象**: whoami、環境変数アクセス、WMIクエリ
- **強み**: 環境変数・WMIベースのユーザー発見の検知

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: User Discovery Activity
- **検知対象**: ユーザー発見活動
- **強み**: MDEテレメトリによる偵察行動の統計分析

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. whoami/ユーザー発見** | whoami /all, quser, hostname | 中（APIで回避可能） | Sigma, Elastic, Splunk, Sentinel |
| **B. 環境変数/WMIクエリ** | %USERNAME%, WMI ComputerSystem | 中（カスタムスクリプトで回避可能） | Sigma, Splunk |
| **C. 偵察コマンドシーケンス** | 短時間内の複数発見コマンド | 高（行動パターンは回避困難） | Elastic, Splunk, Sentinel |

## 3. 統合優先度

### Tier 1: 基礎ルール
1. whoami等のユーザー発見コマンド（不審な親プロセス）
2. 環境変数/WMIベースのユーザー発見

### Tier 2: 高価値ルール
3. 短時間偵察コマンドシーケンス

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（コマンド実行） | 必須 |

## 5. 参考資料
- [MITRE ATT&CK T1033](https://attack.mitre.org/techniques/T1033/)
