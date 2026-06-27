# T1053.005 Scheduled Task/Job: Scheduled Task — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_schtasks_creation.yml`, `win_security_susp_schtask_creation.yml`
- **検知対象**: schtasks.exeコマンド監視、EventID 4698のタスクXML解析
- **強み**: コマンドラインとイベントログの2層検知

### 1.2 elastic/detection-rules
- **代表的なルール**: `persistence_suspicious_schtask_creation.toml`, `lateral_movement_remote_schtask.toml`
- **検知対象**: 不審タスク作成、リモートタスク作成（横展開）
- **強み**: EQLによるリモート横展開パターン検知

### 1.3 splunk/security_content
- **代表的なルール**: Scheduled Task Creation, Windows Scheduled Task Created via XML
- **検知対象**: schtasks.exe実行、EventID 4698/106解析
- **強み**: タスクXMLコンテンツの詳細分析

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Suspicious Scheduled Task Creation, Remote Task Scheduler Activity
- **検知対象**: 不審タスク作成、リモートタスク作成
- **強み**: MDEテレメトリ統合、Entra IDユーザーコンテキスト

---

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. schtasks.exeコマンド監視** | schtasks /Create + 不審パラメータ | 中（COM/API経由で回避可能） | Sigma, Elastic, Splunk, Sentinel |
| **B. EventID 4698タスク登録** | タスクXML内の不審コンテンツ | 高（イベントログは回避困難） | Sigma, Elastic, Splunk, Sentinel |
| **C. リモートタスク作成** | schtasks /S [target] /Create | 高（ネットワーク認証ログも生成） | Elastic, Sigma, Splunk, Sentinel |

### schtasks.exe vs EventID 4698

- **schtasks.exe監視**: プロセス作成ログベース。schtasks.exe経由の作成のみ検知。
- **EventID 4698**: タスクスケジューラの監査ログ。COM API、PowerShell、.NET APIなど全ての作成方法を検知。
- **推奨**: 両方を有効化し、4698ベースの検知をプライマリとする。

## 3. 統合優先度

### Tier 1: 基礎ルール
1. schtasks.exeによる不審タスク作成
2. EventID 4698による包括的タスク登録監視

### Tier 2: 高価値ルール
3. リモートシステムへのタスク作成（横展開）

## 4. ログ要件

| EventID | ログソース | 必要な設定 |
|---|---|---|
| 4688 | Windows Security | プロセス作成の監査 + コマンドライン記録 |
| 4698 | Windows Security | オブジェクトアクセスの監査（その他のオブジェクトアクセスイベント） |
| 106 | Task Scheduler | タスクスケジューラ運用ログの有効化 |
