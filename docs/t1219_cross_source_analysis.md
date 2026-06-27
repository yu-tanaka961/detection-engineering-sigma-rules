# T1219 Remote Access Software — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_anydesk.yml`, `proc_creation_win_teamviewer.yml`
- **検知対象**: AnyDesk/TeamViewer/ScreenConnect実行
- **強み**: サイレントインストールパターンの検知

### 1.2 elastic/detection-rules
- **代表的なルール**: `command_and_control_rat.toml`, `persistence_rat_install.toml`
- **検知対象**: RAT実行、ポータブル実行、ネットワーク接続
- **強み**: 一時ディレクトリからのRAT実行検知

### 1.3 splunk/security_content
- **代表的なルール**: Remote Access Tool Detection, RAT Network Connection
- **検知対象**: RAT実行、リレーサーバー接続
- **強み**: RAT固有ポート（5938, 6568等）の接続監視

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Remote Access Tool Usage
- **検知対象**: リモートアクセスツール使用
- **強み**: MDEテレメトリによるRAT活動の統計分析

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. RATツール実行** | AnyDesk, TeamViewer, ScreenConnect | 中（リネーム可能） | Sigma, Elastic, Splunk, Sentinel |
| **B. RATネットワーク接続** | リレーサーバーポート（5938, 6568等） | 高（固有ポートは回避困難） | Sigma, Elastic, Splunk |
| **C. 不審インストール/ポータブル** | Temp/Downloadsからの実行、サイレントインストール | 高（実行パスはカーネルが記録） | Elastic, Splunk, Sentinel |

## 3. 統合優先度

### Tier 1: 基礎ルール
1. RAT実行検知（サイレントインストール）
2. RATリレーサーバーへのネットワーク接続

### Tier 2: 高価値ルール
3. 不審パスからのRAT実行/ポータブル版

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（RAT実行） | 必須 |
| Sysmon | 3 | ネットワーク接続（リレーサーバー） | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1219](https://attack.mitre.org/techniques/T1219/)
