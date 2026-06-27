# T1083 File and Directory Discovery — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_dir_listing.yml`, `proc_creation_win_net_share.yml`
- **検知対象**: dir/treeコマンド、ネットワーク共有列挙
- **強み**: 再帰的ファイル検索パターンの検知

### 1.2 elastic/detection-rules
- **代表的なルール**: `discovery_file_directory.toml`, `discovery_share_enumeration.toml`
- **検知対象**: ファイル/ディレクトリ発見、共有列挙
- **強み**: 機密ファイルパターン（*.kdbx, *.pfx等）のターゲット検索

### 1.3 splunk/security_content
- **代表的なルール**: File Discovery, Network Share Enumeration
- **検知対象**: ファイル発見、Snaffler等のツール
- **強み**: Snaffler/ShareEnum等の共有スキャンツール検知

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: File Discovery Activity
- **検知対象**: ファイル発見活動
- **強み**: MDEテレメトリによるファイルアクセスの相関分析

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. ディレクトリリスティング** | dir /s, tree, Get-ChildItem -Recurse | 中（APIで回避可能） | Sigma, Elastic, Splunk, Sentinel |
| **B. 共有/ドライブ列挙** | net share, Snaffler, Invoke-ShareFinder | 中（ツール名変更で回避可能） | Sigma, Elastic, Splunk |
| **C. 機密ファイル検索ScriptBlock** | *.kdbx, *.pfx, web.config等の再帰検索 | 高（ScriptBlock Loggingで記録） | Elastic, Splunk |

## 3. 統合優先度

### Tier 1: 基礎ルール
1. 不審なディレクトリリスティングコマンド
2. ネットワーク共有/ドライブ列挙

### Tier 2: 高価値ルール
3. ScriptBlockでの機密ファイル再帰検索

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（コマンド実行） | 必須 |
| PowerShell ScriptBlock | 4104 | ScriptBlockでのファイル検索 | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1083](https://attack.mitre.org/techniques/T1083/)
- [Snaffler](https://github.com/SnaffCon/Snaffler)
