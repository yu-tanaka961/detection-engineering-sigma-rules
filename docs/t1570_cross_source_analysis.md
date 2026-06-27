# T1570 Lateral Tool Transfer — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_lateral_copy.yml`, `file_event_win_remote_write.yml`
- **検知対象**: リモートコピーコマンド、リモートファイル書き込み
- **強み**: UNCパスへのcopy/xcopy/robocopyの詳細パターン検知

### 1.2 elastic/detection-rules
- **代表的なルール**: `lateral_movement_tool_transfer.toml`, `lateral_movement_smb_file_write.toml`
- **検知対象**: ツール転送コマンド、SMB実行ファイル書き込み
- **強み**: Sysmon FileCreateによるリモート実行ファイル作成検知

### 1.3 splunk/security_content
- **代表的なルール**: Lateral Tool Transfer, Remote File Copy
- **検知対象**: ラテラルファイルコピー、WMI/WinRM経由の転送
- **強み**: WMI/WinRM経由のリモートファイルコピーの検知

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Lateral Tool Transfer Detection
- **検知対象**: ラテラルツール転送
- **強み**: ネットワークファイル転送の統計分析

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. ファイルコピーコマンド** | copy/xcopy/robocopy \\\\host | 中（代替手法で回避可能） | Sigma, Elastic, Splunk, Sentinel |
| **B. SMB実行ファイル書き込み** | UNCパスへの.exe/.dll作成 | 高（Sysmon FileCreateで検知） | Sigma, Elastic, Splunk |
| **C. WMI/WinRM経由転送** | Invoke-WmiMethod, WinRS copy | 高（リモート実行はイベントログに記録） | Elastic, Splunk, Sentinel |

## 3. 統合優先度

### Tier 1: 基礎ルール
1. ファイルコピーコマンドによるラテラル転送
2. SMB共有への実行ファイル書き込み

### Tier 2: 高価値ルール
3. WMI/WinRM経由のリモートファイル転送

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（コピーコマンド） | 必須 |
| Sysmon | 11 | ファイル作成（リモート書き込み） | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1570](https://attack.mitre.org/techniques/T1570/)
