# T1105 Ingress Tool Transfer — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_certutil_download.yml`, `proc_creation_win_bitsadmin_download.yml`
- **検知対象**: certutil/bitsadmin/PowerShellによるダウンロード
- **強み**: LOLBinダウンロードコマンドの詳細パターン検知

### 1.2 elastic/detection-rules
- **代表的なルール**: `command_and_control_ingress_tool_transfer.toml`, `lateral_movement_lolbin_download.toml`
- **検知対象**: LOLBinダウンロード、ネットワーク接続、ファイル作成
- **強み**: Sysmon FileCreate/NetworkConnectとの相関検知

### 1.3 splunk/security_content
- **代表的なルール**: Ingress Tool Transfer, LOLBin File Download
- **検知対象**: ツール転送、curl/wget実行
- **強み**: マルチベクター（CLI + ネットワーク + ファイル）相関

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Ingress Tool Transfer Detection
- **検知対象**: ファイルダウンロード活動
- **強み**: MDEテレメトリによるファイル作成の統計分析

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. LOLBinダウンロード** | certutil, bitsadmin, PowerShell | 中（カスタムツールで回避可能） | Sigma, Elastic, Splunk |
| **B. ファイル作成監視** | 実行可能ファイルのユーザーディレクトリ作成 | 高（Sysmon FileCreateで検知） | Elastic, Splunk, Sentinel |
| **C. ネットワーク接続** | LOLBinの外部HTTP/HTTPS接続 | 高（Sysmon NetworkConnectで検知） | Elastic, Splunk, Sentinel |

## 3. 統合優先度

### Tier 1: 基礎ルール
1. LOLBinによるファイルダウンロード
2. 不審プロセスによるファイル作成

### Tier 2: 高価値ルール
3. LOLBinの外部ネットワーク接続

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（ダウンロードコマンド） | 必須 |
| Sysmon | 11 | ファイル作成（ダウンロードファイル） | 推奨 |
| Sysmon | 3 | ネットワーク接続（外部通信） | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1105](https://attack.mitre.org/techniques/T1105/)
- [LOLBAS Project](https://lolbas-project.github.io/)
