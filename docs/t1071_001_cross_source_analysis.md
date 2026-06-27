# T1071.001 Application Layer Protocol: Web Protocols — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_certutil_download.yml`, `proc_creation_win_powershell_webclient.yml`
- **検知対象**: certutil/PowerShellダウンロード、C2フレームワークインジケータ
- **強み**: LOLBinのHTTPダウンロードパターンの詳細検知

### 1.2 elastic/detection-rules
- **代表的なルール**: `command_and_control_web_c2.toml`, `command_and_control_lolbin_network.toml`
- **検知対象**: Web C2通信、LOLBin外部接続
- **強み**: Sysmon NetworkConnect (3) によるLOLBin外部通信検知

### 1.3 splunk/security_content
- **代表的なルール**: C2 Web Protocol, LOLBin Network Connection
- **検知対象**: HTTP/HTTPS C2、Cobalt Strike/Empire等のインジケータ
- **強み**: C2フレームワーク固有のインジケータ検知

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Web Protocol C2
- **検知対象**: WebプロトコルC2通信
- **強み**: ネットワークフローとプロセスの相関分析

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. HTTP C2パターン** | certutil/bitsadmin/mshta + URL | 中（カスタムツールで回避可能） | Sigma, Elastic, Splunk |
| **B. C2フレームワーク** | Cobalt Strike, Sliver, Empire等 | 中（カスタムプロファイルで回避可能） | Sigma, Elastic, Splunk |
| **C. LOLBin外部接続** | mshta/rundll32等のHTTP/443接続 | 高（Sysmon NetworkConnectで検知） | Elastic, Splunk, Sentinel |

## 3. 統合優先度

### Tier 1: 基礎ルール
1. LOLBinのHTTP/HTTPS C2通信パターン
2. 既知C2フレームワークインジケータ

### Tier 2: 高価値ルール
3. LOLBinの外部ネットワーク接続（Sysmon 3）

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（ダウンロードコマンド） | 必須 |
| Sysmon | 3 | ネットワーク接続（LOLBin外部通信） | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1071.001](https://attack.mitre.org/techniques/T1071/001/)
- [LOLBAS Project](https://lolbas-project.github.io/)
