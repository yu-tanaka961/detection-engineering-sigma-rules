# T1486 Data Encrypted for Impact — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `file_event_win_ransomware_extension.yml`, `proc_creation_win_cipher_wipe.yml`
- **検知対象**: ランサムウェア拡張子変更、cipher.exe実行
- **強み**: 既知ランサムウェアファミリーの拡張子パターン

### 1.2 elastic/detection-rules
- **代表的なルール**: `impact_ransomware_encryption.toml`, `impact_bitlocker_abuse.toml`
- **検知対象**: 大量ファイル暗号化、BitLocker悪用
- **強み**: ファイル作成イベントの統計的異常検知

### 1.3 splunk/security_content
- **代表的なルール**: Ransomware Encryption, Data Destruction
- **検知対象**: ランサムウェアインジケータ、暗号化ツール
- **強み**: 身代金メモファイル作成の検知

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Ransomware Activity Detection
- **検知対象**: ランサムウェア活動パターン
- **強み**: MDEによるリアルタイムランサムウェア行動検知

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. ランサムウェア拡張子** | .encrypted, .locked, .lockbit等 | 高（FileCreateで検知） | Sigma, Elastic, Splunk, Sentinel |
| **B. 暗号化ツール実行** | cipher.exe, BitLocker, openssl | 中（カスタムツールで回避可能） | Sigma, Elastic, Splunk |
| **C. 行動パターン（ScriptBlock）** | 暗号化API + ファイル操作 + 身代金メモ | 高（ScriptBlock Loggingで検知） | Sigma, Elastic, Splunk |

## 3. 統合優先度

### Tier 1: 基礎ルール
1. ランサムウェア拡張子/身代金メモ検知
2. 暗号化ツール実行

### Tier 2: 高価値ルール
3. PowerShell暗号化行動パターン

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon | 11 | ファイル作成（暗号化拡張子/身代金メモ） | 必須 |
| Sysmon / Security | 1 / 4688 | プロセス作成（暗号化ツール） | 必須 |
| PowerShell ScriptBlock | 4104 | 暗号化行動パターン | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1486](https://attack.mitre.org/techniques/T1486/)
