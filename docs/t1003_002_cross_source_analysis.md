# T1003.002 OS Credential Dumping: Security Account Manager — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_reg_save_sam.yml`, `proc_creation_win_sam_dump.yml`
- **検知対象**: reg save SAM/SYSTEM、SAMダンプツール実行
- **強み**: レジストリハイブエクスポートコマンドの詳細検知

### 1.2 elastic/detection-rules
- **代表的なルール**: `credential_access_sam_registry_export.toml`, `credential_access_sam_file_copy.toml`
- **検知対象**: レジストリエクスポート、SAMファイルコピー、Shadow Copy経由アクセス
- **強み**: Shadow Copy経由のSAMアクセス検知

### 1.3 splunk/security_content
- **代表的なルール**: SAM Registry Hive Export, SAM Dump Tools
- **検知対象**: reg save、SAMダンプツール、esentutl
- **強み**: esentutl/diskshadow等の代替手法カバー

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Registry Hive Credential Access
- **検知対象**: SAM/SYSTEM/SECURITYレジストリハイブアクセス
- **強み**: MDEテレメトリによるレジストリアクセス可視化

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. レジストリハイブエクスポート** | reg save HKLM\SAM/SYSTEM/SECURITY | 中（API直接呼び出しで回避可能） | Sigma, Elastic, Splunk, Sentinel |
| **B. SAMダンプツール実行** | Mimikatz lsadump::sam、secretsdump等 | 中（ツール名変更で回避可能） | Sigma, Elastic, Splunk |
| **C. SAMファイルコピー** | Shadow Copy経由のSAMファイル直接コピー | 高（ファイル作成はカーネルイベント） | Elastic, Sigma, Splunk |

## 3. 統合優先度

### Tier 1: 基礎ルール
1. reg save SAM/SYSTEM/SECURITYコマンド
2. SAMダンプツール実行

### Tier 2: 高価値ルール
3. SAMファイルの不審な場所へのコピー

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（reg save、ツール実行） | 必須 |
| Sysmon | 11 | ファイル作成（SAMファイルコピー） | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1003.002](https://attack.mitre.org/techniques/T1003/002/)
- [SAM Credential Dumping](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-hashes-from-sam-registry)
