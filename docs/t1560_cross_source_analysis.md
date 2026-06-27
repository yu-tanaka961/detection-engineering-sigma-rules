# T1560 Archive Collected Data — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_7z_password.yml`, `proc_creation_win_compress_archive.yml`
- **検知対象**: 7z/WinRARパスワード付きアーカイブ、PowerShell Compress-Archive
- **強み**: パスワード付きアーカイブ作成の詳細検知

### 1.2 elastic/detection-rules
- **代表的なルール**: `collection_archive_data.toml`, `collection_staging_archive.toml`
- **検知対象**: データアーカイブ、ステージングディレクトリへのアーカイブ作成
- **強み**: ステージングディレクトリでのアーカイブ作成パターン

### 1.3 splunk/security_content
- **代表的なルール**: Archive Data Collection, Exfiltration Staging
- **検知対象**: アーカイブツール、makecab、.NETアーカイブ
- **強み**: makecab/compact等の組み込みツールの検知

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Data Archive Activity
- **検知対象**: データアーカイブ活動
- **強み**: ファイル作成イベントとの相関分析

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. アーカイブツール実行** | 7z, WinRAR + パスワード/機密ディレクトリ | 中（組み込みツールで回避可能） | Sigma, Elastic, Splunk |
| **B. PowerShell/組み込みアーカイブ** | Compress-Archive, makecab, .NET ZipFile | 中（カスタムスクリプトで回避可能） | Sigma, Elastic, Splunk |
| **C. ステージングアーカイブ作成** | Temp/ProgramData/Publicへのアーカイブ | 高（Sysmon FileCreateで検知） | Elastic, Splunk, Sentinel |

## 3. 統合優先度

### Tier 1: 基礎ルール
1. アーカイブツールの不審実行（パスワード付き/機密ディレクトリ）
2. PowerShell/組み込みツールによるアーカイブ

### Tier 2: 高価値ルール
3. ステージングディレクトリへのアーカイブ作成

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（アーカイブツール） | 必須 |
| Sysmon | 11 | ファイル作成（アーカイブファイル） | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1560](https://attack.mitre.org/techniques/T1560/)
