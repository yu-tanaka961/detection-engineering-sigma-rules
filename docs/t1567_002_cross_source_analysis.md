# T1567.002 Exfiltration Over Web Service: Exfiltration to Cloud Storage — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_rclone.yml`, `proc_creation_win_cloud_upload.yml`
- **検知対象**: Rclone実行、クラウドストレージCLIツール
- **強み**: Rcloneのパラメータ・リネーム検知

### 1.2 elastic/detection-rules
- **代表的なルール**: `exfiltration_cloud_storage.toml`, `exfiltration_rclone.toml`
- **検知対象**: クラウドストレージへのアップロード、Rclone活動
- **強み**: クラウドストレージAPIエンドポイントの検知

### 1.3 splunk/security_content
- **代表的なルール**: Cloud Storage Exfiltration, Rclone Detection
- **検知対象**: AWS S3/Azure Blob/GCS アップロード
- **強み**: クラウドCLIツール（aws, azcopy, gsutil）の詳細検知

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Data Exfiltration to Cloud Storage
- **検知対象**: クラウドストレージへの大量データ転送
- **強み**: ネットワークフロー量による統計的異常検知

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. クラウドCLIツール** | rclone, aws, azcopy, gsutil | 中（ツール名変更で回避可能） | Sigma, Elastic, Splunk |
| **B. HTTPアップロード** | PowerShell/curlのクラウドAPI呼び出し | 中（カスタムスクリプトで回避可能） | Sigma, Elastic, Sentinel |
| **C. Rcloneリネーム/設定** | リネームRclone、非標準パスからの実行 | 高（コマンドラインフラグで検知） | Sigma, Elastic, Splunk |

## 3. 統合優先度

### Tier 1: 基礎ルール
1. クラウドストレージCLIアップロード
2. PowerShell/curlによるクラウドAPI呼び出し

### Tier 2: 高価値ルール
3. Rclone設定ファイル作成/リネーム実行

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（アップロードツール） | 必須 |
| Sysmon | 3 | ネットワーク接続（クラウドAPI） | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1567.002](https://attack.mitre.org/techniques/T1567/002/)
- [Detecting Rclone - NCC Group](https://research.nccgroup.com/2021/05/27/detecting-rclone-an-effective-tool-for-exfiltration/)
