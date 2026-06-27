# T1552.001 Unsecured Credentials: Credentials In Files — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_susp_cred_file_search.yml`, `proc_creation_win_unattend_cred.yml`
- **検知対象**: パスワードファイル検索、unattend.xmlアクセス
- **強み**: findstr/Select-Stringによるパスワード検索パターン

### 1.2 elastic/detection-rules
- **代表的なルール**: `credential_access_sensitive_file_search.toml`, `credential_access_ssh_key_theft.toml`
- **検知対象**: 機密ファイル検索、SSH鍵窃取、unattend.xml
- **強み**: クラウド認証情報ファイル（.aws/credentials等）の検知

### 1.3 splunk/security_content
- **代表的なルール**: Credential File Search, Unattend XML Access
- **検知対象**: パスワードファイル検索、デプロイメントファイル
- **強み**: 多様なファイル検索コマンドの包括的カバー

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Sensitive File Discovery
- **検知対象**: 機密ファイル発見活動
- **強み**: MDEファイルアクセステレメトリ

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. パスワードファイル検索** | findstr/Select-String "password" | 中（カスタムスクリプトで回避可能） | Sigma, Elastic, Splunk, Sentinel |
| **B. デプロイメントファイルアクセス** | unattend.xml, sysprep.xml | 中（直接ファイルコピーで回避可能） | Elastic, Sigma, Splunk |
| **C. SSH鍵/設定ファイルアクセス** | id_rsa, .ppk, .kdbx | 高（ファイルアクセスはカーネルイベント） | Elastic, Sigma, Splunk |

## 3. 統合優先度

### Tier 1: 基礎ルール
1. パスワードファイル検索コマンド
2. unattend.xml / sysprep.xmlアクセス

### Tier 2: 高価値ルール
3. SSH鍵/KeePassデータベースアクセス

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（検索コマンド） | 必須 |
| Sysmon | FileAccess | ファイルアクセス（SSH鍵等） | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1552.001](https://attack.mitre.org/techniques/T1552/001/)
- [Unattend.xml Credential Extraction](https://pentestlab.blog/2017/06/19/extracting-credentials-from-unattend-xml/)
