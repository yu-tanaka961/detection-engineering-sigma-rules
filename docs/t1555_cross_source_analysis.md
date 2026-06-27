# T1555 Credentials from Password Stores — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `file_access_win_browser_credential_access.yml`, `proc_creation_win_vaultcmd.yml`
- **検知対象**: ブラウザ認証情報ファイルアクセス、Credential Vault列挙
- **強み**: Chromium/Firefoxの認証情報ファイルパスの網羅的カバー

### 1.2 elastic/detection-rules
- **代表的なルール**: `credential_access_browser_credentials.toml`, `credential_access_dpapi_masterkey.toml`
- **検知対象**: ブラウザ認証情報、DPAPI Master Key、Credential Vault
- **強み**: DPAPIマスターキーアクセスの詳細検知

### 1.3 splunk/security_content
- **代表的なルール**: Browser Credential Access, Credential Vault Access
- **検知対象**: ブラウザパスワード、Windows Credential Manager
- **強み**: 多ブラウザ（Chrome/Firefox/Edge/Brave等）の包括的カバー

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Browser Credential Theft, Windows Credential Manager Access
- **検知対象**: ブラウザ認証情報窃取、Credential Manager
- **強み**: MDEテレメトリによるファイルアクセスの可視化

---

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. ブラウザ認証情報アクセス** | Login Data/logins.json/Cookiesファイル | 中（カスタムツールで直接アクセス可能） | Sigma, Elastic, Splunk, Sentinel |
| **B. Credential Manager/Vault** | vaultcmd, cmdkey, dpapi::モジュール | 中（API直接呼び出しで回避可能） | Sigma, Elastic, Splunk, Sentinel |
| **C. DPAPIマスターキーアクセス** | %APPDATA%\Microsoft\Protect\下のファイル | 高（ファイルアクセスはカーネルイベント） | Elastic, Sigma, Splunk |

## 3. 統合優先度

### Tier 1: 基礎ルール
1. ブラウザ認証情報ファイルへの不審アクセス
2. Credential Manager / Vault列挙ツール

### Tier 2: 高価値ルール
3. DPAPIマスターキーファイルアクセス

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon | 1 | プロセス作成（ツール実行） | 必須 |
| Sysmon | 11 / FileAccess | ファイルアクセス（認証情報ファイル） | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1555](https://attack.mitre.org/techniques/T1555/)
- [Browser Credential Theft - Red Canary](https://redcanary.com/threat-detection-report/)
