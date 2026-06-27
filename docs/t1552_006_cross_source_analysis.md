# T1552.006 Unsecured Credentials: Group Policy Preferences — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_gpp_password.yml`, `posh_ps_gpp_decrypt.yml`
- **検知対象**: Get-GPPPassword実行、ScriptBlockでのGPPデクリプト
- **強み**: PowerShell ScriptBlockでのAES鍵/cpasswordデクリプト検知

### 1.2 elastic/detection-rules
- **代表的なルール**: `credential_access_gpp_password.toml`, `credential_access_sysvol_gpp.toml`
- **検知対象**: GPPパスワード発見、SYSVOLファイルアクセス
- **強み**: SYSVOLのGPP XMLファイルアクセス監視

### 1.3 splunk/security_content
- **代表的なルール**: GPP Password Discovery, SYSVOL GPP Access
- **検知対象**: GPPパスワード検索、SYSVOLアクセス
- **強み**: findstr/Select-Stringでのcpassword検索パターン

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: GPP Credential Access
- **検知対象**: GPP認証情報アクセス
- **強み**: Azure AD/オンプレADの相関分析

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. GPPパスワードツール実行** | Get-GPPPassword, gpp-decrypt | 中（カスタムスクリプトで回避可能） | Sigma, Elastic, Splunk, Sentinel |
| **B. SYSVOL GPPファイルアクセス** | Groups.xml, Services.xml等のファイル読み取り | 高（ファイルアクセスはカーネルイベント） | Elastic, Sigma, Splunk |
| **C. ScriptBlockでのデクリプト** | cpassword + AES鍵でのデクリプト処理 | 高（ScriptBlock Loggingは難読化解除後を記録） | Sigma, Elastic, Splunk |

### GPP認証情報の攻撃フロー

1. **SYSVOLアクセス**: \\domain\SYSVOL\domain\Policies\下のGPP XMLファイルにアクセス
2. **cpassword取得**: XMLファイルからcpassword属性値を抽出
3. **AESデクリプト**: MS14-025で公開された鍵でcpasswordをデクリプト
4. **認証情報悪用**: 取得したローカル管理者パスワード等で権限昇格

## 3. 統合優先度

### Tier 1: 基礎ルール
1. GPPパスワード発見ツール/コマンド
2. SYSVOL GPP XMLファイルアクセス

### Tier 2: 高価値ルール
3. ScriptBlockでのcpasswordデクリプト活動

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（ツール実行） | 必須 |
| Sysmon | FileAccess | SYSVOLファイルアクセス | 推奨 |
| PowerShell ScriptBlock | 4104 | デクリプト活動検知 | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1552.006](https://attack.mitre.org/techniques/T1552/006/)
- [MS14-025](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-025)
- [GPP Password - ADSecurity](https://adsecurity.org/?p=2288)
