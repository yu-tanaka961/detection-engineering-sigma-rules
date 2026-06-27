# T1482 Domain Trust Discovery — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_nltest_trust.yml`, `proc_creation_win_dsquery_trust.yml`
- **検知対象**: nltest /domain_trusts、dsquery trustedDomain
- **強み**: Windows組み込みコマンドの信頼列挙パターン

### 1.2 elastic/detection-rules
- **代表的なルール**: `discovery_domain_trust.toml`, `discovery_trust_abuse.toml`
- **検知対象**: ドメイン信頼列挙、SID History悪用
- **強み**: 信頼関係悪用（SID History injection）の検知

### 1.3 splunk/security_content
- **代表的なルール**: Domain Trust Discovery, Cross-Domain Trust Abuse
- **検知対象**: 信頼列挙、フォレスト間攻撃
- **強み**: ADFind/PowerViewでの信頼オブジェクト検索の検知

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Domain Trust Enumeration
- **検知対象**: ドメイン信頼列挙活動
- **強み**: Azure ADとオンプレADのハイブリッド信頼監視

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. 組み込みコマンド** | nltest, dsquery, netdom | 中（代替ツールで回避可能） | Sigma, Elastic, Splunk, Sentinel |
| **B. PowerShell/LDAP列挙** | Get-ADTrust, Get-DomainTrust, ADFind | 中（カスタムクエリで回避可能） | Sigma, Elastic, Splunk |
| **C. 信頼関係悪用** | SID History injection、信頼キー抽出 | 高（Kerberos/ADイベントで検知） | Elastic, Splunk, Sentinel |

## 3. 統合優先度

### Tier 1: 基礎ルール
1. 組み込みコマンドでの信頼列挙
2. PowerShell/ADFindでの信頼オブジェクト検索

### Tier 2: 高価値ルール
3. クロスドメイン信頼悪用インジケータ

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（コマンド実行） | 必須 |

## 5. 参考資料
- [MITRE ATT&CK T1482](https://attack.mitre.org/techniques/T1482/)
- [AD Trust Abuse - ADSecurity](https://adsecurity.org/?p=1772)
- [SID Filtering and Forest Trusts](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/)
