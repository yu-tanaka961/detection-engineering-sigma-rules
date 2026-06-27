# T1649 Steal or Forge Authentication Certificates (AD CS) — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_certutil_export.yml`, `proc_creation_win_certipy.yml`
- **検知対象**: certutil証明書エクスポート、AD CS攻撃ツール実行
- **強み**: certutil/certreqコマンドラインの詳細パターン検知

### 1.2 elastic/detection-rules
- **代表的なルール**: `credential_access_adcs_certificate_request.toml`, `credential_access_certipy.toml`
- **検知対象**: AD CS証明書要求異常、ESC1-ESC8テンプレート悪用
- **強み**: 証明書テンプレート悪用のイベントログベース検知

### 1.3 splunk/security_content
- **代表的なルール**: AD CS Certificate Abuse, Certipy Tool Detection
- **検知対象**: 証明書登録異常、攻撃ツール実行
- **強み**: SAN属性を含む証明書要求の異常検知

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: AD CS Certificate Template Abuse
- **検知対象**: 証明書テンプレート変更、異常な証明書発行
- **強み**: AD CSイベントログ（4886/4887/4898/4899）の統合分析

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. 証明書エクスポート/要求** | certutil -exportPFX, certreq -submit | 中（API直接呼び出しで回避可能） | Sigma, Elastic, Splunk |
| **B. AD CS攻撃ツール** | Certipy, ForgeCert, PassTheCert | 中（ツール名変更で回避可能） | Sigma, Elastic, Splunk |
| **C. 証明書テンプレート悪用** | ESC1-ESC8、SAN属性悪用（4887） | 高（AD CSイベントログは回避困難） | Elastic, Splunk, Sentinel |

## 3. 統合優先度

### Tier 1: 基礎ルール
1. certutil/certreq証明書エクスポート・要求
2. AD CS攻撃ツール実行検知

### Tier 2: 高価値ルール
3. 証明書テンプレート悪用インジケータ（ESC1-ESC8）

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（ツール実行） | 必須 |
| AD CS Audit | 4886 | 証明書要求受信 | 推奨 |
| AD CS Audit | 4887 | 証明書発行 | 推奨 |
| AD CS Audit | 4898/4899 | テンプレートロード/変更 | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1649](https://attack.mitre.org/techniques/T1649/)
- [Certified Pre-Owned - SpecterOps](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [Certipy](https://github.com/ly4k/Certipy)
