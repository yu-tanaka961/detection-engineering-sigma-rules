# T1078.004 Valid Accounts: Cloud Accounts — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 Azure/Azure-Sentinel
- **代表的なルール**: Impossible Travel Activity, MFA Fatigue Detection, Service Principal Abuse
- **検知対象**: Impossible Travel、MFA疲労攻撃、サービスプリンシパル悪用
- **強み**: Azure AD Sign-In Logsのネイティブ統合、Identity Protection Risk Score活用
- **ログソース**: SigninLogs, AuditLogs, AADNonInteractiveUserSignInLogs

### 1.2 elastic/detection-rules
- **代表的なルール**: `cloud_auth_impossible_travel.toml`, `cloud_persistence_service_principal_abuse.toml`
- **検知対象**: クラウド認証異常、サービスプリンシパル永続化
- **強み**: マルチクラウド対応（Azure, AWS, GCP）、EQLによる複合条件

### 1.3 splunk/security_content
- **代表的なルール**: Azure AD Impossible Travel, Azure AD Multiple MFA Requests
- **検知対象**: Impossible Travel、MFA疲労、OAuth同意フィッシング
- **強み**: CIMベースのマルチクラウド正規化、Analytic Story

---

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. Impossible Travel** | 地理的に不可能な場所からのサインイン | 中（VPN/Proxyで回避可能） | Sentinel, Splunk, Elastic |
| **B. MFA疲労攻撃** | MFA拒否→承認パターン | 高（認証ログに必ず記録） | Sentinel, Splunk, Elastic |
| **C. サービスプリンシパル悪用** | 資格情報追加、権限付与 | 高（監査ログに必ず記録） | Sentinel, Splunk, Elastic |

### クラウドアカウント攻撃の特徴

1. **ログの不可避性**: クラウドプロバイダの認証・監査ログは攻撃者が無効化できない（回避困難な痕跡）
2. **Identity Protectionの活用**: Azure AD Identity Protectionのリスクスコアは、単一イベントでは見えない異常を機械学習で検知
3. **サービスプリンシパルの重要性**: 人間のアカウントだけでなく、アプリケーション ID（サービスプリンシパル）の監視が不可欠

---

## 3. 統合優先度

### Tier 1: 基礎ルール
1. Impossible Travel / 異常サインイン検知
2. MFA疲労攻撃検知（プッシュ通知ボミング）

### Tier 2: 高価値ルール
3. サービスプリンシパルの不審な操作

## 4. ログ要件

| ログソース | 必要な設定 | 対応ルール |
|---|---|---|
| Azure AD SigninLogs | Azure AD診断設定の有効化 | impossible_travel, mfa_fatigue |
| Azure AD AuditLogs | Azure AD診断設定の有効化 | service_principal |
| Azure AD Identity Protection | P2ライセンス推奨 | impossible_travel (risk score) |

### 重要: Azure ADログの転送設定

クラウドアカウント検知にはAzure AD（Entra ID）のログをSIEMに転送する設定が前提:
1. Azure Portal → Entra ID → 診断設定 → SIEMワークスペースへの転送を有効化
2. SigninLogs, AuditLogs, NonInteractiveUserSignInLogs を対象に含める
3. Azure AD Identity Protection（P2ライセンス）によるリスクスコアの活用を推奨
