# T1078 Valid Accounts — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `win_security_susp_failed_logons_single_source.yml`, `win_security_admin_logon_non_dc.yml`
- **検知対象**: 単一ソースからの失敗ログオン集中、非DCからの管理者ログオン
- **強み**: EventID 4625/4624/4672の包括的カバレッジ

### 1.2 elastic/detection-rules
- **代表的なルール**: `credential_access_brute_force_logon.toml`, `privilege_escalation_admin_logon_anomaly.toml`
- **検知対象**: ブルートフォース成功パターン、特権アカウントの異常使用
- **強み**: ML（Machine Learning）ジョブとの統合、Rare Userモデル

### 1.3 splunk/security_content
- **代表的なルール**: Brute Force Access Behavior Detected, Previously Seen Users
- **検知対象**: ブルートフォース成功、初見ユーザー検知
- **強み**: ルックアップテーブルによるベースライン管理

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Dormant Account Logon, Admin Logon Anomaly
- **検知対象**: 休眠アカウントの再活性化、管理者ログオンの異常
- **強み**: Entra ID Identity Protectionとの統合

---

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. ブルートフォース検知** | 4625多数→4624成功パターン | 高（認証ログ必須） | Sigma, Elastic, Splunk, Sentinel |
| **B. 休眠アカウント活性化** | 長期未使用アカウントのログオン | 中（ベースライン依存） | Sentinel, Splunk, Elastic |
| **C. 特権アカウント異常** | 管理者の非標準端末からのログオン | 高（4672ログ必須） | Sigma, Elastic, Splunk, Sentinel |

---

## 3. 統合優先度

### Tier 1: 基礎ルール
1. 複数失敗→成功ログオンパターン
2. 休眠アカウントの活性化検知

### Tier 2: 高価値ルール
3. 特権アカウントの異常ソースからのログオン
