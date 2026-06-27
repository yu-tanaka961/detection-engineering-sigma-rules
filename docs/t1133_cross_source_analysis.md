# T1133 External Remote Services — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `win_security_rdp_bruteforce.yml`, `win_security_rdp_login_from_external.yml`
- **検知対象**: RDPブルートフォース（4625）、外部IPからのRDPログオン
- **強み**: Windowsセキュリティイベントの包括的カバレッジ

### 1.2 elastic/detection-rules
- **代表的なルール**: `credential_access_rdp_brute_force.toml`, `initial_access_rdp_from_external.toml`
- **検知対象**: RDPブルートフォース、VPN異常、外部リモートアクセス
- **強み**: ネットワーク接続とプロセスの相関分析

### 1.3 splunk/security_content
- **代表的なルール**: Windows Multiple Account Lockouts, RDP from External Source
- **検知対象**: アカウントロックアウト頻発、外部からのRDP
- **強み**: CIMベースの正規化、時系列異常検知

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: RDP Brute Force Detection, Anomalous VPN Connection
- **検知対象**: RDPブルートフォース、VPN異常ログオン、Conditional Access連携
- **強み**: Azure AD / Entra IDとの統合、地理情報ベースの異常検知

---

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. RDPブルートフォース** | EventID 4625 多数発生 | 高（認証ログ必須） | Sigma, Elastic, Splunk, Sentinel |
| **B. 外部IPからのRDPログオン** | 非RFC1918からの4624/LogonType10 | 高（IPアドレス偽装困難） | Sigma, Elastic, Splunk, Sentinel |
| **C. VPN異常ログオン** | NPS/RADIUS認証異常 | 中（VPN種別依存） | Splunk, Sentinel, Elastic |

---

## 3. 統合優先度

### Tier 1: 基礎ルール
1. RDPブルートフォース検知（EventID 4625集計）
2. 外部（パブリック）IPからのRDPログオン

### Tier 2: 高価値ルール
3. VPN異常ログオンパターン（NPS/RADIUS）

## 4. ログ要件

| EventID | ログソース | 必要な設定 |
|---|---|---|
| 4625 | Windows Security | ログオン失敗の監査（デフォルト有効） |
| 4624 | Windows Security | ログオン成功の監査（デフォルト有効） |
| 6272/6273 | Windows Security | NPS（RADIUS）ログの有効化 |
| 20271 | System | RRAS VPN接続ログの有効化 |
