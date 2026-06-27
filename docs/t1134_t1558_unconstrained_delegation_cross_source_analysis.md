# T1134/T1558 Unconstrained Delegation Abuse — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_delegation_enum.yml`, `proc_creation_win_rubeus_tgt.yml`
- **検知対象**: 制約なし委任列挙、TGT抽出ツール
- **強み**: PowerView/ADModuleでの委任列挙パターン検知

### 1.2 elastic/detection-rules
- **代表的なルール**: `credential_access_unconstrained_delegation.toml`, `credential_access_coercion.toml`
- **検知対象**: 委任列挙、認証強制、TGT抽出
- **強み**: PrinterBug/PetitPotam等の認証強制ツール検知

### 1.3 splunk/security_content
- **代表的なルール**: Unconstrained Delegation Enumeration, Kerberos Delegation Abuse
- **検知対象**: LDAP委任クエリ、Kerberos委任悪用
- **強み**: LDAP検索フィルタの詳細分析

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Unconstrained Delegation Detection
- **検知対象**: 制約なし委任アカウントへの認証異常
- **強み**: ハイブリッド環境での委任アカウント監視

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. 委任列挙** | TRUSTED_FOR_DELEGATION LDAP検索 | 中（カスタムクエリで回避可能） | Sigma, Elastic, Splunk, Sentinel |
| **B. TGT抽出** | Rubeus monitor/dump, sekurlsa::tickets | 中（ツール名変更で回避可能） | Sigma, Elastic, Splunk |
| **C. 認証強制** | PrinterBug, PetitPotam, DFSCoerce | 中（新しい強制手法が継続的に発見） | Elastic, Splunk, Sentinel |

### Unconstrained Delegation攻撃フロー

1. **列挙**: TRUSTED_FOR_DELEGATION フラグを持つアカウントを発見
2. **侵害**: 委任ホストを侵害
3. **認証強制**: PrinterBug/PetitPotam等でDCを委任ホストに認証させる
4. **TGT抽出**: Rubeus/Mimikatzで委任ホスト上のDC TGTを抽出
5. **権限昇格**: DCのTGTでPass-the-Ticket、ドメイン管理者権限を取得

## 3. 統合優先度

### Tier 1: 基礎ルール
1. 制約なし委任列挙活動
2. TGT抽出ツール実行

### Tier 2: 高価値ルール
3. 認証強制ツール/手法の検知

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（ツール実行） | 必須 |
| Windows Security Kerberos | 4768/4769 | Kerberos認証イベント | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1134](https://attack.mitre.org/techniques/T1134/)
- [MITRE ATT&CK T1558](https://attack.mitre.org/techniques/T1558/)
- [Unconstrained Delegation Abuse - SpecterOps](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1)
- [krbrelayx](https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/)
