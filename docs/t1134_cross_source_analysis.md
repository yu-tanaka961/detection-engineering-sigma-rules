# T1134 Access Token Manipulation — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_hktl_token_manipulation.yml`, `win_security_token_privilege_adjusted.yml`
- **検知対象**: トークン操作ツール、トークン権限調整
- **強み**: 既知ツール（Incognito, Mimikatz token）の網羅的なシグネチャ

### 1.2 elastic/detection-rules
- **代表的なルール**: `privilege_escalation_token_manipulation.toml`, `defense_evasion_ppid_spoofing.toml`
- **検知対象**: トークン操作、権限昇格、Parent PIDスプーフィング
- **強み**: EventID 4703（トークン権限調整）の高精度検知、PPID異常検知

### 1.3 splunk/security_content
- **代表的なルール**: Access Token Manipulation, Parent PID Spoofing
- **検知対象**: トークン操作コマンド、PPID異常
- **強み**: runas /netonly検知、API呼び出しパターンの検知

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Token Manipulation Detection, Suspicious Token Privilege
- **検知対象**: トークン操作、権限昇格異常
- **強み**: MDEテレメトリによるトークンレベルの可視化

---

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. トークン操作ツール** | Incognito, Mimikatz token, runas /netonly | 中（ツール名変更で回避可能） | Sigma, Elastic, Splunk, Sentinel |
| **B. トークン権限調整** | EventID 4703（SeDebugPrivilege等の取得） | 高（Security Event Logはカーネルが記録） | Elastic, Sigma, Splunk, Sentinel |
| **C. Parent PIDスプーフィング** | PPID不整合（svchost←cmd等の異常な親子関係） | 高（プロセス作成はカーネルイベント） | Elastic, Sigma, Splunk |

### トークン操作の主要手法

1. **Token Impersonation/Theft**: 他プロセスのトークンをコピーして使用。SeImpersonatePrivilege必須。
2. **Create Process with Token**: DuplicateTokenEx + CreateProcessWithToken でトークン付きプロセス作成。
3. **Parent PID Spoofing**: PROC_THREAD_ATTRIBUTE_PARENT_PROCESSで偽の親プロセスを指定。
4. **Make and Impersonate Token**: LogonUser APIで新規トークンを作成しスレッドに設定。

## 3. 統合優先度

### Tier 1: 基礎ルール
1. トークン操作ツール検知（Incognito, Mimikatz, PowerShell API呼び出し）
2. トークン権限調整検知（EventID 4703: SeDebugPrivilege等の異常取得）

### Tier 2: 高価値ルール
3. Parent PIDスプーフィング検知（Windows標準プロセスの異常な親子関係）

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（コマンドライン検知） | 必須 |
| Security | 4703 | トークン権限調整 | 推奨 |
| Sysmon | 1 | プロセス作成（Parent PID検証） | 必須 |

## 5. 参考資料
- [MITRE ATT&CK T1134](https://attack.mitre.org/techniques/T1134/)
- [Token Manipulation - Red Canary](https://redcanary.com/threat-detection-report/)
- [PPID Spoofing Detection](https://blog.didierstevens.com/2009/11/22/quickpost-selectmyparent-or-playing-with-the-parent-process/)
