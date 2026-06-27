# T1136.001 Create Account: Local Account — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_net_user_add.yml`, `win_security_user_account_created.yml`
- **検知対象**: net user /addコマンド、EventID 4720（ユーザーアカウント作成）
- **強み**: コマンドラインとイベントログの双方からの検知

### 1.2 elastic/detection-rules
- **代表的なルール**: `persistence_local_account_creation.toml`, `persistence_hidden_account.toml`
- **検知対象**: ローカルアカウント作成、隠しアカウント（$サフィックス）
- **強み**: SAMレジストリ操作による隠しアカウント検知

### 1.3 splunk/security_content
- **代表的なルール**: Local Account Creation, Hidden Account Detection
- **検知対象**: net user、New-LocalUser、wmicによるアカウント作成
- **強み**: 複数のアカウント作成手法の網羅的カバー

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Local Account Created, Account Added to Administrators Group
- **検知対象**: 4720（作成）、4732（グループ追加）の相関検知
- **強み**: アカウント作成→管理者グループ追加の一連のフロー検知

---

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. コマンドライン検知** | net user /add, New-LocalUser, wmic useraccount | 中（API直接呼び出しで回避可能） | Sigma, Elastic, Splunk, Sentinel |
| **B. イベントログ検知** | EventID 4720（作成）+ 4732（グループ追加） | 高（Security Event Logはカーネルが記録） | Sigma, Elastic, Splunk, Sentinel |
| **C. 隠しアカウント検知** | $サフィックス、SAMレジストリ操作 | 高（SAMレジストリ変更はカーネルイベント） | Elastic, Sigma |

### アカウント作成の手法

1. **net user /add**: 最も一般的なCLI手法。コマンドライン監視で容易に検知。
2. **New-LocalUser**: PowerShellネイティブコマンド。ScriptBlock Loggingで記録。
3. **WMI**: wmic useraccount create。WMI経由のアカウント操作。
4. **API直接呼び出し**: NetUserAdd API。コマンドラインには残らないがEventID 4720は記録される。
5. **隠しアカウント**: ユーザー名末尾に$を付加、またはSAMレジストリ直接操作。

## 3. 統合優先度

### Tier 1: 基礎ルール
1. コマンドラインベースのアカウント作成検知（net user /add, New-LocalUser, wmic）
2. イベントログベースの検知（EventID 4720 + 4732の相関）

### Tier 2: 高価値ルール
3. 隠しアカウント作成検知（$サフィックス、SAMレジストリ操作）

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（コマンドライン検知） | 必須 |
| Security | 4720 | ユーザーアカウント作成 | 必須 |
| Security | 4732 | セキュリティ有効グループへのメンバー追加 | 必須 |
| Security | 4724 | パスワードリセット | 推奨 |
| Sysmon | 13 | SAMレジストリ値変更 | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1136.001](https://attack.mitre.org/techniques/T1136/001/)
- [Local Account Creation - Red Canary](https://redcanary.com/threat-detection-report/)
- [Hidden Accounts Detection - SANS](https://www.sans.org/blog/)
