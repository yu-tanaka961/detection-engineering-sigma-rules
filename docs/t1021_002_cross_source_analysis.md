# T1021.002 SMB/Windows Admin Shares — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_psexec.yml`, `proc_creation_win_admin_share.yml`
- **検知対象**: PsExec実行、管理共有アクセス
- **強み**: PsExec/PaExecのコマンドラインパターン検知

### 1.2 elastic/detection-rules
- **代表的なルール**: `lateral_movement_smb_admin_share.toml`, `lateral_movement_psexec.toml`
- **検知対象**: SMB管理共有経由のラテラルムーブメント
- **強み**: リモートサービスインストール（7045）の異常パス検知

### 1.3 splunk/security_content
- **代表的なルール**: PsExec Lateral Movement, Admin Share Access
- **検知対象**: PsExec、管理共有コピー、Impacketツール
- **強み**: Impacket psexec.py/smbexec.py等のPython版検知

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: SMB Lateral Movement
- **検知対象**: SMBベースのラテラルムーブメント
- **強み**: ネットワークログオン（Type 3）との相関分析

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. PsExec/類似ツール** | PsExec, PaExec, Impacket | 中（カスタムツールで回避可能） | Sigma, Elastic, Splunk, Sentinel |
| **B. 管理共有アクセス** | net use \\\\host\ADMIN$, C$ | 中（代替手法で回避可能） | Sigma, Elastic, Splunk |
| **C. リモートサービスインストール** | 7045 + 不審パス/サービス名 | 高（サービスインストールはカーネルが記録） | Elastic, Splunk, Sentinel |

## 3. 統合優先度

### Tier 1: 基礎ルール
1. PsExec/SMBラテラルムーブメント
2. 管理共有への不審アクセス

### Tier 2: 高価値ルール
3. リモートサービスインストール（不審パス）

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（PsExec等） | 必須 |
| Windows System | 7045 | サービスインストール | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1021.002](https://attack.mitre.org/techniques/T1021/002/)
- [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)
- [Impacket](https://github.com/fortra/impacket)
