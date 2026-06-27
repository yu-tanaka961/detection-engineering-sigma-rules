# T1197 BITS Jobs — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_bitsadmin_susp_usage.yml`, `proc_creation_win_bitsadmin_setnotifycmdline.yml`
- **検知対象**: bitsadmin不審コマンド、SetNotifyCmdLine永続化
- **強み**: bitsadminのサブコマンド別の詳細な検知条件

### 1.2 elastic/detection-rules
- **代表的なルール**: `defense_evasion_bits_download.toml`, `persistence_bits_notify_cmdline.toml`
- **検知対象**: BITSダウンロード、BITS永続化、BITSイベントログ
- **強み**: BITS永続化（SetNotifyCmdLine）の専用検知ルール

### 1.3 splunk/security_content
- **代表的なルール**: BITSAdmin Download, BITS Job Persistence
- **検知対象**: bitsadminによるダウンロード、BITS永続化
- **強み**: BITS Clientイベントログの活用

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: BITS Job Abuse, Suspicious BITS Transfer
- **検知対象**: BITS関連の不審活動
- **強み**: MDEテレメトリとBITSイベントの相関分析

---

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. bitsadmin不審コマンド** | /transfer, /addfile + 外部URL | 中（PowerShell BITSで代替可能） | Sigma, Elastic, Splunk, Sentinel |
| **B. BITS永続化（SetNotifyCmdLine）** | SetNotifyCmdLine + 不審実行ファイル | 高（プロセス作成ログで確実に記録） | Sigma, Elastic, Splunk |
| **C. BITSイベントログ監視** | BITS Client EventID 3（ジョブ作成） | 高（BITSサービスが記録、プロセスレベルより包括的） | Sigma, Elastic, Splunk |

### BITS悪用の3つのパターン

1. **ダウンロード**: bitsadmin /transfer や Start-BitsTransfer でマルウェアをダウンロード。プロキシやファイアウォールの検知を回避。
2. **永続化**: SetNotifyCmdLineでジョブ完了時にコマンドを実行。BITSジョブは再起動後も維持される。
3. **横展開**: リモートホストへのBITSジョブ作成（/RemoteName パラメータ）

## 3. 統合優先度

### Tier 1: 基礎ルール
1. bitsadmin不審コマンド実行（/transfer, /addfile + 外部URL）
2. BITS永続化検知（SetNotifyCmdLine + 不審な実行ファイル）

### Tier 2: 高価値ルール
3. BITSイベントログ監視（BITS Client EventID 3 + 非Microsoftドメイン）

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（bitsadminコマンドライン） | 必須 |
| BITS Client | 3 | BITSジョブ作成イベント | 推奨 |
| BITS Client | 59 | BITSジョブ状態変更 | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1197](https://attack.mitre.org/techniques/T1197/)
- [BITS Abuse - FireEye](https://www.fireeye.com/blog/threat-research/2020/03/monitoring-windows-bits-service.html)
- [BITS Transfer Persistence - SANS](https://www.sans.org/blog/)
