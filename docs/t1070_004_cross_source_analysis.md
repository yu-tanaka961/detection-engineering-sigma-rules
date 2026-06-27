# T1070.004 Indicator Removal: File Deletion — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_susp_file_deletion.yml`, `win_security_event_log_cleared.yml`
- **検知対象**: 不審ファイル削除、イベントログクリア、Shadow Copy削除
- **強み**: 幅広い削除手法のカバー（vssadmin, wevtutil, fsutil等）

### 1.2 elastic/detection-rules
- **代表的なルール**: `defense_evasion_file_deletion.toml`, `defense_evasion_timestomp.toml`
- **検知対象**: 証拠ファイル削除、タイムスタンプ改ざん、イベントログクリア
- **強み**: Timestomping検知（Sysmon EventID 2）の高精度ルール

### 1.3 splunk/security_content
- **代表的なルール**: Suspicious File Deletion, Event Log Cleared
- **検知対象**: ファイル削除コマンド、イベントログクリア
- **強み**: Prefetch/USN Journal削除の包括的検知

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Security Event Log Cleared, Evidence Tampering
- **検知対象**: イベントログクリア、証拠隠滅活動
- **強み**: EventID 1102の高信頼度検知

---

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. ファイル削除コマンド** | vssadmin, wevtutil, fsutil, sdelete | 中（API直接呼び出しで回避可能） | Sigma, Elastic, Splunk, Sentinel |
| **B. イベントログクリア** | EventID 1102（Security log cleared） | 高（Event Logサービスが記録、抑制は非常に困難） | Sigma, Elastic, Splunk, Sentinel |
| **C. タイムスタンプ改ざん** | Sysmon EventID 2（FileCreateTimeChanged） | 高（カーネルレベルのファイルシステム監視） | Elastic, Sigma, Splunk |

### 証拠隠滅の主要手法

1. **Shadow Copy削除**: vssadmin delete shadows / wmic shadowcopy delete。ランサムウェアでも頻出。
2. **イベントログクリア**: wevtutil cl Security / Clear-EventLog。EventID 1102が生成される。
3. **USN Journal削除**: fsutil usn deletejournal。ファイル変更履歴の消去。
4. **Prefetch削除**: Prefetchファイルの削除による実行痕跡の消去。
5. **Timestomping**: ファイル作成日時を改ざんし、タイムライン分析を妨害。

## 3. 統合優先度

### Tier 1: 基礎ルール
1. 不審ファイル削除コマンド検知（Shadow Copy, Event Log, USN Journal等）
2. イベントログクリア検知（EventID 1102）

### Tier 2: 高価値ルール
3. タイムスタンプ改ざん検知（Sysmon EventID 2）

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（削除コマンド検知） | 必須 |
| Security | 1102 | Security Event Log クリア | 必須 |
| System | 104 | System Event Log クリア | 推奨 |
| Sysmon | 2 | ファイル作成時刻変更（Timestomping） | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1070.004](https://attack.mitre.org/techniques/T1070/004/)
- [MITRE ATT&CK T1070.001](https://attack.mitre.org/techniques/T1070/001/)
- [Evidence Destruction Detection - SANS DFIR](https://www.sans.org/blog/)
