# T1490 Inhibit System Recovery — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_vssadmin_delete.yml`, `proc_creation_win_bcdedit_recovery.yml`
- **検知対象**: VSS削除、bcdedit回復無効化
- **強み**: vssadmin/wmic/PowerShellのVSS操作パターン

### 1.2 elastic/detection-rules
- **代表的なルール**: `impact_vss_deletion.toml`, `impact_bcdedit_recovery.toml`
- **検知対象**: VSS削除、ブート設定変更、wbadmin削除
- **強み**: 複数回復抑制コマンドの連続実行検知

### 1.3 splunk/security_content
- **代表的なルール**: VSS Shadow Copy Delete, BCDEdit Recovery Disable
- **検知対象**: VSS削除、bcdedit、reagentc
- **強み**: ランサムウェアキルチェーンの一部としての相関検知

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: System Recovery Inhibition
- **検知対象**: 回復機能無効化
- **強み**: MDEテレメトリによるランサムウェア前兆検知

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. VSS削除** | vssadmin, wmic shadowcopy, PowerShell | 高（OS組み込みコマンド） | Sigma, Elastic, Splunk, Sentinel |
| **B. ブート設定変更** | bcdedit, reagentc, wbadmin | 高（管理者権限必要） | Sigma, Elastic, Splunk, Sentinel |
| **C. 複数コマンド連続** | 2つ以上の回復抑制コマンド | 高（時間相関で検知） | Elastic, Splunk, Sentinel |

## 3. 統合優先度

### Tier 1: 基礎ルール
1. VSS削除/リサイズ
2. bcdedit/reagentc/wbadmin回復無効化

### Tier 2: 高価値ルール
3. 複数回復抑制コマンドの連続実行

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（回復抑制コマンド） | 必須 |

## 5. 参考資料
- [MITRE ATT&CK T1490](https://attack.mitre.org/techniques/T1490/)
