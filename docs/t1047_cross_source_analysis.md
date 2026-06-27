# T1047 Windows Management Instrumentation — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_wmic_susp_execution.yml`, `sysmon_wmi_event_subscription.yml`
- **検知対象**: WMIC不審実行、WMIイベントサブスクリプション永続化
- **強み**: Sysmon WMIイベント（19/20/21）のネイティブサポート

### 1.2 elastic/detection-rules
- **代表的なルール**: `execution_wmic_suspicious.toml`, `persistence_wmi_event_subscription.toml`
- **検知対象**: WMIC悪用、WmiPrvSE子プロセス異常、WMI永続化
- **強み**: WmiPrvSE.exeの親子関係分析

### 1.3 splunk/security_content
- **代表的なルール**: Suspicious WMIC Usage, WMI Permanent Event Subscription
- **検知対象**: WMIC不審コマンド、WMIイベントサブスクリプション
- **強み**: WMI横展開の検知（/node: パラメータ監視）

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: WMIC Suspicious Activity, WMI Event Subscription Persistence
- **検知対象**: WMI関連の不審活動
- **強み**: MDEテレメトリによるWMI活動の包括的可視化

---

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. WMIC不審コマンド** | wmic process call create, /node: | 中（PowerShell WMI CIMで代替可能） | Sigma, Elastic, Splunk, Sentinel |
| **B. WmiPrvSE子プロセス** | WmiPrvSE.exe→shell/LOLBin | 高（カーネル強制の親子関係） | Elastic, Sigma, Splunk, Sentinel |
| **C. WMIイベントサブスクリプション** | Sysmon 19/20/21イベント | 高（Sysmonログは回避困難） | Sigma, Elastic, Splunk, Sentinel |

### WMI実行の2つのパス

1. **WMIC.exe経由**: コマンドラインツール。プロセス作成ログで検知可能。Microsoftは非推奨化を進めている。
2. **WMI CIM/COM経由**: PowerShellのGet-WmiObject/Invoke-WmiMethod、.NETのManagementObject等。WmiPrvSE.exeの子プロセス監視で検知。

## 3. 統合優先度

### Tier 1: 基礎ルール
1. WMIC不審コマンド実行（process call create, /node:, XSL等）
2. WmiPrvSE.exeからの不審子プロセス生成

### Tier 2: 高価値ルール
3. WMIイベントサブスクリプション永続化（Sysmon 19/20/21）

## 4. ログ要件

| EventID | ログソース | 必要な設定 |
|---|---|---|
| 1 (Sysmon) / 4688 | Process Creation | プロセス作成の監査 + コマンドライン |
| 19, 20, 21 (Sysmon) | Sysmon | SysmonでWMIイベント監視を有効化 |
