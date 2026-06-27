# T1489 Service Stop — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_net_stop.yml`, `proc_creation_win_service_stop.yml`
- **検知対象**: net stop/sc stop による重要サービス停止
- **強み**: 重要サービス名リストによるフィルタリング

### 1.2 elastic/detection-rules
- **代表的なルール**: `impact_service_stop.toml`, `impact_mass_service_stop.toml`
- **検知対象**: サービス停止、大量サービス停止シーケンス
- **強み**: 大量停止の時間窓ベース検知

### 1.3 splunk/security_content
- **代表的なルール**: Service Stop, Ransomware Service Kill
- **検知対象**: サービス停止、taskkill
- **強み**: ランサムウェアターゲットサービスの包括的リスト

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Mass Service Stop Detection
- **検知対象**: 大量サービス停止
- **強み**: 統計的異常検知（通常パターンからの逸脱）

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. CLI サービス停止** | net stop, sc stop, taskkill | 中（PowerShellで回避可能） | Sigma, Elastic, Splunk, Sentinel |
| **B. PowerShell/WMI停止** | Stop-Service, WMI StopService | 中（直接API呼び出しで回避可能） | Sigma, Elastic, Splunk |
| **C. 大量停止シーケンス** | 短時間内の複数サービス停止 | 高（行動パターンは回避困難） | Elastic, Splunk, Sentinel |

## 3. 統合優先度

### Tier 1: 基礎ルール
1. 重要サービスのCLI停止
2. PowerShell/WMIによるサービス停止

### Tier 2: 高価値ルール
3. 大量サービス停止シーケンス

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（サービス停止コマンド） | 必須 |

## 5. 参考資料
- [MITRE ATT&CK T1489](https://attack.mitre.org/techniques/T1489/)
