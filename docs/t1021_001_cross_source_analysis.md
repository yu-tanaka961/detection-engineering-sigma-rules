# T1021.001 Remote Desktop Protocol — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_mstsc.yml`, `proc_creation_win_tscon.yml`
- **検知対象**: mstsc.exeリモート接続、tsconセッションハイジャック
- **強み**: RDPセッションハイジャック（tscon）の詳細検知

### 1.2 elastic/detection-rules
- **代表的なルール**: `lateral_movement_rdp.toml`, `defense_evasion_rdp_enable.toml`
- **検知対象**: RDPラテラルムーブメント、RDP有効化
- **強み**: レジストリ/ファイアウォール経由のRDP有効化検知

### 1.3 splunk/security_content
- **代表的なルール**: RDP Lateral Movement, RDP Session Hijack
- **検知対象**: RDP接続、セッションハイジャック、ポートトンネリング
- **強み**: RDPポートトンネリング（chisel, plink等）の検知

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: RDP Lateral Movement
- **検知対象**: RDPラテラルムーブメント
- **強み**: ネットワークログオン（Type 10）の統計分析

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. RDP接続/ツール** | mstsc /v:, SharpRDP, xfreerdp | 中（代替ツールで回避可能） | Sigma, Elastic, Splunk, Sentinel |
| **B. セッションハイジャック** | tscon /dest:, qwinsta | 高（SYSTEM権限が必要） | Sigma, Elastic, Splunk |
| **C. RDP有効化/設定変更** | fDenyTSConnections, ファイアウォール3389 | 高（レジストリ変更はカーネルが記録） | Elastic, Splunk, Sentinel |

## 3. 統合優先度

### Tier 1: 基礎ルール
1. RDP不審接続/ツール実行
2. RDPセッションハイジャック（tscon）

### Tier 2: 高価値ルール
3. RDP有効化レジストリ/ファイアウォール変更

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（mstsc, tscon等） | 必須 |
| Windows Security Logon | 4624 (Type 10) | RDPログオンイベント | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1021.001](https://attack.mitre.org/techniques/T1021/001/)
- [RDP Hijacking](https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6)
