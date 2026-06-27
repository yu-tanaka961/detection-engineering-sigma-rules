# T1569.002 System Services: Service Execution — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `win_system_service_install_susp.yml`, `proc_creation_win_sc_service_creation.yml`
- **検知対象**: 不審なサービスインストール（7045）、sc.exeによるサービス作成
- **強み**: EventID 7045のサービスバイナリパス解析

### 1.2 elastic/detection-rules
- **代表的なルール**: `persistence_suspicious_service_creation.toml`, `execution_services_child_process.toml`
- **検知対象**: 不審なサービス作成、services.exeの子プロセス異常
- **強み**: サービスバイナリの振る舞い分析

### 1.3 splunk/security_content
- **代表的なルール**: Suspicious Service Installation, SC.exe Service Creation
- **検知対象**: サービスインストール、sc.exe悪用
- **強み**: PsExec、Cobalt Strikeサービスの固有パターン

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Suspicious Service Created, Unusual Service Child Process
- **検知対象**: 不審サービス作成、サービス経由の異常プロセス
- **強み**: MDE テレメトリとの統合

---

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. サービスインストール監視** | EventID 7045 + 不審バイナリパス | 高（カーネルレベルのログ） | Sigma, Elastic, Splunk, Sentinel |
| **B. sc.exeによる操作** | sc.exe create/config コマンド | 中（WMI等で代替可能） | Sigma, Elastic, Splunk |
| **C. services.exe子プロセス** | services.exe→shell/LOLBin | 高（カーネル強制の親子関係） | Elastic, Sigma, Splunk |

## 3. 統合優先度

### Tier 1: 基礎ルール
1. 不審なサービスインストール（EventID 7045監視）
2. sc.exeによるサービス作成（不審なbinPath）

### Tier 2: 高価値ルール
3. services.exeからの不審子プロセス生成

## 4. ログ要件

| EventID | ログソース | 必要な設定 |
|---|---|---|
| 7045 | System | デフォルトで有効 |
| 4688 | Windows Security | プロセス作成の監査 + コマンドライン記録 |
