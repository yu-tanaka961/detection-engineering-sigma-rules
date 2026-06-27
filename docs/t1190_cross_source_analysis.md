# T1190 Exploit Public-Facing Application — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_webshell_spawn.yml`, `file_event_win_webshell_creation_detect.yml`
- **検知対象**: Webサーバープロセスからの不審な子プロセス生成、Webディレクトリへの不審ファイル作成
- **強み**: プロセスツリー解析、ファイルイベント監視

### 1.2 elastic/detection-rules
- **代表的なルール**: `persistence_webshell_detection.toml`, `initial_access_suspicious_ms_office_child_process.toml`
- **検知対象**: Webシェル検知、Exchange脆弱性エクスプロイト（ProxyShell/ProxyLogon）
- **強み**: EQLによる複合条件、Elastic Endpointテレメトリ

### 1.3 splunk/security_content
- **代表的なルール**: W3WP Spawning Shell, Webshell Indicator, ProxyShell Analytics
- **検知対象**: IIS/Apache子プロセス異常、既知CVEエクスプロイトパターン
- **強み**: Analytic Storyによるエクスプロイトチェーン全体の可視化

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Web Shell Activity, Exchange SSRF Detection
- **検知対象**: SecurityEventとIISログの相関、Exchange固有のエクスプロイト痕跡
- **強み**: Azure WAFログとの統合

---

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. Webサーバー子プロセス異常** | w3wp.exe→cmd/powershell | 高（親プロセス偽装困難） | Sigma, Elastic, Splunk, Sentinel |
| **B. Webディレクトリファイル作成** | aspx/jsp/phpファイル書き込み | 高（Webシェル設置に必須） | Sigma, Elastic, Splunk, Sentinel |
| **C. 既知CVEエクスプロイト** | ProxyShell, Log4Shell等 | 中（シグネチャベース） | Sigma, Elastic, Splunk, Sentinel |

---

## 3. 統合優先度

### Tier 1: 基礎ルール
1. Webサーバーからの不審子プロセス生成（親子関係ベース）
2. Webディレクトリへの不審ファイル作成

### Tier 2: 高価値ルール
3. 既知CVEエクスプロイトインジケータ（ProxyShell, Log4Shell等）
