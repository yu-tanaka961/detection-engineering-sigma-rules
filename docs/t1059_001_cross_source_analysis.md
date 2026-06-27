# T1059.001 PowerShell — Cross-Source Detection Analysis & Unified Sigma Rules

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **ルール数**: 30件以上がT1059.001タグ付き
- **形式**: Sigma YAML（変換不要）
- **代表的な検知パターン**:
  - `proc_creation_win_powershell_base64_encoded_cmd.yml` — Base64エンコードされたコマンドライン
  - `proc_creation_win_powershell_susp_download_patterns.yml` — IEX + DownloadStringパターン
  - `proc_creation_win_powershell_susp_parameter_variation.yml` — -NoP, -W Hidden等の不審パラメータ
  - `proc_creation_win_powershell_encode.yml` — 既知の悪意あるcmdlet実行
  - `proc_creation_win_schtasks_reg_loader.yml` — schtasks経由でレジストリからPowerShellペイロード読み込み
- **logsource**: `category: process_creation, product: windows`（Sysmon EventID 1 / Security 4688）
- **強み**: コミュニティレビュー済み、幅広いカバレッジ、pySigmaで各SIEM変換可能

### 1.2 elastic/detection-rules
- **ルール数**: 15件以上がT1059.001参照
- **形式**: TOML / EQL・KQL
- **代表的な検知パターン**:
  - `defense_evasion_amsi_bypass_powershell.toml` — AMSIバイパスの試行検知
  - `defense_evasion_defender_exclusion_via_powershell.toml` — Defender除外設定の追加
  - `execution_suspicious_powershell_imgload.toml` — 不審なDLLロード経由のPS実行
  - `execution_scheduled_task_powershell_source.toml` — スケジュールタスク経由のPS実行
  - `initial_access_suspicious_ms_office_child_process.toml` — Office→PowerShell子プロセス
- **logsource**: `logs-endpoint.events.*` / ECS準拠
- **強み**: EQL（Event Query Language）による高度な相関ルール、parent-child関係の検知

### 1.3 splunk/security_content
- **ルール数**: 20件以上がT1059.001タグ付き
- **形式**: YAML定義 + SPL検索クエリ
- **代表的な検知パターン**:
  - PowerShell ScriptBlock Logging (EventID 4104) の監視
  - Encoded PowerShell + Network Connection の相関
  - Malicious PowerShell Commandlets の網羅的リスト
  - AMSI bypass パターン（Reflection, Patching）
- **logsource**: Sysmon EventID 1 / Windows Security 4688 / PowerShell 4104
- **強み**: Analytic Story による文脈付与、CIM（Common Information Model）正規化

### 1.4 Azure/Azure-Sentinel Detections
- **形式**: KQL (Kusto Query Language)
- **代表的な検知パターン**:
  - SecurityEvent テーブルでの PowerShell 実行検知
  - SigninLogs との相関（誰がPSを実行したか）
  - DeviceProcessEvents による MDE 連携
  - OfficeActivity との統合（Office→PS実行チェーン）
- **logsource**: SecurityEvent / DeviceProcessEvents / AzureActivity
- **強み**: Entra ID / Azure AD との統合、クラウドネイティブなコンテキスト

### 1.5 elastic/protections-artifacts (behavior)
- **形式**: TOML / EQL（behavior detection）
- **代表的な検知パターン**:
  - `execution_suspicious_command_shell_execution_via_windows_run.toml` — Windows Run経由の不審実行
  - PowerShell + User Execution (T1204) の組み合わせ
  - Endpoint Security層でのbehavior detection（メモリ内実行、反射的DLLロード）
- **logsource**: Elastic Endpoint telemetry
- **強み**: EDR固有のbehavior（メモリスキャン、DLLインジェクション）をカバー

---

## 2. 検知アプローチの分類（回避困難な痕跡の観点から）

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. Base64エンコードコマンド** | `-EncodedCommand` / `-e` + Base64文字列 | 中（パラメータ短縮で回避可能） | Sigma, Elastic, Splunk, Sentinel |
| **B. 不審ダウンロードパターン** | `IEX(New-Object Net.WebClient).DownloadString` | 中（難読化で回避可能） | Sigma, Splunk, Sentinel |
| **C. 不審パラメータ組み合わせ** | `-NoP -W Hidden -Exec Bypass` の組み合わせ | 中〜低（代替手法多数） | Sigma, Elastic, Splunk |
| **D. 親プロセス異常** | Office/Exchange/IIS→PowerShell起動 | 高（親プロセス偽装は困難） | Elastic, Splunk, Sentinel |
| **E. AMSIバイパス試行** | `AmsiUtils`, `amsiInitFailed` 等の文字列 | 高（AMSI操作は検知が容易） | Elastic, Splunk |
| **F. ScriptBlock Logging** | EventID 4104 のスクリプトブロック内容 | 高（ログ自体の無効化以外回避困難） | Splunk, Sigma, Sentinel |
| **G. Behavior Detection** | メモリ内実行、反射的DLLロード | 最高（EDR固有テレメトリ） | Elastic Protect |

---

## 3. 統合優先度

### Tier 1: 基礎ルール（全ソース合意・即時導入）
1. Base64エンコードPowerShellコマンド検知
2. 不審パラメータ組み合わせ検知（-NoP -W Hidden -Exec Bypass）
3. 不審ダウンロード＋実行パターン

### Tier 2: 高価値ルール（複数ソース合意・環境依存チューニング要）
4. Office/IIS/Exchange→PowerShell親子プロセス異常
5. AMSIバイパス試行検知
6. ScriptBlock Logging（EventID 4104）の悪意あるcmdlet検知

### Tier 3: 高度ルール（EDR固有・追加テレメトリ要）
7. PowerShell CLM（Constrained Language Mode）バイパス
8. .NET Reflection経由のインメモリ実行
9. PowerShell Runspace APIの直接呼び出し

---

## 4. 統合ルールの設計方針

各統合Sigmaルールは以下の拡張メタデータを持つ:
- `x-source-provenance`: 元となったソースリポジトリのリスト
- `x-evasion-resistance`: 回避困難度（1-5, DRS ED軸との整合）
- `x-log-requirements`: 必要なログソースとEventID
- `x-drs-category`: DRSフレームワークのDQ次元との対応
