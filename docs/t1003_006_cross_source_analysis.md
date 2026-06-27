# T1003.006 DCSync — Cross-Source Detection Analysis & Unified Sigma Rules

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **ルール数**: 5件以上がT1003.006に関連
- **形式**: Sigma YAML（変換不要）
- **代表的な検知パターン**:
  - `win_security_dcsync.yml` — EventID 4662でのレプリケーションGUID検知
  - `win_security_replication_user_backdoor.yml` — レプリケーション権限の委任検知
  - `proc_creation_win_hktl_mimikatz_command_line.yml` — Mimikatzコマンドライン検知
- **logsource**: `product: windows, service: security`（EventID 4662 / 5136）
- **強み**: 4662イベントの正確なGUIDマッチング、DC機器アカウントのフィルタリング

### 1.2 elastic/detection-rules
- **ルール数**: 3件以上がT1003.006参照
- **形式**: TOML / EQL・KQL
- **代表的な検知パターン**:
  - `credential_access_dcsync_replication_rights.toml` — DRSレプリケーション権限の使用検知
  - `persistence_dcsync_permissions_granted.toml` — レプリケーション権限の付与検知
  - ネットワークレベルでのDRSUAPI通信異常検知
- **logsource**: `logs-endpoint.events.*` / `logs-windows.*`
- **強み**: EQLによるプロセスとネットワークの相関、権限委任の事前検知

### 1.3 splunk/security_content
- **ルール数**: 5件以上がDCSync関連
- **形式**: YAML定義 + SPL検索クエリ
- **代表的な検知パターン**:
  - DCSync Attack（EventID 4662ベース）
  - Credential Dumping via Mimikatz（プロセス作成ベース）
  - AD Replication Permission Granted（EventID 5136ベース）
  - DCSync Network Indicator（ネットワークベース）
- **logsource**: Windows Security EventLog / Sysmon / Network Traffic
- **強み**: Analytic Storyによる攻撃チェーン全体の可視化

### 1.4 Azure/Azure-Sentinel Detections
- **形式**: KQL (Kusto Query Language)
- **代表的な検知パターン**:
  - SecurityEvent 4662での非DCアカウントによるレプリケーション要求
  - IdentityDirectoryEvents（MDI）でのDCSync検知
  - Replication Rights Delegationの異常検知
- **logsource**: SecurityEvent / IdentityDirectoryEvents / AzureADDirectoryLogs
- **強み**: Microsoft Defender for Identity（MDI）との統合、Azure AD Connectの正確なフィルタリング

---

## 2. 検知アプローチの分類（回避困難な痕跡の観点から）

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. レプリケーションGUID検知** | EventID 4662 + DS-Replication GUIDs | 最高（プロトコル上必須） | Sigma, Elastic, Splunk, Sentinel |
| **B. ツール実行検知** | Mimikatz lsadump::dcsync等のコマンドライン | 中（カスタムツールで回避可能） | Sigma, Elastic, Splunk, Sentinel |
| **C. ScriptBlock検知** | Invoke-DCSync / DSInternals等 | 高（ログ無効化以外回避困難） | Sigma, Splunk, Sentinel |
| **D. ネットワーク異常検知** | 非DCからのDRSUAPI通信 | 高（プロトコル使用は不可避） | Elastic, Splunk, Sentinel |
| **E. 権限委任検知** | レプリケーション権限のACL変更 | 最高（永続化の事前検知） | Sigma, Elastic, Splunk, Sentinel |

### なぜDCSyncの検知は高精度か

DCSync攻撃は以下の理由で検知が容易な攻撃手法の一つ:

1. **プロトコル上の制約**: DS-Replication-Get-Changes / Get-Changes-All のGUIDは、DCSync実行時に必ずActive Directoryのアクセス監査ログに記録される。攻撃者はこのGUIDの使用を回避できない。
2. **正当な使用元の限定性**: レプリケーション権限を正当に使用するのはDCマシンアカウントとAzure AD Connectのみ。ベースラインが明確で、異常検知が容易。
3. **多層検知が可能**: イベントログ（4662）、ネットワーク（DRSUAPI）、プロセス（ツール実行）の3層で独立した検知が可能。

---

## 3. 統合優先度

### Tier 1: 基礎ルール（全ソース合意・即時導入）
1. **EventID 4662 レプリケーションGUID検知** — 最も信頼性が高く、回避が最も困難
2. **DCSync ツール実行検知** — Mimikatz / impacket / DSInternalsのコマンドライン

### Tier 2: 高価値ルール（複数ソース合意・環境依存チューニング要）
3. **ScriptBlock Logging検知** — PowerShell経由のDCSync（EventID 4104必要）
4. **ネットワーク異常検知** — 非DCからのDRSUAPI通信（Sysmon EventID 3必要）
5. **権限委任検知** — レプリケーション権限のACL変更（EventID 5136必要）

---

## 4. ログ要件と導入前提

| EventID | ログソース | 必要な設定 | 対応ルール |
|---|---|---|---|
| 4662 | Windows Security | DS Accessの監査有効化（SACL設定） | tier1_dcsync_replication_rights |
| 4688 | Windows Security | プロセス作成の監査 + コマンドライン記録 | tier1_dcsync_tool_execution |
| 4104 | PowerShell | ScriptBlock Logging有効化 | tier2_dcsync_scriptblock |
| 3 (Sysmon) | Sysmon | NetworkConnect イベント有効化 | tier2_dcsync_network_drsuapi |
| 5136 | Windows Security | ディレクトリサービス変更の監査 | tier2_dcsync_permission_delegation |

### 重要: EventID 4662の有効化

DCSync検知の要であるEventID 4662は、デフォルトでは記録されない。以下の設定が必要:

1. **グループポリシー**: `Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > DS Access > Audit Directory Service Access` を「成功」に設定
2. **SACL設定**: Domain NCオブジェクトに対して適切なSACLを設定し、レプリケーション操作のアクセスを監査対象に含める

## 5. 統合ルールの設計方針

各統合Sigmaルールは以下の拡張メタデータを持つ:
- `x-source.*`: 元となったソースリポジトリ
- `x-evasion-resistance`: 回避困難度（medium / high）
- `x-log-requirement.*`: 必要なログソースとEventID
- `x-drs.*`: DRSフレームワークの次元との対応
