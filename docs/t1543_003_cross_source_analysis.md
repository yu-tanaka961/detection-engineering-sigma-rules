# T1543.003 Windows Service Persistence — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `sysmon_registry_susp_service_modification.yml`, `win_system_susp_service_installed.yml`
- **検知対象**: サービスレジストリ改変、不審サービスインストール
- **強み**: Sysmon 13（レジストリ値変更）の詳細なパス検知

### 1.2 elastic/detection-rules
- **代表的なルール**: `persistence_service_registry_modification.toml`, `persistence_service_dll_hijack.toml`
- **検知対象**: サービスレジストリ改変、サービスDLLハイジャック、svchost異常DLLロード
- **強み**: サービスDLLハイジャックの専用検知ロジック

### 1.3 splunk/security_content
- **代表的なルール**: Suspicious Service Registry Modification, New Service Created in Suspicious Location
- **検知対象**: レジストリ経由のサービス改変、不審パスのサービスバイナリ
- **強み**: サービスバイナリのパス異常に対する網羅的な条件

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Service Registry Modification, Suspicious Windows Service Installation
- **検知対象**: サービス関連レジストリ変更、MDEテレメトリベースのサービス検知
- **強み**: MDE連携による包括的なサービス活動の可視化

---

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. サービスレジストリ改変** | ImagePath/ServiceDll変更（Sysmon 13） | 高（レジストリ変更はカーネルが記録） | Sigma, Elastic, Splunk, Sentinel |
| **B. 不審パスのサービスインストール** | EventID 7045（Temp/AppData/UNCパス） | 高（System Event Logは攻撃者が消去しにくい） | Sigma, Elastic, Splunk, Sentinel |
| **C. サービスDLLハイジャック** | svchost.exeの非標準パスDLLロード | 高（DLLロードはカーネルイベント） | Elastic, Sigma |

### サービス永続化の主要手法

1. **新規サービス作成**: sc create / New-Service → EventID 7045で記録
2. **既存サービスの改変**: レジストリ直接編集でImagePath/ServiceDllを変更 → Sysmon 13で記録
3. **サービスDLLハイジャック**: svchost -k に読み込まれるDLLを差し替え → Sysmon 7で記録

## 3. 統合優先度

### Tier 1: 基礎ルール
1. サービスレジストリ改変検知（Sysmon 13: ImagePath/ServiceDll変更）
2. 不審パスからのサービスインストール（EventID 7045）

### Tier 2: 高価値ルール
3. サービスDLLハイジャック（svchost.exeの非標準DLLロード）

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon | 13 | レジストリ値変更 | 必須 |
| System | 7045 | 新規サービスインストール | 必須 |
| Sysmon | 7 | DLLロード（ImageLoad） | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1543.003](https://attack.mitre.org/techniques/T1543/003/)
- [Windows Service Persistence - Red Canary](https://redcanary.com/threat-detection-report/)
- [Sysmon Configuration for Service Monitoring](https://github.com/SwiftOnSecurity/sysmon-config)
