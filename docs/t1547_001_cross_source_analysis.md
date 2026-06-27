# T1547.001 Registry Run Keys / Startup Folder — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `sysmon_registry_run_key_modification.yml`, `sysmon_file_creation_startup_folder.yml`
- **検知対象**: Run/RunOnceキー変更、Startupフォルダへのファイル作成
- **強み**: Sysmon 13による詳細なレジストリパス検知、値の内容検査

### 1.2 elastic/detection-rules
- **代表的なルール**: `persistence_registry_run_key.toml`, `persistence_startup_folder_file_creation.toml`
- **検知対象**: Runキー変更、Startupフォルダ、不審プロセスによるRunキー変更
- **強み**: 変更プロセスの信頼性評価（scripting engine/LOLBins検知）

### 1.3 splunk/security_content
- **代表的なルール**: Registry Run Key Modification, Startup Folder Persistence
- **検知対象**: Runキーの追加/変更、Startupフォルダへのファイルドロップ
- **強み**: レジストリ値の詳細なパターンマッチング（cmdline, script等）

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Autorun Registry Key Modification, Startup Folder File Creation
- **検知対象**: 自動起動レジストリキー、Startupフォルダ変更
- **強み**: MDEテレメトリによるプロセスとレジストリの相関分析

---

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. Runキーレジストリ変更** | Run/RunOnceへの値追加・変更（Sysmon 13） | 高（レジストリ変更はカーネルが記録） | Sigma, Elastic, Splunk, Sentinel |
| **B. Startupフォルダファイル作成** | Startup/スタートアップフォルダへのファイル書き込み（Sysmon 11） | 高（ファイル作成イベントはOS レベルで記録） | Sigma, Elastic, Splunk, Sentinel |
| **C. 不審プロセスによるRunキー変更** | scripting engine/LOLBinからのRunキー操作 | 高（プロセス×レジストリの相関） | Elastic, Sigma |

### 自動起動の主要レジストリパス

1. **HKCU/HKLM\Software\Microsoft\Windows\CurrentVersion\Run** — 最も一般的な永続化パス
2. **HKCU/HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce** — 一度だけ実行
3. **HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices** — レガシー互換
4. **shell:startup / shell:common startup** — Startupフォルダ（Explorer経由で実行）

## 3. 統合優先度

### Tier 1: 基礎ルール
1. Run/RunOnceキーへの不審値追加（Sysmon 13: 不審な値パターン検知）
2. Startupフォルダへのファイル作成（Sysmon 11: 不審な拡張子）

### Tier 2: 高価値ルール
3. 不審プロセスによるRunキー変更（scripting engine/LOLBins/Tempパスからの変更）

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon | 13 | レジストリ値変更（RegistryEvent - Value Set） | 必須 |
| Sysmon | 11 | ファイル作成 | 必須 |
| Sysmon | 1 | プロセス作成（変更元プロセスの特定） | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1547.001](https://attack.mitre.org/techniques/T1547/001/)
- [Autoruns - Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)
- [Persistence via Registry Run Keys - SANS](https://www.sans.org/blog/)
