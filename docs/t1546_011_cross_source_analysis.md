# T1546.011 Application Shimming — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_sdbinst_susp.yml`, `sysmon_registry_shim_database.yml`
- **検知対象**: sdbinst.exeによるシムDB登録、AppCompatFlagsレジストリ変更
- **強み**: sdbinstコマンドラインの詳細なパラメータ検知

### 1.2 elastic/detection-rules
- **代表的なルール**: `persistence_application_shimming.toml`, `persistence_sdb_file_creation.toml`
- **検知対象**: シムDBインストール、SDBファイル作成、レジストリ変更
- **強み**: SDBファイルのパス異常検知、レジストリ直接操作の検知

### 1.3 splunk/security_content
- **代表的なルール**: Application Shimming, Shim Database Installation
- **検知対象**: sdbinst実行、シムDBレジストリ変更
- **強み**: SDBファイルのハッシュ検証

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Shim Database Installation, Suspicious AppCompat Activity
- **検知対象**: シムDB関連の不審活動
- **強み**: MDEテレメトリによるシムDB活動の包括的可視化

---

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. sdbinst.exe実行** | sdbinstによるSDBファイルインストール | 中（レジストリ直接操作で回避可能） | Sigma, Elastic, Splunk, Sentinel |
| **B. AppCompatFlagsレジストリ変更** | InstalledSDB/Custom/Layersキー変更 | 高（レジストリ変更はカーネルが記録） | Elastic, Sigma, Splunk |
| **C. SDBファイル作成** | 不審パスへのSDBファイル書き込み | 高（ファイル作成イベントはOS レベルで記録） | Elastic, Sigma, Splunk |

### Application Shimmingの攻撃フロー

1. **SDBファイル作成**: カスタムシムDBファイル(.sdb)を作成。InjectDLL、RedirectEXE等のフィックスを含む。
2. **SDB登録**: sdbinst.exe または レジストリ直接操作でシムDBを登録。
3. **ターゲットアプリ実行時**: 登録されたシムが自動適用。DLLインジェクション、実行リダイレクト等が発生。
4. **永続化**: シムDB設定は再起動後も維持される。

## 3. 統合優先度

### Tier 1: 基礎ルール
1. sdbinst.exeによるSDBインストール検知
2. AppCompatFlagsレジストリ直接操作検知（sdbinst以外からの変更）

### Tier 2: 高価値ルール
3. 不審パスへのSDBファイル作成検知

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（sdbinstコマンドライン） | 必須 |
| Sysmon | 13 | レジストリ値変更（AppCompatFlags） | 必須 |
| Sysmon | 11 | ファイル作成（SDBファイル） | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1546.011](https://attack.mitre.org/techniques/T1546/011/)
- [FIN7 Shim Databases Persistence - Mandiant](https://www.mandiant.com/resources/blog/fin7-shim-databases-persistence)
- [Application Shimming - SANS](https://www.sans.org/blog/)
