# T1003.001 OS Credential Dumping: LSASS Memory — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `sysmon_cred_dump_lsass_access.yml`, `proc_creation_win_mimikatz.yml`, `sysmon_lsass_dump_file_creation.yml`
- **検知対象**: LSASSプロセスアクセス（Sysmon 10）、Mimikatz実行、ダンプファイル作成
- **強み**: GrantedAccessマスクの詳細なフィルタリング

### 1.2 elastic/detection-rules
- **代表的なルール**: `credential_access_lsass_memory_access.toml`, `credential_access_mimikatz.toml`, `credential_access_lsass_dump_file.toml`
- **検知対象**: LSASSメモリアクセス、クレデンシャルダンプツール、ダンプファイル
- **強み**: プロセスアクセス権限の多段フィルタリング、正規プロセスの包括的除外

### 1.3 splunk/security_content
- **代表的なルール**: LSASS Memory Access, Credential Dumping Tools, LSASS Dump File
- **検知対象**: LSASSアクセス、ツール実行、ファイル作成
- **強み**: comsvcs.dll MiniDump、createdump.exe等の代替ダンプ手法のカバー

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Credential Access via LSASS, LSASS Credential Dump
- **検知対象**: LSASSアクセス異常、クレデンシャルダンプ
- **強み**: MDE Credential Guard/LSASS PPL状態の監視

---

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. LSASSプロセスアクセス** | Sysmon 10: GrantedAccess 0x1010等 | 高（カーネルレベルのプロセスアクセス記録） | Sigma, Elastic, Splunk, Sentinel |
| **B. ダンプツール実行** | Mimikatz, ProcDump, comsvcs.dll MiniDump | 中（ツール名変更/カスタムビルドで回避可能） | Sigma, Elastic, Splunk, Sentinel |
| **C. ダンプファイル作成** | lsass.dmp等のファイル作成（Sysmon 11） | 高（ファイル作成はカーネルイベント） | Elastic, Sigma, Splunk |

### LSASS クレデンシャルダンプの主要手法

1. **Mimikatz sekurlsa::logonpasswords**: 最も一般的。LSASSメモリから直接クレデンシャルを抽出。
2. **ProcDump -ma lsass.exe**: Microsoft公式ツールを悪用したLSASSメモリダンプ。
3. **comsvcs.dll MiniDump**: rundll32経由でMiniDump関数を呼び出し。LOLBin手法。
4. **Task Manager**: GUIからLSASSプロセスのダンプファイルを作成。
5. **直接メモリアクセス**: カスタムツールによるOpenProcess + MiniDumpWriteDump API呼び出し。
6. **PPL バイパス**: LSASS Protected Process Light保護を回避する脆弱ドライバ経由のアクセス。

## 3. 統合優先度

### Tier 1: 基礎ルール
1. LSASSプロセスアクセス監視（Sysmon 10: 不審なGrantedAccess）
2. クレデンシャルダンプツール実行（Mimikatz, ProcDump, comsvcs.dll等）

### Tier 2: 高価値ルール
3. LSASSダンプファイル作成検知（Sysmon 11: .dmpファイル）

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon | 10 | プロセスアクセス（LSASS GrantedAccess） | 必須 |
| Sysmon / Security | 1 / 4688 | プロセス作成（ツール実行検知） | 必須 |
| Sysmon | 11 | ファイル作成（ダンプファイル） | 推奨 |
| Sysmon | 7 | イメージロード（DLLインジェクション検知） | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1003.001](https://attack.mitre.org/techniques/T1003/001/)
- [LSASS Protection - Microsoft](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [Credential Dumping - Red Canary](https://redcanary.com/threat-detection-report/techniques/lsass-memory/)
