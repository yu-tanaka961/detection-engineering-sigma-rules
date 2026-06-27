# T1003.003 OS Credential Dumping: NTDS — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_ntdsutil.yml`, `proc_creation_win_ntds_access.yml`
- **検知対象**: ntdsutil IFM、NTDS.ditファイルアクセス
- **強み**: ntdsutilコマンドパターンの詳細検知

### 1.2 elastic/detection-rules
- **代表的なルール**: `credential_access_ntds_dump.toml`, `credential_access_ntds_dump_file_creation.toml`
- **検知対象**: NTDS.ditダンプ、ファイル作成、Shadow Copy
- **強み**: diskshadow/esentutl等の代替手法の包括的カバー

### 1.3 splunk/security_content
- **代表的なルール**: NTDS Credential Dump, NTDS File Access
- **検知対象**: ntdsutil、secretsdump、NTDS.ditファイル操作
- **強み**: Impacket secretsdumpのリモートダンプ検知

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: NTDS.dit Access
- **検知対象**: NTDS.ditファイルアクセス、IFM作成
- **強み**: DC上でのNTDS活動の包括的監視

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. ntdsutil IFM/ダンプ** | ntdsutil "activate instance ntds" create full | 中（他ツールで代替可能） | Sigma, Elastic, Splunk, Sentinel |
| **B. NTDS.ditファイルアクセス** | esentutl、copy、robocopy、secretsdump | 中（多様な手法が存在） | Elastic, Sigma, Splunk |
| **C. NTDS.ditファイル作成** | 通常パス外へのntds.ditコピー（Sysmon 11） | 高（ファイル作成はカーネルイベント） | Elastic, Sigma, Splunk |

## 3. 統合優先度

### Tier 1: 基礎ルール
1. ntdsutil IFM / Shadow Copy作成
2. NTDS.ditファイルアクセス/コピー

### Tier 2: 高価値ルール
3. NTDS.ditファイルの不審な場所への作成

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（ntdsutil、esentutl等） | 必須 |
| Sysmon | 11 | ファイル作成（NTDS.ditコピー） | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1003.003](https://attack.mitre.org/techniques/T1003/003/)
- [NTDS Credential Dumping - ADSecurity](https://adsecurity.org/?p=2398)
