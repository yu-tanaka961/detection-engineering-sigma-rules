# T1204.002 User Execution: Malicious File — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_susp_execution_path.yml`, `proc_creation_win_susp_iso_mount.yml`
- **検知対象**: ユーザーディレクトリからの実行、ISO/VHDマウント実行
- **強み**: ファイルパスベースの網羅的パターン

### 1.2 elastic/detection-rules
- **代表的なルール**: `execution_from_unusual_directory.toml`, `defense_evasion_iso_mount_execution.toml`
- **検知対象**: 非標準ディレクトリ実行、コンテナファイルマウント
- **強み**: MOTW (Mark-of-the-Web) バイパス検知

### 1.3 splunk/security_content
- **代表的なルール**: Suspicious Process From User-Writable Dir, ISO Image Mount
- **検知対象**: ユーザー書き込み可能ディレクトリからの実行
- **強み**: Analytic Storyによるマルウェア配布チェーンの文脈付与

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Executable from Suspicious Directory, Virtual Disk Execution
- **検知対象**: 不審ディレクトリからの実行、仮想ディスク経由の実行

---

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. ユーザーディレクトリ実行** | Downloads/Desktop/Tempからの実行 | 中（正当な使用も多い） | Sigma, Elastic, Splunk, Sentinel |
| **B. コンテナマウント実行** | ISO/IMG/VHDからの実行 | 高（マウント操作はログに記録） | Sigma, Elastic, Splunk, Sentinel |
| **C. LNKファイル悪用** | 不審なターゲットを持つLNKの実行 | 中（LNKの内容は変更容易） | Sigma, Elastic, Splunk |

### マクロ後時代の攻撃手法シフト

Microsoft による Office マクロのデフォルトブロック（2022年）以降、攻撃者の主要配布手法は以下に移行:
1. **ISO/IMG/VHD** → MOTW バイパスによる実行制限回避
2. **LNK ファイル** → アイコン偽装による騙し実行
3. **OneNote 添付** → .one ファイル内の悪意あるスクリプト
4. **HTML Smuggling** → HTMLファイルからのペイロード展開

## 3. 統合優先度

### Tier 1: 基礎ルール
1. ユーザーディレクトリからの不審なプロセス実行
2. ISO/IMG/VHDマウント経由の実行検知

### Tier 2: 高価値ルール
3. 不審なターゲットを持つLNKファイルの実行
