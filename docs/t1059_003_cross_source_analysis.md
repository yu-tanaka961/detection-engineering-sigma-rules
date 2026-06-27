# T1059.003 Windows Command Shell — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_cmd_suspicious_execution.yml`, `proc_creation_win_cmd_obfuscation.yml`
- **検知対象**: 不審なcmd.exeコマンドチェーン、DOSfuscation難読化
- **強み**: コマンドライン文字列パターンの網羅的カバレッジ

### 1.2 elastic/detection-rules
- **代表的なルール**: `execution_suspicious_cmd_line.toml`, `defense_evasion_cmd_obfuscation.toml`
- **検知対象**: 不審なcmd実行パターン、難読化、親プロセス異常
- **強み**: EQLによる親子プロセス関係の精密な分析

### 1.3 splunk/security_content
- **代表的なルール**: Suspicious Cmd.exe Execution, CMD Obfuscation Techniques
- **検知対象**: コマンドチェーン、環境変数悪用、出力リダイレクト
- **強み**: CIMによる正規化、偵察コマンドの包括リスト

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Suspicious Command Shell Activity
- **検知対象**: cmd.exeの不審な使用パターン
- **強み**: MDE (Microsoft Defender for Endpoint) テレメトリとの統合

---

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. 不審コマンドパターン** | 偵察コマンドチェーン、出力リダイレクト | 中（別ツールで代替可能） | Sigma, Elastic, Splunk, Sentinel |
| **B. 親プロセス異常** | Office/Web/Script→cmd.exe | 高（親プロセス偽装困難） | Sigma, Elastic, Splunk, Sentinel |
| **C. DOSfuscation/難読化** | キャレット挿入、環境変数悪用 | 中（新しい難読化手法で回避） | Sigma, Elastic, Splunk |

## 3. 統合優先度

### Tier 1: 基礎ルール
1. 不審なcmd.exeコマンドパターン（偵察チェーン、リダイレクト）
2. 不審な親プロセスからのcmd.exe起動

### Tier 2: 高価値ルール
3. DOSfuscation / コマンドライン難読化
