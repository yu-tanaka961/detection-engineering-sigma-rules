# T1027 Obfuscated Files or Information — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_susp_encoded_content.yml`, `posh_ps_susp_obfuscation.yml`
- **検知対象**: エンコードコマンド、PowerShell難読化、二重拡張子
- **強み**: ScriptBlock Loggingによる難読化解除後の検知

### 1.2 elastic/detection-rules
- **代表的なルール**: `defense_evasion_obfuscated_content.toml`, `defense_evasion_double_extension.toml`
- **検知対象**: エンコードペイロード、二重拡張子、RTLO文字
- **強み**: 正規表現ベースの長大コマンドライン検知

### 1.3 splunk/security_content
- **代表的なルール**: Obfuscated Command Line, PowerShell Obfuscation
- **検知対象**: Base64エンコード、certutilエンコード、文字列操作
- **強み**: certutil悪用の包括的検知

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Encoded Command Detection, RTLO Character in Filename
- **検知対象**: エンコードコマンド、RTLO文字、難読化スクリプト
- **強み**: MDEテレメトリによるファイルレベルの難読化検知

---

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. エンコード/圧縮コンテンツ** | Base64, certutil encode, Gzip | 中（新たなエンコード手法で回避可能） | Sigma, Elastic, Splunk, Sentinel |
| **B. 二重拡張子/RTLO** | .pdf.exe, RTLO Unicode文字 | 高（ファイル名はOS レベルで記録） | Elastic, Sigma, Splunk, Sentinel |
| **C. ScriptBlock難読化指標** | 文字配列構築、動的呼び出し、tick難読化 | 高（ScriptBlock Loggingは難読化解除後を記録） | Sigma, Elastic, Splunk |

### 難読化の主要手法

1. **Base64エンコード**: -EncodedCommand、FromBase64String、certutil -encode
2. **文字列操作**: 文字配列構築、文字列反転、フォーマット演算子、環境変数連結
3. **圧縮**: GzipStream、DeflateStream、MemoryStream
4. **ファイル名偽装**: 二重拡張子（.pdf.exe）、RTLO Unicode文字、スペースパディング
5. **Tick難読化**: バッククォート挿入（`I`n`v`o`k`e-`E`x`p`r`e`s`s`i`o`n）

## 3. 統合優先度

### Tier 1: 基礎ルール
1. エンコード/圧縮コンテンツ検知（Base64, certutil, Gzip等）
2. 二重拡張子/RTLO検知（ファイル名ベースの偽装）

### Tier 2: 高価値ルール
3. ScriptBlock難読化指標（PowerShell 4104による難読化解除後の検知）

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（コマンドライン検知） | 必須 |
| PowerShell ScriptBlock | 4104 | ScriptBlock Logging（難読化解除後） | 必須 |

## 5. 参考資料
- [MITRE ATT&CK T1027](https://attack.mitre.org/techniques/T1027/)
- [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)
- [PowerShell Obfuscation Detection - FireEye](https://www.fireeye.com/blog/)
