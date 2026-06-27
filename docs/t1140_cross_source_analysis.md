# T1140 Deobfuscate/Decode Files or Information — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_certutil_decode.yml`, `posh_ps_decode_and_execute.yml`, `proc_creation_win_hh_chm_susp.yml`
- **検知対象**: certutilデコード、PowerShellデコード+実行、CHM/XSL処理
- **強み**: certutilパラメータの詳細な検知条件

### 1.2 elastic/detection-rules
- **代表的なルール**: `defense_evasion_certutil_decode.toml`, `defense_evasion_posh_decode_execute.toml`
- **検知対象**: certutilデコード、PowerShellデコード実行、XSLスクリプト処理
- **強み**: ScriptBlock Loggingによるデコード+実行パターンの高精度検知

### 1.3 splunk/security_content
- **代表的なルール**: Certutil Decode File, PowerShell Decode and Execute, XSL Script Processing
- **検知対象**: certutilデコード操作、PowerShellデコード、CHM/XSL悪用
- **強み**: 多段デコードチェーンの検知

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Certutil Suspicious Activity, PowerShell Encoded Execution
- **検知対象**: certutil悪用、PowerShellエンコード実行
- **強み**: MDEテレメトリによるファイルデコード活動の可視化

---

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. certutilデコード操作** | -decode, -decodehex, -urlcache | 中（PowerShell等で代替可能） | Sigma, Elastic, Splunk, Sentinel |
| **B. PowerShellデコード+実行** | FromBase64String + iex/Invoke-Expression | 高（ScriptBlock Loggingは難読化解除後を記録） | Elastic, Sigma, Splunk, Sentinel |
| **C. CHM/XSLスクリプト処理** | hh.exe, msxsl.exe, wmic /format: | 中（あまり一般的でないため目立つ） | Sigma, Elastic, Splunk |

### デコード/デオブファスケーションの主要手法

1. **certutil -decode**: Base64エンコードファイルのデコード。LOLBinとして広く悪用。
2. **PowerShell FromBase64String**: [Convert]::FromBase64String() + Invoke-Expressionの組み合わせ。
3. **GzipStream/DeflateStream**: 圧縮ペイロードの展開。Base64+Gzipの多段構成が一般的。
4. **CHM (Compiled HTML Help)**: hh.exeでCHMファイルを開き、埋め込みスクリプトを実行。
5. **XSL Processing**: wmic /format: や msxsl.exe でXSLファイル内のスクリプトを実行。

## 3. 統合優先度

### Tier 1: 基礎ルール
1. certutilデコード/エンコード操作の検知
2. PowerShellデコード+実行パターン（ScriptBlock Logging）

### Tier 2: 高価値ルール
3. CHM/XSLスクリプト処理（hh.exe不審実行、wmic XSL処理）

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（certutil/hh.exe/wmic） | 必須 |
| PowerShell ScriptBlock | 4104 | ScriptBlock Logging（デコード+実行検知） | 必須 |
| Sysmon | 11 | ファイル作成（デコード出力ファイル） | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1140](https://attack.mitre.org/techniques/T1140/)
- [LOLBAS Certutil](https://lolbas-project.github.io/lolbas/Binaries/Certutil/)
- [MITRE ATT&CK T1220 (XSL Script Processing)](https://attack.mitre.org/techniques/T1220/)
