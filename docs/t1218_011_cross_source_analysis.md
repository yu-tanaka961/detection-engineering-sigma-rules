# T1218.011 Rundll32 — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_rundll32_susp_activity.yml`, `proc_creation_win_rundll32_susp_dll_path.yml`
- **検知対象**: 不審コマンドパターン、不審パスDLLロード、プロキシ関数呼び出し
- **強み**: shell32/url.dll等のプロキシ関数の網羅的検知

### 1.2 elastic/detection-rules
- **代表的なルール**: `defense_evasion_rundll32_suspicious.toml`, `defense_evasion_rundll32_abnormal_parent.toml`
- **検知対象**: 不審実行、異常な親プロセス、ネットワーク接続
- **強み**: 親子プロセス関係の異常検知、外部通信検知

### 1.3 splunk/security_content
- **代表的なルール**: Rundll32 Suspicious Execution, Rundll32 Unusual DLL Path
- **検知対象**: 不審コマンド、不審パスDLL、子プロセス生成
- **強み**: rundll32からの偵察コマンド実行チェーン検知

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Rundll32 Abuse Detection, Rundll32 Network Activity
- **検知対象**: rundll32不審活動、ネットワーク通信
- **強み**: MDEテレメトリによる包括的なrundll32活動可視化

---

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. 不審コマンドパターン** | javascript:, リモートDLL, プロキシ関数 | 中（新たなプロキシ手法で回避可能） | Sigma, Elastic, Splunk, Sentinel |
| **B. 不審パスDLLロード** | Temp/AppData/Downloads等からのDLL読み込み | 高（プロセス作成はカーネルイベント） | Elastic, Sigma, Splunk |
| **C. 異常な親プロセス/子プロセス** | Office→rundll32、rundll32→cmd等 | 高（親子関係はカーネルが記録） | Elastic, Sigma, Splunk |

### Rundll32悪用の主要パターン

1. **プロキシ実行**: shell32.dll,ShellExec_RunDLL / url.dll,FileProtocolHandler 等で任意コマンド実行
2. **リモートDLLロード**: UNCパスやHTTP経由で外部DLLを直接ロード
3. **DLLサイドローディング**: 不審パスからのDLLロード（マルウェアドロッパー）
4. **プロセスインジェクション**: 引数なしrundll32起動→プロセスインジェクション先として利用
5. **JavaScript実行**: `rundll32 javascript:"\..\mshtml..."` パターン

## 3. 統合優先度

### Tier 1: 基礎ルール
1. 不審コマンドパターン（プロトコルハンドラ、リモートDLL、プロキシ関数）
2. 不審パスからのDLLロード

### Tier 2: 高価値ルール
3. 異常な親プロセス/子プロセス関係

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（コマンドライン検知） | 必須 |
| Sysmon | 3 | ネットワーク接続（外部通信検知） | 推奨 |
| Sysmon | 7 | イメージロード（DLLロード監視） | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1218.011](https://attack.mitre.org/techniques/T1218/011/)
- [LOLBAS Rundll32](https://lolbas-project.github.io/lolbas/Binaries/Rundll32/)
- [Rundll32 Detection - Red Canary](https://redcanary.com/threat-detection-report/techniques/rundll32/)
