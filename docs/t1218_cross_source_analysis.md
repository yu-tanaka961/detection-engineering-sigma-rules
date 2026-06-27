# T1218 System Binary Proxy Execution — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_mshta_susp.yml`, `proc_creation_win_rundll32_susp.yml`, `proc_creation_win_cmstp.yml`
- **検知対象**: mshta, rundll32, regsvr32, cmstp, msiexec, installutil
- **強み**: LOLBin別の詳細なコマンドラインパターン検知

### 1.2 elastic/detection-rules
- **代表的なルール**: `defense_evasion_mshta.toml`, `defense_evasion_rundll32.toml`, `defense_evasion_lolbin_network.toml`
- **検知対象**: プロキシ実行、LOLBinネットワーク接続、不審なDLLロード
- **強み**: LOLBinからの外部ネットワーク接続検知（Sysmon 3）

### 1.3 splunk/security_content
- **代表的なルール**: Mshta Suspicious Execution, Rundll32 Proxy Execution, CMSTP UAC Bypass
- **検知対象**: 各LOLBinの不審実行パターン
- **強み**: UACバイパスとの相関検知

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Suspicious Proxy Execution, LOLBin Network Activity
- **検知対象**: LOLBinの不審実行、ネットワーク活動
- **強み**: MDEテレメトリによるLOLBin活動の包括的可視化

---

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. mshta/rundll32/regsvr32不審実行** | スクリプト実行、リモートコンテンツ、不審パスDLL | 中（新たなLOLBinが発見される可能性） | Sigma, Elastic, Splunk, Sentinel |
| **B. CMSTP/MSIExec/InstallUtilプロキシ実行** | INFファイル、リモートMSI、.NETアセンブリ | 中（ツール固有のパラメータで検知） | Sigma, Elastic, Splunk |
| **C. LOLBin外部ネットワーク接続** | LOLBinからの外部IPへの接続（Sysmon 3） | 高（ネットワーク接続はカーネルイベント） | Elastic, Sigma, Splunk |

### 主要なLOLBinとその悪用手法

1. **mshta.exe**: HTA/JavaScript/VBScript実行。`mshta javascript:...` でインラインスクリプト実行。
2. **rundll32.exe**: 任意のDLLエントリポイント呼び出し。`javascript:` プロトコルハンドラも悪用可能。
3. **regsvr32.exe**: Squiblydoo攻撃（/s /n /u /i:URL scrobj.dll）でリモートSCT実行。
4. **cmstp.exe**: INFファイル経由のUACバイパスとコマンド実行。
5. **msiexec.exe**: リモートMSIパッケージの静かなインストール、DLL実行。
6. **InstallUtil.exe**: .NETアセンブリのロードによるアプリケーションホワイトリスト回避。

## 3. 統合優先度

### Tier 1: 基礎ルール
1. mshta/rundll32/regsvr32の不審実行パターン検知
2. CMSTP/MSIExec/InstallUtilのプロキシ実行検知

### Tier 2: 高価値ルール
3. LOLBinからの外部ネットワーク接続検知（Sysmon 3）

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（コマンドライン検知） | 必須 |
| Sysmon | 3 | ネットワーク接続（LOLBin外部通信） | 推奨 |
| Sysmon | 7 | イメージロード（DLLロード監視） | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1218](https://attack.mitre.org/techniques/T1218/)
- [LOLBAS Project](https://lolbas-project.github.io/)
- [Squiblydoo Attack - Red Canary](https://redcanary.com/threat-detection-report/)
