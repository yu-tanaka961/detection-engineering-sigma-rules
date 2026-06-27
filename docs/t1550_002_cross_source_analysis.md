# T1550.002 Pass the Hash — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_mimikatz_pth.yml`, `win_security_pth_logon.yml`
- **検知対象**: Mimikatz sekurlsa::pth実行、NTLM認証異常
- **強み**: PtHツールのコマンドラインパターン検知

### 1.2 elastic/detection-rules
- **代表的なルール**: `lateral_movement_pass_the_hash.toml`, `credential_access_pth_logon.toml`
- **検知対象**: PtHツール、NTLM Type 3ログオン異常、Logon Type 9
- **強み**: Logon Type 9 (NewCredentials) による sekurlsa::pth 検知

### 1.3 splunk/security_content
- **代表的なルール**: Pass the Hash Attack, NTLM Logon Anomaly
- **検知対象**: PtHツール、Impacketハッシュ認証
- **強み**: Impacket -hashes パラメータの検知

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Pass the Hash Detection
- **検知対象**: NTLM認証異常パターン
- **強み**: ネットワークログオンの統計的異常分析

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. PtHツール実行** | Mimikatz, Impacket, Invoke-TheHash | 中（ツール名変更で回避可能） | Sigma, Elastic, Splunk |
| **B. NTLM認証異常** | Type 3 NTLM + ローカル管理者 | 高（認証イベントは回避困難） | Elastic, Sigma, Sentinel |
| **C. ログオンタイプ異常** | Type 9 (NewCredentials), 4648明示的資格情報 | 高（カーネルイベント） | Elastic, Splunk, Sentinel |

## 3. 統合優先度

### Tier 1: 基礎ルール
1. PtHツール実行検知
2. NTLM認証ログオン異常

### Tier 2: 高価値ルール
3. Logon Type 9 / 明示的資格情報異常

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（ツール実行） | 必須 |
| Windows Security Logon | 4624 | ログオンイベント（Type 3/9） | 必須 |
| Windows Security Logon | 4648 | 明示的資格情報使用 | 推奨 |
| Windows Security Kerberos | 4768 | TGT要求（Overpass-the-Hash） | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1550.002](https://attack.mitre.org/techniques/T1550/002/)
- [Pass-the-Hash Detection - JPCERT](https://jpcert.or.jp/english/pub/sr/ir_research.html)
