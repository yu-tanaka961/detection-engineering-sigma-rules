# T1090 Proxy — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_netsh_portproxy.yml`, `proc_creation_win_proxy_tools.yml`
- **検知対象**: netshポートプロキシ、プロキシツール実行
- **強み**: netsh interface portproxyの詳細パラメータ検知

### 1.2 elastic/detection-rules
- **代表的なルール**: `command_and_control_proxy.toml`, `persistence_webshell_proxy.toml`
- **検知対象**: プロキシツール、Webシェルプロキシ
- **強み**: reGeorg/NeoReGeorg Webシェルプロキシの検知

### 1.3 splunk/security_content
- **代表的なルール**: Proxy Tool Execution, Multi-Hop Proxy
- **検知対象**: プロキシツール、Tor、マルチホッププロキシ
- **強み**: Torブラウザ/リレーの検知

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Proxy Configuration Activity
- **検知対象**: プロキシ設定活動
- **強み**: ネットワークフローの多段プロキシ検知

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. プロキシツール実行** | netsh portproxy, SOCKS, frpc | 中（代替ツールで回避可能） | Sigma, Elastic, Splunk |
| **B. Webシェルプロキシ** | reGeorg, NeoReGeorg, ABPTTS | 中（カスタムWebシェルで回避可能） | Sigma, Elastic, Splunk |
| **C. マルチホッププロキシ** | Tor, proxychains, meek | 高（Torプロセスの実行は検知容易） | Elastic, Splunk, Sentinel |

## 3. 統合優先度

### Tier 1: 基礎ルール
1. プロキシ/SOCKSツール実行
2. Webシェルプロキシファイル作成

### Tier 2: 高価値ルール
3. マルチホッププロキシ/Tor使用

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（プロキシツール） | 必須 |
| Sysmon | 11 | ファイル作成（Webシェルプロキシ） | 推奨 |
| Sysmon | 3 | ネットワーク接続（プロキシ通信） | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1090](https://attack.mitre.org/techniques/T1090/)
- [reGeorg](https://github.com/sensepost/reGeorg)
- [Neo-reGeorg](https://github.com/L-codes/Neo-reGeorg)
