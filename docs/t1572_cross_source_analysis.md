# T1572 Protocol Tunneling — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_ssh_tunnel.yml`, `proc_creation_win_chisel.yml`
- **検知対象**: SSH/plinkトンネル、chisel/ngrok実行
- **強み**: SSHポートフォワーディングフラグの詳細検知

### 1.2 elastic/detection-rules
- **代表的なルール**: `command_and_control_tunneling.toml`, `command_and_control_dns_tunnel.toml`
- **検知対象**: プロトコルトンネリング、DNSトンネル
- **強み**: トンネルツールの外部ネットワーク接続（Sysmon 3）検知

### 1.3 splunk/security_content
- **代表的なルール**: Protocol Tunneling, DNS Tunneling Detection
- **検知対象**: SSH/SOCKS/DNSトンネル、netshポートプロキシ
- **強み**: DNSトンネリングツール（iodine, dnscat2等）の検知

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Protocol Tunneling Detection
- **検知対象**: プロトコルトンネリング活動
- **強み**: ネットワークフローの統計的異常検知

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. SSH/トンネルツール** | ssh -L/-R, chisel, ngrok, plink | 中（ツール名変更で回避可能） | Sigma, Elastic, Splunk |
| **B. DNSトンネル** | iodine, dnscat2, dns2tcp | 中（カスタムツールで回避可能） | Sigma, Elastic, Splunk |
| **C. トンネルネットワーク接続** | 非標準ポートSSH、トンネルツールの外部接続 | 高（Sysmon NetworkConnectで検知） | Elastic, Splunk, Sentinel |

## 3. 統合優先度

### Tier 1: 基礎ルール
1. SSH/プロトコルトンネルツール実行
2. DNSトンネリングツール実行

### Tier 2: 高価値ルール
3. トンネルネットワーク接続異常

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（トンネルツール） | 必須 |
| Sysmon | 3 | ネットワーク接続（トンネル通信） | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1572](https://attack.mitre.org/techniques/T1572/)
- [Chisel](https://github.com/jpillora/chisel)
- [dnscat2](https://github.com/iagox86/dnscat2)
