# T1558.003 Steal or Forge Kerberos Tickets: Kerberoasting — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `win_security_kerberoasting.yml`, `proc_creation_win_kerberoast_tools.yml`
- **検知対象**: RC4暗号化TGSリクエスト（EventID 4769）、Kerberoastingツール実行
- **強み**: EventID 4769の暗号化タイプフィルタリング

### 1.2 elastic/detection-rules
- **代表的なルール**: `credential_access_kerberoasting.toml`, `credential_access_kerberos_downgrade.toml`
- **検知対象**: Kerberoasting、RC4ダウングレード、ツール実行
- **強み**: 暗号化ダウングレード攻撃の行動検知

### 1.3 splunk/security_content
- **代表的なルール**: Kerberoasting TGS Request, Kerberos RC4 Downgrade
- **検知対象**: TGSリクエスト異常、RC4ダウングレード
- **強み**: 複数TGSリクエストの時間相関分析

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Kerberoasting Detection, SPN Enumeration
- **検知対象**: Kerberoasting活動、SPN列挙
- **強み**: Azure ADとオンプレミスADの相関分析

---

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. TGSリクエスト異常** | EventID 4769: RC4暗号化（0x17）のTGS要求 | 高（Kerberos認証はDCが記録） | Sigma, Elastic, Splunk, Sentinel |
| **B. Kerberoastingツール実行** | Rubeus, Invoke-Kerberoast, GetUserSPNs | 中（ツール名変更で回避可能） | Sigma, Elastic, Splunk, Sentinel |
| **C. RC4暗号化ダウングレード** | AES対応環境でのRC4 TGSリクエスト | 高（DC側で記録、回避困難） | Elastic, Sigma, Splunk |

### Kerberoasting攻撃フロー

1. **SPN列挙**: setspn -Q */* / Get-ADUser -Filter {ServicePrincipalName -ne "$null"} でSPN付きアカウントを列挙
2. **TGSリクエスト**: 対象SPNに対してRC4暗号化のTGSチケットを要求
3. **チケット抽出**: メモリ上のTGSチケットをエクスポート
4. **オフラインクラック**: HashcatやJohn the Ripperでサービスアカウントのパスワードをクラック
5. **アカウント悪用**: クラックしたサービスアカウントで権限昇格や横展開

### 検知のポイント

- **RC4 vs AES**: AES対応環境でRC4のTGSリクエストは異常。ただしレガシー環境ではRC4が正常な場合がある。
- **量的異常**: 短時間に複数の異なるSPNへのTGSリクエストはKerberoastingの強い指標。
- **ツールシグネチャ**: Rubeus/Invoke-Kerberoastのコマンドラインパターンは比較的検知しやすい。

## 3. 統合優先度

### Tier 1: 基礎ルール
1. RC4暗号化TGSリクエスト検知（EventID 4769: EncryptionType 0x17）
2. Kerberoastingツール実行検知（Rubeus, Invoke-Kerberoast等）

### Tier 2: 高価値ルール
3. Kerberos暗号化ダウングレード検知（AES環境でのRC4使用）

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Security | 4769 | Kerberos TGSリクエスト | 必須 |
| Sysmon / Security | 1 / 4688 | プロセス作成（ツール実行検知） | 必須 |
| Security | 4768 | Kerberos TGTリクエスト | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1558.003](https://attack.mitre.org/techniques/T1558/003/)
- [Kerberoasting - harmj0y](https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/)
- [Detecting Kerberoasting - ADSecurity](https://adsecurity.org/?p=3458)
