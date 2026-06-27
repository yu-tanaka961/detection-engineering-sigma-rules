# T1068 Exploitation for Privilege Escalation — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_hktl_privesc_tools.yml`, `sysmon_driver_load_vuln_driver.yml`
- **検知対象**: 既知の権限昇格ツール、脆弱ドライバロード
- **強み**: 既知ツール名/ハッシュの網羅的なシグネチャ

### 1.2 elastic/detection-rules
- **代表的なルール**: `privilege_escalation_exploit_tool.toml`, `privilege_escalation_vulnerable_driver_loaded.toml`
- **検知対象**: 権限昇格ツール実行、トークン昇格異常、脆弱ドライバ
- **強み**: トークン昇格タイプの異常検知、BYOVD検知

### 1.3 splunk/security_content
- **代表的なルール**: Known Privilege Escalation Exploit, Vulnerable Driver Loaded
- **検知対象**: 既知のエクスプロイトツール、脆弱ドライバ
- **強み**: LOLDriversプロジェクトとの連携

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Privilege Escalation via Token Manipulation, Suspicious Driver Load
- **検知対象**: トークン操作、不審なドライバロード
- **強み**: MDEによるカーネルレベルの異常検知

---

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. トークン昇格異常** | SYSTEM権限取得（4688 TokenElevationType） | 高（Security Event Logはカーネルが記録） | Elastic, Sigma, Splunk, Sentinel |
| **B. 既知ツール実行** | Potato系、PrintSpoofer、winPEAS等 | 中（ツール名変更/カスタムビルドで回避可能） | Sigma, Elastic, Splunk |
| **C. 脆弱ドライバロード（BYOVD）** | 既知の脆弱ドライバ（Sysmon 6） | 高（ドライバロードはカーネルイベント） | Elastic, Sigma, Splunk |

### 権限昇格エクスプロイトの主要カテゴリ

1. **Potato系エクスプロイト**: JuicyPotato, GodPotato, SweetPotato等。サービスアカウントからSYSTEMへの昇格。
2. **PrintSpoofer/SpoolSample**: Print Spoolerサービスの脆弱性を悪用。
3. **BYOVD (Bring Your Own Vulnerable Driver)**: 正規だが脆弱な署名済みドライバをロードしてカーネルアクセスを取得。
4. **カーネルエクスプロイト**: CVEベースのカーネル脆弱性攻撃。パッチ適用状況に依存。

## 3. 統合優先度

### Tier 1: 基礎ルール
1. トークン昇格異常検知（EventID 4688: SYSTEM権限のプロセスが不審パスから実行）
2. 既知権限昇格ツール実行（Potato系、PrintSpoofer、winPEAS等のシグネチャ）

### Tier 2: 高価値ルール
3. 脆弱ドライバロード検知（Sysmon 6: 既知の脆弱ドライバ + 不審パスからのドライバ）

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Security | 4688 | プロセス作成（TokenElevationType含む） | 必須 |
| Sysmon | 1 | プロセス作成（コマンドライン詳細） | 必須 |
| Sysmon | 6 | ドライバロード | 推奨 |
| Sysmon | 7 | イメージロード（DLLロード） | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1068](https://attack.mitre.org/techniques/T1068/)
- [LOLDrivers Project](https://www.loldrivers.io/)
- [Potato Exploits - jlajara](https://jlajara.gitlab.io/Potatoes_Windows_Privesc)
- [BYOVD Attacks - Elastic](https://www.elastic.co/security-labs/)
