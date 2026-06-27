# T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_responder.yml`, `sysmon_registry_llmnr_nbtns.yml`
- **検知対象**: Responder/Inveighツール実行、LLMNR/NBT-NS設定変更
- **強み**: ポイズニングツールのコマンドラインパターン検知

### 1.2 elastic/detection-rules
- **代表的なルール**: `credential_access_llmnr_poisoning.toml`, `credential_access_ntlm_relay.toml`
- **検知対象**: ポイズニングツール、LLMNR/NBT-NS設定変更、NTLMリレー
- **強み**: LLMNR/NBT-NSレジストリ変更の高精度検知

### 1.3 splunk/security_content
- **代表的なルール**: LLMNR/NBT-NS Poisoning, NTLM Relay Detection
- **検知対象**: ポイズニング、NTLMリレー、認証強制
- **強み**: PetitPotam/PrinterBug等の認証強制ツール検知

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Name Resolution Poisoning
- **検知対象**: 名前解決ポイズニング活動
- **強み**: ネットワークレベルの異常検知

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. ポイズニングツール実行** | Responder, Inveigh, Pretender | 中（ツール名変更で回避可能） | Sigma, Elastic, Splunk, Sentinel |
| **B. LLMNR/NBT-NS設定変更** | EnableMulticast/NetbiosOptionsレジストリ | 高（レジストリ変更はカーネルが記録） | Elastic, Sigma, Splunk |
| **C. NTLMリレー/認証強制** | ntlmrelayx, PetitPotam, Coercer | 中（多様なツールが存在） | Elastic, Sigma, Splunk |

## 3. 統合優先度

### Tier 1: 基礎ルール
1. ポイズニングツール実行検知
2. LLMNR/NBT-NS設定変更

### Tier 2: 高価値ルール
3. NTLMリレー/認証強制ツール

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（ツール実行） | 必須 |
| Sysmon | 13 | レジストリ変更（LLMNR/NBT-NS設定） | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1557.001](https://attack.mitre.org/techniques/T1557/001/)
- [Responder](https://github.com/lgandx/Responder)
- [Inveigh](https://github.com/Kevin-Robertson/Inveigh)
