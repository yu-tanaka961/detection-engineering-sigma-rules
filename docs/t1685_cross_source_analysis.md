# T1685 Disable or Modify Tools — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_disable_defender.yml`, `sysmon_registry_defender_disabled.yml`, `posh_ps_amsi_bypass.yml`
- **検知対象**: Defenderサービス停止、レジストリ改変、AMSIバイパス
- **強み**: セキュリティツール名の網羅的なリスト、AMSIバイパスパターンの詳細検知

### 1.2 elastic/detection-rules
- **代表的なルール**: `defense_evasion_disable_security_tools.toml`, `defense_evasion_defender_disabled_registry.toml`, `defense_evasion_etw_provider_disabled.toml`
- **検知対象**: セキュリティサービス無効化、Defenderレジストリ改変、ETWプロバイダ無効化
- **強み**: ETWプロバイダレベルの改ざん検知、レジストリベースのDefender設定変更の高精度検知

### 1.3 splunk/security_content
- **代表的なルール**: Disable Security Tools, Windows Defender Registry Modification, ETW Tampering
- **検知対象**: セキュリティツール無効化、Defender設定変更、ETW改ざん
- **強み**: 複数のセキュリティ製品（CrowdStrike、SentinelOne、Carbon Black等）の包括的カバー

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Security Service Disabled, Defender Policy Modification, ETW Provider Modification
- **検知対象**: セキュリティサービス停止、Defenderポリシー変更
- **強み**: MDE連携によるDefender Tamper Protection状態の監視

---

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. セキュリティサービス停止/無効化** | sc stop, net stop, taskkill, Set-Service | 中（API直接呼び出しで回避可能） | Sigma, Elastic, Splunk, Sentinel |
| **B. Defenderレジストリ改変** | DisableRealtimeMonitoring等のレジストリ値変更 | 高（レジストリ変更はカーネルが記録） | Elastic, Sigma, Splunk, Sentinel |
| **C. ETW/AMSI改ざん** | ETWプロバイダ無効化、AMSIバイパス、監査ポリシー変更 | 高（プロセス作成ログで記録） | Elastic, Sigma, Splunk, Sentinel |

### セキュリティツール無効化の主要手法

1. **サービス停止**: sc stop WinDefend / net stop Sense / taskkill /F /IM MsMpEng.exe
2. **レジストリ改変**: DisableRealtimeMonitoring=1、DisableAntiSpyware=1 等のDefenderポリシー変更
3. **Defender除外追加**: Exclusions\Pathsに攻撃ツールのパスを追加
4. **ETWプロバイダ無効化**: logman stop / COMPlus_ETWEnabled=0 でテレメトリ収集を停止
5. **AMSIバイパス**: amsiInitFailed=true設定、AmsiScanBufferのパッチによるスクリプト検査回避
6. **監査ポリシー変更**: auditpol /set で特定の監査カテゴリを無効化

## 3. 統合優先度

### Tier 1: 基礎ルール
1. セキュリティツールサービス停止/無効化（sc, net, taskkill, PowerShell）
2. Windows Defenderレジストリ設定改変（Sysmon 13）

### Tier 2: 高価値ルール
3. ETWプロバイダ/AMSI改ざん検知（高度な回避技術の検知）

## 4. ログ要件

| ログソース | EventID | 用途 | 必須/推奨 |
|---|---|---|---|
| Sysmon / Security | 1 / 4688 | プロセス作成（sc, net, taskkill等） | 必須 |
| Sysmon | 13 | レジストリ値変更（Defender設定） | 必須 |
| Windows Defender | 5001 | リアルタイム保護の無効化 | 推奨 |
| Windows Defender | 5007 | Defender構成変更 | 推奨 |

## 5. 参考資料
- [MITRE ATT&CK T1685](https://attack.mitre.org/techniques/T1685/)
- [MITRE ATT&CK T1562.001 (旧ID)](https://attack.mitre.org/techniques/T1562/001/)
- [ETW Tampering - MDSec](https://blog.xpnsec.com/hiding-your-dotnet-complus-etwenabled/)
- [AMSI Bypass Techniques](https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/)
