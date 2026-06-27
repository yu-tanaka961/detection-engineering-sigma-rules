# T1566.001 Spearphishing Attachment — Cross-Source Detection Analysis

## 1. ソース別検知アプローチ比較

### 1.1 SigmaHQ/sigma
- **代表的なルール**: `proc_creation_win_office_shell.yml`, `image_load_office_vbadll.yml`, `file_event_win_office_temp_file.yml`
- **検知対象**: Office→シェル生成、VBAエンジンロード、不審ファイル書き込み
- **強み**: プロセスツリー、イメージロード、ファイルイベントの3層検知

### 1.2 elastic/detection-rules
- **代表的なルール**: `initial_access_suspicious_ms_office_child_process.toml`, `execution_office_macro_indicator.toml`
- **検知対象**: Office子プロセス異常、マクロ実行インジケータ
- **強み**: EQLによる複合条件、behavior detectionとの統合

### 1.3 splunk/security_content
- **代表的なルール**: Office Application Spawn Suspicious Process, Office Document Dropped Executable
- **検知対象**: Office→不審プロセス、ドキュメントからの実行ファイルドロップ
- **強み**: Analytic Storyによるフィッシング攻撃チェーン全体の可視化

### 1.4 Azure/Azure-Sentinel
- **代表的なルール**: Office Application Spawning Suspicious Process, Suspicious File Write
- **検知対象**: Office子プロセス、メールクライアントからの不審ファイル書き込み
- **強み**: OfficeActivityログとの統合、MDOアラートとの相関

---

## 2. 検知アプローチの分類

| 検知カテゴリ | 検知対象 | 回避難易度 | ソースカバレッジ |
|---|---|---|---|
| **A. Office子プロセス異常** | Office→cmd/powershell/LOLBin | 高（親プロセス偽装困難） | Sigma, Elastic, Splunk, Sentinel |
| **B. マクロ実行検知** | VBE7.DLLロード + 不審DLL | 高（VBAエンジンロードは必須） | Sigma, Elastic, Splunk |
| **C. ペイロードファイル書き込み** | Office→exe/script/lnkファイル作成 | 高（ファイルI/Oは回避困難） | Sigma, Elastic, Splunk, Sentinel |

### フィッシング攻撃の検知チェーン

```
メール受信 → 添付ファイル開封 → マクロ実行(B) → ペイロード書き込み(C) → 子プロセス生成(A)
```

各フェーズで独立した検知が可能であり、多層防御として非常に有効。

---

## 3. 統合優先度

### Tier 1: 基礎ルール
1. Office→不審子プロセス生成（親子関係ベース）
2. Office VBAエンジン＋不審DLLロード

### Tier 2: 高価値ルール
3. Office/メールクライアントからの不審ファイル書き込み

## 4. 注意事項

Microsoft による Office マクロのデフォルトブロック（2022年〜）以降、攻撃者は以下の代替手法に移行している:
- ISO/IMG/VHDファイルによるMark-of-the-Web回避
- OneNote添付ファイル（.one）によるペイロード配布
- Windows Shortcut (.lnk) ファイルの悪用

これらの新手法に対応するため、`selection_extension_other` で ISO/IMG/VHD/LNK ファイルの書き込みも検知対象に含めている。
