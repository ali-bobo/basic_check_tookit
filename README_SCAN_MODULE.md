簡短說明：如何使用 `scan_commands.json` 的示範載入模組

檔案位置（相對 workspace）：
- `reports/scan_commands.json`  (已提供)

Python 範例（dry-run 列出）：

```bash
python tools/load_scan_commands.py --list --platform linux
```

列出某指令並 dry-run：

```bash
python tools/load_scan_commands.py --id linux_free
```

實際執行（注意：會執行系統命令，請自行確認權限與風險）：

```bash
python tools/load_scan_commands.py --id linux_free --execute
```

PowerShell 範例：

```powershell
# 於 tools 資料夾執行或用完整路徑載入模組
. .\tools\ScanCommands.ps1
Get-ScanCommands -Platform linux
Get-ScanCommandById -Id linux_free
Invoke-ScanCommand -Id linux_free -WhatIf   # dry-run
```

注意事項：
- 兩套範例預設為 dry-run（不會執行命令），除非明確傳入 `--execute`（Python）或在 PowerShell 使用 `-Confirm:$false` 與不加 `-WhatIf`。
- 嚴格遵守「不得使用提權指令」的原則；若命令被標示 `requires_admin=true`，模組會拒絕執行並提示。
- 若要整合到掃描程式，請把 JSON 路徑作為參數傳入，並在執行前通知使用者可能的風險與權限需求。
