# SysKit Scanner v2.0.0

> **系統健檢掃描工具 — 非管理員 / 非 root 安全掃描**

跨平台 (Windows / Rocky Linux / Ubuntu) 的系統健檢掃描器，  
所有指令皆為**唯讀 (read-only)**，**絕不使用管理員或 root 權限**。

---

## 功能特色

| 特色 | 說明 |
|------|------|
| 🔒 零權限 | 禁止以 root / Administrator 身分執行；所有指令為非特權唯讀 |
| 📊 CIS-like 基準 | 10 項安全檢查 (PASS / FAIL / SKIPPED)，含計分百分比 |
| 🌐 跨平台 | Windows (PowerShell)、Rocky/CentOS (Bash)、Ubuntu/Debian (Bash) |
| 📝 雙格式報告 | TXT (繁體中文摘要表頭) + JSON (機器可讀) |
| ⚙️ 可設定閾值 | `config/thresholds.conf` 控制記憶體、磁碟、危險埠等門檻 |
| 🔍 取證建議 | 報告末尾附帶管理員專屬取證指令參考 (不自動執行) |
| 🛡️ 敏感資料遮蔽 | 自動遮蔽 password=、token= 等敏感字串 |
| ⏱️ 指令逾時 | 每個指令預設 10 秒逾時，避免掃描卡住 |

---

## 專案結構

```
basic_check_tookit/
├── launcher.py              # Python 跨平台選單啟動器
├── scan_rocky.sh            # Rocky / CentOS / RHEL 掃描腳本
├── scan_ubuntu.sh           # Ubuntu / Debian 掃描腳本
├── scan.ps1                 # Windows PowerShell 掃描腳本
├── README.md                # 本文件
├── config/
│   └── thresholds.conf      # 閾值設定檔 (KEY=VALUE)
├── reports/                 # 報告輸出目錄
│   ├── syskit_report_*.txt  # TXT 報告 (自動生成)
│   ├── syskit_report_*.json # JSON 報告 (自動生成)
│   ├── sample_report_v2.txt # 範例 TXT 報告
│   ├── sample_report.json   # 範例 JSON 報告
│   ├── scan_commands.json   # 非管理員指令清冊 (JSON)
│   └── scan_commands.csv    # 非管理員指令清冊 (CSV)
├── tools/
│   ├── load_scan_commands.py # Python 指令清冊載入器
│   ├── ScanCommands.ps1     # PowerShell 指令清冊模組
│   └── README_SCAN_MODULE.md
└── .gitkeep
```

---

## 快速開始

### 方式 1：使用 Python 啟動器 (推薦)

```bash
# Linux / macOS
python3 launcher.py

# Windows (PowerShell)
python launcher.py
```

啟動器會自動偵測作業系統並執行對應腳本，也可手動選擇。

### 方式 2：直接執行腳本

```bash
# Rocky / CentOS / RHEL
bash scan_rocky.sh

# Ubuntu / Debian
bash scan_ubuntu.sh
```

```powershell
# Windows (PowerShell 5.1+)
powershell -ExecutionPolicy Bypass -File scan.ps1
```

> ⚠️ **注意：** 請以一般使用者身分執行。腳本偵測到 root/admin 會拒絕執行。

---

## 報告說明

### TXT 報告

報告開頭包含**繁體中文摘要表頭**：

```
================================================================================
  SysKit Scanner v2.0.0  |  系統健檢摘要表
================================================================================
  [狀態] 🟢 正常
  [主機] my-server (Rocky Linux 9.3)
  [負載] LA: 0.15 / 0.20 / 0.18 | Processes: 185
  ...
  ▶ CIS-like 安全基準 (Security Benchmark)
    - 通過: 8 / 未通過: 1 / 跳過: 1 — 分數: 8/10
================================================================================
```

後面接詳細掃描的每個 Section 原始輸出。

### JSON 報告

JSON 報告包含所有結構化資料，可供後續自動化分析：

```json
{
  "host": "my-server",
  "os": "Rocky Linux 9.3",
  "scanner_version": "2.0.0",
  "overall_status": "🟢 正常",
  "cis_score": { "passed": 8, "failed": 1, "skipped": 1, "total": 10 },
  "cis_checks": [ ... ],
  "critical_findings": [],
  "warn_findings": [ ... ]
}
```

---

## CIS-like 安全基準 (10 項)

所有檢查皆使用非特權指令，無需 root / admin：

| # | 檢查項目 | Linux | Windows |
|---|----------|-------|---------|
| 1 | SSH / RDP 監聽 | `ss -tlnp` 檢查 :22 | `Get-NetTCPConnection` 檢查 :3389 |
| 2 | 危險埠開放 | 比對 DANGEROUS_PORTS | 同左 |
| 3 | 記憶體使用 | `free -m` 剩餘 MiB | `Win32_OperatingSystem` FreePhysicalMemory |
| 4 | Swap / 磁碟使用 | `df -h` 檢查 / | `Get-PSDrive C` 使用率 |
| 5 | SELinux / Defender | `getenforce` | `Get-MpComputerStatus` |
| 6 | 關鍵檔案權限 | `/etc/passwd` 權限 | 防火牆設定檔狀態 |
| 7 | Home 目錄權限 | `stat $HOME` | 自動啟動服務數量 |
| 8 | 使用者 crontab | `crontab -l` | 啟動項目數量 |
| 9 | SUID/SGID 文件 | `find $HOME` | Guest 帳戶狀態 |
| 10 | 程序數量 | `ps aux` 行數 | `Get-Process` 計數 |

**計分：** PASS = 1 分 / FAIL = 0 分 / SKIPPED = 0 分

---

## 閾值設定

編輯 `config/thresholds.conf`：

```ini
# 記憶體 (MiB)
MEM_WARN_MB=300
MEM_CRIT_MB=100

# Swap (MiB) — 僅 Linux
SWAP_WARN_MB=200

# 磁碟使用率 (%)
DISK_WARN_PERCENT=80
DISK_CRIT_PERCENT=90

# CPU 負載 — 僅 Linux
LOAD_WARN=4.0

# 危險埠清單
DANGEROUS_PORTS=21,23,25,69,111,135,139,445,514,631,1433,1434,3306,3389,5432,5900,6379,8080,9200,27017
```

---

## 禁止使用的指令

v2 嚴格禁止所有需要 root / admin 的指令。以下操作在報告中標為 **[SKIPPED]**，  
並附帶建議管理員手動執行的指令：

| 平台 | 被跳過的操作 | 建議管理員執行 |
|------|-------------|---------------|
| Rocky | `firewall-cmd --list-all` | `sudo firewall-cmd --list-all` |
| Rocky | `/var/log/secure` | `sudo ausearch -m USER_AUTH -ts recent` |
| Ubuntu | `ufw status verbose` | `sudo ufw status verbose` |
| Ubuntu | `/var/log/auth.log` | `sudo journalctl -u ssh --since '1 hour ago'` |
| Windows | Security Event Log | `Get-WinEvent -FilterHashtable @{LogName='Security'}` |

---

## 指令清冊模組

`reports/scan_commands.json` 記錄了所有使用的非管理員指令（Linux + Windows），  
方便合規審計與文檔。

```bash
# Python 載入器
python3 tools/load_scan_commands.py reports/scan_commands.json --os linux --format table

# PowerShell 載入器
Import-Module .\tools\ScanCommands.ps1
Get-ScanCommands -Path .\reports\scan_commands.json -OS windows | Format-Table
```

---

## 系統需求

| 平台 | 最低需求 |
|------|---------|
| Linux | Bash 4+, coreutils, iproute2, procps |
| Windows | PowerShell 5.1+ (Windows 10/11, Server 2016+) |
| Launcher | Python 3.6+ (僅標準函式庫) |

---

## 常見問答

**Q: 為什麼某些項目顯示 [SKIPPED]？**  
A: 該項目需要 root / admin 權限。報告中會附帶建議由管理員手動執行的指令。

**Q: 報告存在哪裡？**  
A: `./reports/syskit_report_YYYYMMDD_HHMMSS.txt` 和 `.json`。

**Q: 可以排程自動執行嗎？**  
A: 可以。例如 Linux crontab 或 Windows Task Scheduler，以一般使用者身分排程即可。

**Q: JSON 檔的 `cis_score` 可以用來自動告警嗎？**  
A: 可以。讀取 `cis_score.failed` 即可判斷是否需要發送通知。

---

## 版本歷程

| 版本 | 日期 | 變更 |
|------|------|------|
| 2.0.0 | 2025-01 | 完整重寫：CIS-like 10 項基準、JSON 輸出、繁中表頭、閾值設定、取證建議、零權限設計 |
| 1.0.0 | 2024 | 初始版本 |

---

## License

MIT License — 此工具僅供系統健檢用途，不保證結果的完整性或準確性。  
使用者應自行評估風險。
