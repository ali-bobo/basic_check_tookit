# SysKit Scanner v2.1.0

> 跨平台系統健檢工具 — Windows / Rocky Linux / Ubuntu / macOS
> 所有指令皆為唯讀，絕不使用 root / Administrator 權限。

---

## 功能特色

| 特色 | 說明 |
|------|------|
| 🔒 零權限 | 偵測 root / admin 即拒絕執行 |
| 📊 CIS-like 基準 | 10 項安全檢查，PASS / FAIL / SKIPPED + 計分 |
| 🌐 跨平台 | Windows · Rocky/CentOS · Ubuntu/Debian · macOS |
| 📝 三格式報告 | TXT (繁中表頭) + JSON (機器可讀) + HTML (視覺化) |
| 🛡️ 安全防護 | 指令注入防護 (CWE-78 Allowlist) + checksum 驗證 |
| ⚙️ 可設定閾值 | `config/thresholds.conf` 控制記憶體、磁碟、埠門檻 |

---

## 專案結構

```
basic_check_tookit/
├── launcher.py              # Python 跨平台選單啟動器
├── scan_rocky.sh            # Rocky / CentOS / RHEL
├── scan_ubuntu.sh           # Ubuntu / Debian
├── scan_macos.sh            # macOS / Darwin
├── scan.ps1                 # Windows PowerShell
├── config/
│   └── thresholds.conf      # 閾值設定
├── reports/
│   ├── syskit_report_*      # 輸出報告（.gitignore 排除，不進版本控制）
│   ├── scan_commands.json   # 非管理員指令清冊 (JSON)
│   ├── scan_commands.json.sha256  # SHA-256 校驗碼
│   └── scan_commands.csv    # 非管理員指令清冊 (CSV)
└── tools/
    ├── load_scan_commands.py # 指令清冊載入器
    ├── ScanCommands.ps1     # PowerShell 指令清冊模組
    └── generate_html.py     # HTML 報告產生器
```

---

## 快速開始

```bash
# Linux / macOS
python3 launcher.py

# Windows
python launcher.py
```

啟動器自動偵測 OS，也可手動選擇。或直接執行腳本：

```bash
bash scan_rocky.sh      # Rocky / CentOS
bash scan_ubuntu.sh     # Ubuntu
bash scan_macos.sh      # macOS
```

```powershell
powershell -ExecutionPolicy Bypass -File scan.ps1   # Windows
```

> 請以一般使用者身分執行。偵測到 root / admin 會拒絕執行並退出。

---

## 報告輸出

報告存入 `reports/`，每次掃描產生三個檔案：

- `syskit_report_YYYYMMDD_HHMMSS.txt` — 繁體中文摘要表頭 + 各指令原始輸出
- `syskit_report_YYYYMMDD_HHMMSS.json` — 結構化資料，可供自動化分析或告警
- `syskit_report_YYYYMMDD_HHMMSS.html` — 可装載瀏覽的視覺化報告

JSON 報告關鍵欄位：`host` / `overall_status` / `cis_score` / `cis_checks` / `critical_findings` / `warn_findings`

> 所有報告已加入 `.gitignore`，不會被推入版本控制。

---

## CIS-like 10 項安全基準

| # | 項目 | Windows | Linux | macOS |
|---|------|---------|-------|-------|
| 1 | SSH / RDP 監聽 | :3389 | :22 | :22 |
| 2 | 危險埠（區分系統埠與防火牆狀態） | 同 | 同 | 同 |
| 3 | 記憶體使用 | FreePhysicalMemory | `free -m` | `vm_stat` |
| 4 | 磁碟使用率 | C: | / | / |
| 5 | 防火牆 | Windows Firewall 三個設定檔 | iptables/firewalld | Application Firewall |
| 6 | 防毒保護 | Defender + 第三方 AV | SELinux / AppArmor | SIP / Gatekeeper |
| 7 | 自動啟動服務 | `Get-Service` | crontab | LaunchAgents |
| 8 | 啟動項目 | Win32_StartupCommand | crontab | Login Items |
| 9 | Guest 帳號 / 家目錄 | Guest 帳號 | Home dir perms | Home dir perms |
| 10 | 程序數量 | `Get-Process` | `ps aux` | `ps aux` |

> PASS = 1 分 / FAIL = 0 分 / SKIPPED = 0 分。部分項目需管理員權限才能檢查，此時標為 `SKIPPED`。

**常見誤報說明**
- **埠 135/139 (Windows)**：屬 Windows 系統服務（RPC/NetBIOS）必然監聽，防火牆啟用時封鎖外部連線。掃描器已自動區分並標為 PASS。
- **Defender 即時保護=停用**：安裝第三方防毒後 Windows 會自動停用 Defender，屬正常行為。掃描器會暴出第三方防毒名稱並標為 PASS。

---

## 閾值設定

編輯 `config/thresholds.conf`：

```ini
MEM_WARN_MB=300          # 記憶體警告門檻 (MiB)
MEM_CRIT_MB=100          # 記憶體致命門檻
DISK_WARN_PERCENT=80     # 磁碟警告百分比
DISK_CRIT_PERCENT=90     # 磁碟致命百分比
LOAD_WARN=4.0            # CPU 負載警告（僅 Linux）
DANGEROUS_PORTS=21,23,25,69,111,135,139,445,...
```

---

## 指令清冊工具

```bash
# 列出 Linux 指令並驗證 checksum
python3 tools/load_scan_commands.py --list --platform linux --verify-checksum

# 手動產生 HTML 報告
python3 tools/generate_html.py reports/syskit_report_YYYYMMDD_HHMMSS.json
```

---

## 系統需求

| 平台 | 最低需求 |
|------|--------|
| Linux | Bash 4+, coreutils, iproute2, procps |
| Windows | PowerShell 5.1+ (Win10/11, Server 2016+) |
| macOS | macOS 11+ (Bash/zsh) |
| 啟動器 | Python 3.6+ (僅標準函式庫) |

---

## 版本歷程

| 版本 | 日期 | 變更 |
|------|------|------|
| 2.1.0 | 2026-06 | 新增 macOS、HTML 報告、CWE-78 防護、checksum、修正埠誤報與 Defender 偶合偵測 |
| 2.0.0 | 2026-03 | CIS-like 基準、JSON 輸出、繁中表頭、閾值設定、零權限設計 |
| 1.0.0 | 2024 | 初始版本 |

---

MIT License — 僅供系統健檢用途，使用者自行評估風險。

