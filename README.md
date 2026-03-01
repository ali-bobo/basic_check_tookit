# SysKit Scanner — System Engineer Toolkit

A lightweight, **read-only** system diagnostic toolkit for system engineers.  
Supports **Windows (PowerShell)**, **Ubuntu (Bash)**, and **Rocky Linux (Bash)**.

---

## Features

| Category | What it collects |
|---|---|
| **System Info** | OS version, kernel, CPU, memory, BIOS/firmware, uptime |
| **Network Config** | IP addresses, routes, DNS servers |
| **Connectivity** | Ping, DNS resolution, public IP, traceroute (limited hops) |
| **Connections** | Listening ports, established TCP/UDP connections |
| **Processes** | Top CPU/memory consumers, process tree, suspicious process names |
| **Startup & Persistence** | Auto-start services, scheduled tasks/cron, startup entries |
| **Users & Logins** | Local users, login history, failed logins |
| **Package Updates** | Upgradable packages (query only — never installs) |
| **Firewall** | Firewall status & inbound rules (read-only) |
| **Disk & Storage** | Filesystem usage, mount points, large files |
| **Suspicious Files** | Scans key directories for `.hta`, `.scr`, `.vbs`, `.wsf`, `.docm`, `.xlsm`, etc. |
| **Log Summary** | Recent system/application/auth errors (limited entries) |
| **VM/Container** | Detects if running in a VM or container |

---

## Safety Guarantees

- **Non-privileged only** — refuses to run as Administrator / root.
- **Read-only** — no files are created, modified, or deleted on the system (except the report).
- **No network exposure** — no data is uploaded; only one outbound HTTP call to get your public IP.
- **No package changes** — queries update status but never installs or removes anything.
- **No dangerous commands** — `rm`, `dd`, `mkfs`, `shutdown`, service stop, firewall changes, etc. are explicitly forbidden.
- **No deprecated tools** — avoids `netstat`, `ifconfig`, `wmic` in favor of modern alternatives.
- **Sensitive data masking** — patterns like `password=`, `token=`, `secret=` are masked in output.
- **Command timeout** — each command has a 10-second timeout to prevent hangs.
- **Output truncation** — each section is capped at 60 lines to keep reports manageable.

---

## Requirements

| Platform | Requirements |
|---|---|
| **Windows** | PowerShell 5.1+ (built-in on Windows 10/11/Server 2016+) |
| **Ubuntu** | Bash 4+, coreutils, iproute2, systemd (standard on Ubuntu 18.04+) |
| **Rocky** | Bash 4+, coreutils, iproute2, systemd, dnf (standard on Rocky 8/9) |
| **Launcher** | Python 3.6+ (optional — you can run scripts directly) |

No additional packages need to be installed.

---

## Quick Start

### Option 1: Use the Launcher (recommended)

```bash
# Interactive menu
python launcher.py

# Auto-detect OS and run immediately
python launcher.py --auto
```

### Option 2: Run scripts directly

**Windows (PowerShell):**
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scan.ps1
```

**Ubuntu:**
```bash
chmod +x scan_ubuntu.sh
./scan_ubuntu.sh
```

**Rocky Linux:**
```bash
chmod +x scan_rocky.sh
./scan_rocky.sh
```

---

## Output

Reports are saved to:

```
./reports/syskit_report_YYYYMMDD_HHMMSS.txt
```

### Sample Report Structure

```
================================================================================
  SysKit Scanner v1.0.0  |  Windows PowerShell (Non-Elevated Safe Mode)
  Scan started : 2026-03-01 14:30:00
  Hostname     : WORKSTATION-01
  User         : engineer
================================================================================

────────────────────────────────────────────────────────────────
  [OS & Build]
  Time: 14:30:01
────────────────────────────────────────────────────────────────
  Caption      : Microsoft Windows 11 Pro
  Version      : 10.0.22631
  ...

────────────────────────────────────────────────────────────────
  [TCP Listening Ports]
  ...

────────────────────────────────────────────────────────────────
  [Suspicious Files in Key Directories]
  [!] Found 2 suspicious file(s):
  ...

================================================================================
  Scan completed : 2026-03-01 14:31:15
  Report saved to: ./reports/syskit_report_20260301_143000.txt
================================================================================
```

---

## File Structure

```
toolkit/
├── launcher.py          # Cross-platform menu launcher
├── scan.ps1             # Windows PowerShell scanner
├── scan_ubuntu.sh       # Ubuntu Bash scanner
├── scan_rocky.sh        # Rocky Linux Bash scanner
├── README.md            # This file
└── reports/             # Generated reports (auto-created)
    └── syskit_report_YYYYMMDD_HHMMSS.txt
```

---

## Forbidden Actions (by design)

The following actions are **never** performed by this toolkit:

- ❌ Delete or overwrite files (`rm -rf`, `Remove-Item -Recurse -Force`)
- ❌ Install or remove packages (`apt install`, `dnf install`)
- ❌ Modify firewall rules (`ufw allow`, `firewall-cmd --add-port`)
- ❌ Stop/restart services or the system (`systemctl stop`, `shutdown`)
- ❌ Low-level disk operations (`dd`, `mkfs`, `parted`)
- ❌ Execute remote/untrusted scripts or binaries
- ❌ Port-scan external hosts
- ❌ Request or use elevated privileges

---

## License

This toolkit is provided as-is for internal use by system engineers.  
Use at your own discretion. No warranty is implied.
