#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SysKit Scanner v2.0.0 — Cross-platform Launcher
================================================
自動偵測作業系統並執行對應的掃描腳本。
- Linux (Rocky/CentOS/Alma) → scan_rocky.sh
- Linux (Ubuntu/Debian)     → scan_ubuntu.sh
- Windows                   → scan.ps1

所有指令皆為唯讀，不使用管理員 / root 權限。
報告輸出至 ./reports/ (TXT + JSON，UTF-8 繁體中文)。
"""

import os
import sys
import platform
import subprocess
import shutil
import datetime

VERSION = "2.0.0"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPORT_DIR = os.path.join(SCRIPT_DIR, "reports")


def banner():
    print()
    print("=" * 56)
    print("  SysKit Scanner v{} — Launcher".format(VERSION))
    print("=" * 56)
    print("  [*] 所有指令皆為唯讀，不使用管理員/root 權限。")
    print("  [*] 報告 (TXT + JSON) 將存至 ./reports/")
    print("=" * 56)
    print()


def detect_os():
    """Return one of: 'rocky', 'ubuntu', 'windows', 'unknown'."""
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    elif system == "linux":
        os_release = {}
        for f in ["/etc/os-release", "/usr/lib/os-release"]:
            if os.path.isfile(f):
                with open(f, "r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        line = line.strip()
                        if "=" in line:
                            k, v = line.split("=", 1)
                            os_release[k] = v.strip('"').strip("'")
                break
        distro_id = os_release.get("ID", "").lower()
        id_like = os_release.get("ID_LIKE", "").lower()
        if distro_id in ("rocky", "centos", "almalinux", "rhel", "fedora", "ol"):
            return "rocky"
        if "rhel" in id_like or "fedora" in id_like or "centos" in id_like:
            return "rocky"
        if distro_id in ("ubuntu", "debian", "linuxmint", "pop", "zorin", "elementary"):
            return "ubuntu"
        if "debian" in id_like or "ubuntu" in id_like:
            return "ubuntu"
        return "unknown"
    else:
        return "unknown"


def ensure_reports_dir():
    if not os.path.isdir(REPORT_DIR):
        os.makedirs(REPORT_DIR, exist_ok=True)


def run_script(script_name, shell_cmd):
    script_path = os.path.join(SCRIPT_DIR, script_name)
    if not os.path.isfile(script_path):
        print("[!] 找不到腳本: {}".format(script_path))
        return False

    print("[*] 執行: {} ...".format(script_name))
    print("-" * 50)
    try:
        result = subprocess.run(
            shell_cmd,
            shell=True,
            cwd=SCRIPT_DIR,
        )
        return result.returncode == 0
    except Exception as e:
        print("[ERROR] {}".format(e))
        return False


def run_rocky():
    return run_script("scan_rocky.sh", "bash scan_rocky.sh")


def run_ubuntu():
    return run_script("scan_ubuntu.sh", "bash scan_ubuntu.sh")


def run_windows():
    ps = shutil.which("pwsh") or shutil.which("powershell")
    if not ps:
        print("[!] 無法找到 PowerShell 執行路徑。")
        return False
    # quote the path in case it contains spaces (e.g. in "C:\Program Files")
    quoted_ps = '"{}"'.format(ps)
    cmd = '{} -NoProfile -ExecutionPolicy Bypass -File "{}"'.format(
        quoted_ps, os.path.join(SCRIPT_DIR, "scan.ps1")
    )
    return run_script("scan.ps1", cmd)


def menu():
    banner()
    detected = detect_os()
    friendly = {
        "rocky": "Rocky / CentOS / RHEL 系列",
        "ubuntu": "Ubuntu / Debian 系列",
        "windows": "Windows",
        "unknown": "未知",
    }

    print("  偵測到: {} ({})".format(friendly.get(detected, "未知"), platform.platform()))
    print()
    print("  [1] 自動偵測並執行  (推薦)")
    print("  [2] 手動選擇 — Rocky / CentOS")
    print("  [3] 手動選擇 — Ubuntu / Debian")
    print("  [4] 手動選擇 — Windows")
    print("  [0] 離開")
    print()

    choice = input("  請選擇 [1]: ").strip()
    if choice == "" or choice == "1":
        choice = "auto"
    elif choice == "0":
        print("  Bye!")
        sys.exit(0)

    ensure_reports_dir()

    if choice == "auto":
        if detected == "rocky":
            return run_rocky()
        elif detected == "ubuntu":
            return run_ubuntu()
        elif detected == "windows":
            return run_windows()
        else:
            print("[!] 無法自動偵測作業系統。請手動選擇。")
            return False
    elif choice == "2":
        return run_rocky()
    elif choice == "3":
        return run_ubuntu()
    elif choice == "4":
        return run_windows()
    else:
        print("[!] 無效選項。")
        return False


def main():
    # Refuse root/admin
    if platform.system().lower() != "windows":
        if os.geteuid() == 0:
            print("[!] 此工具禁止以 root 身分執行！請以一般使用者執行。")
            sys.exit(1)

    success = menu()

    print()
    if success:
        print("=" * 56)
        print("  [✔] 掃描完成！")
        print("  [*] TXT 報告: ./reports/syskit_report_*.txt")
        print("  [*] JSON 報告: ./reports/syskit_report_*.json")
        print("=" * 56)
    else:
        print("=" * 56)
        print("  [✘] 掃描未成功完成，請檢查上方訊息。")
        print("=" * 56)
    print()


if __name__ == "__main__":
    main()
