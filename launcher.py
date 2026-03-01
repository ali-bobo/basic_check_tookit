#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════════════════
# SysKit Scanner - Cross-Platform Launcher
# ═══════════════════════════════════════════════════════════════════════════════
# Displays a menu to select the target OS, then executes the corresponding
# scan script.  No external dependencies — uses only the Python standard library.
#
# Usage:
#   python launcher.py          (interactive menu)
#   python launcher.py --auto   (auto-detect current OS and run)
# ═══════════════════════════════════════════════════════════════════════════════

import os
import sys
import platform
import subprocess
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

BANNER = r"""
 ____            _  ___ _     ____
/ ___| _   _ ___| |/ (_) |_  / ___|  ___ __ _ _ __  _ __   ___ _ __
\___ \| | | / __| ' /| | __| \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 ___) | |_| \__ \ . \| | |_   ___) | (_| (_| | | | | | | |  __/ |
|____/ \__, |___/_|\_\_|\__| |____/ \___\__,_|_| |_|_| |_|\___|_|
       |___/
                     System Engineer Toolkit  v1.0.0
"""

SAFETY_NOTICE = """
╔══════════════════════════════════════════════════════════════════════╗
║  SAFETY NOTICE                                                      ║
║  • This tool runs in NON-PRIVILEGED safe mode only.                 ║
║  • All commands are READ-ONLY — nothing on your system is modified. ║
║  • No data is uploaded or sent externally.                          ║
║  • Report is saved locally in the ./reports/ folder.                ║
║  • The tool will REFUSE to run as Administrator / root.             ║
╚══════════════════════════════════════════════════════════════════════╝
"""

MENU = """
  Please select the scan target:

    [1]  Windows   (PowerShell)
    [2]  Ubuntu    (Bash)
    [3]  Rocky     (Bash)
    [0]  Exit

"""


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def detect_os():
    """Try to auto-detect the running OS and return a menu choice number."""
    system = platform.system().lower()
    if system == "windows":
        return "1"
    elif system == "linux":
        # Distinguish Ubuntu vs Rocky/RHEL
        try:
            with open("/etc/os-release") as f:
                content = f.read().lower()
            if "ubuntu" in content or "debian" in content:
                return "2"
            elif "rocky" in content or "rhel" in content or "centos" in content:
                return "3"
        except FileNotFoundError:
            pass
        return "2"  # default to Ubuntu for unknown Linux
    return None


def run_powershell():
    script = os.path.join(SCRIPT_DIR, "scan.ps1")
    if not os.path.isfile(script):
        print(f"[!] Script not found: {script}")
        return False
    print(f"\n[*] Launching PowerShell scanner: {script}\n")
    # Use -ExecutionPolicy Bypass so the script can run without policy issues
    result = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script],
        cwd=SCRIPT_DIR,
    )
    return result.returncode == 0


def run_bash(script_name):
    script = os.path.join(SCRIPT_DIR, script_name)
    if not os.path.isfile(script):
        print(f"[!] Script not found: {script}")
        return False
    # Ensure executable
    try:
        os.chmod(script, 0o755)
    except OSError:
        pass
    print(f"\n[*] Launching Bash scanner: {script}\n")
    result = subprocess.run(["bash", script], cwd=SCRIPT_DIR)
    return result.returncode == 0


def main():
    auto_mode = "--auto" in sys.argv

    clear_screen()
    print(BANNER)
    print(SAFETY_NOTICE)

    if auto_mode:
        choice = detect_os()
        if choice is None:
            print("[!] Could not auto-detect OS. Falling back to interactive menu.")
            auto_mode = False
        else:
            os_names = {"1": "Windows (PowerShell)", "2": "Ubuntu (Bash)", "3": "Rocky Linux (Bash)"}
            print(f"[Auto] Detected: {os_names.get(choice, 'Unknown')}\n")
    
    if not auto_mode:
        print(MENU)
        try:
            choice = input("  Enter your choice [0-3]: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[*] Cancelled.")
            sys.exit(0)

    start_time = time.time()
    success = False

    if choice == "1":
        success = run_powershell()
    elif choice == "2":
        success = run_bash("scan_ubuntu.sh")
    elif choice == "3":
        success = run_bash("scan_rocky.sh")
    elif choice == "0":
        print("[*] Bye!")
        sys.exit(0)
    else:
        print(f"[!] Invalid choice: {choice}")
        sys.exit(1)

    elapsed = time.time() - start_time
    print(f"\n[*] Total execution time: {elapsed:.1f}s")

    if success:
        reports_dir = os.path.join(SCRIPT_DIR, "reports")
        # Find the most recent report
        try:
            files = sorted(
                [f for f in os.listdir(reports_dir) if f.startswith("syskit_report_")],
                reverse=True,
            )
            if files:
                latest = os.path.join(reports_dir, files[0])
                print(f"[*] Latest report: {latest}")
        except OSError:
            pass
        print("\n[+] Done! Check the reports/ folder for your scan results.\n")
    else:
        print("\n[!] Scan finished with errors. Check output above.\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
