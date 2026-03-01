#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# SysKit Scanner - Ubuntu Edition (Non-Root, Safe Mode)
# ═══════════════════════════════════════════════════════════════════════════════
# - Runs WITHOUT root privileges. Refuses to execute as root.
# - All commands are READ-ONLY; nothing is modified.
# - Uses modern tools (ip, ss, systemctl). Avoids deprecated ifconfig/netstat.
# - Report is saved to ./reports/syskit_report_YYYYMMDD_HHMMSS.txt
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

VERSION="1.0.0"
CMD_TIMEOUT=10
MAX_LINES=60
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPORT_DIR="${SCRIPT_DIR}/reports"
REPORT_FILE="${REPORT_DIR}/syskit_report_${TIMESTAMP}.txt"

# Suspicious file extensions
SUSPICIOUS_EXTS=("hta" "scr" "pif" "wsf" "vbe" "vbs" "jse" "gadget" "url"
                 "docm" "xlsm" "lnk" "bat" "cmd" "reg" "cpl" "msi")

# Sensitive patterns to mask
MASK_PATTERNS=("password=" "pwd=" "secret=" "token=" "apikey=")

# ─── Helpers ─────────────────────────────────────────────────────────────────

mask_sensitive() {
    local text="$1"
    for pat in "${MASK_PATTERNS[@]}"; do
        text=$(echo "$text" | sed -E "s/(${pat})[^ ;\"']*/\1****/gi" 2>/dev/null || echo "$text")
    done
    echo "$text"
}

truncate_output() {
    local output="$1"
    local max="$2"
    local count
    count=$(echo "$output" | wc -l)
    if [ "$count" -gt "$max" ]; then
        echo "$output" | head -n "$max"
        echo "  ... (truncated, showing first ${max} of ${count} lines)"
    else
        echo "$output"
    fi
}

run_section() {
    local label="$1"
    shift
    local cmd_str="$*"

    echo ""
    echo "────────────────────────────────────────────────────────────────"
    echo "  [${label}]"
    echo "  Time: $(date +'%H:%M:%S')"
    echo "  Command: ${cmd_str}"
    echo "────────────────────────────────────────────────────────────────"

    local raw
    if raw=$(timeout "${CMD_TIMEOUT}" bash -c "$cmd_str" 2>&1); then
        raw=$(mask_sensitive "$raw")
        truncate_output "$raw" "$MAX_LINES"
    else
        local rc=$?
        if [ $rc -eq 124 ]; then
            echo "  [TIMEOUT] Command did not complete within ${CMD_TIMEOUT}s - skipped."
        else
            raw=$(mask_sensitive "${raw:-}")
            if [ -n "$raw" ]; then
                truncate_output "$raw" "$MAX_LINES"
            fi
            echo "  [NOTE] Command exited with code ${rc}."
        fi
    fi
}

banner() {
    cat <<EOF
================================================================================
  SysKit Scanner v${VERSION}  |  Ubuntu (Non-Root Safe Mode)
  Scan started : $(date +'%Y-%m-%d %H:%M:%S')
  Hostname     : $(hostname)
  User         : $(whoami)
================================================================================
EOF
}

# ─── Pre-flight ──────────────────────────────────────────────────────────────

if [ "$(id -u)" -eq 0 ]; then
    echo "[!] This tool must NOT run as root. Please run as a normal user."
    exit 1
fi

echo ""
echo "========================================"
echo "  SysKit Scanner - Ubuntu Safe Mode"
echo "========================================"
echo ""
echo "[*] All commands are READ-ONLY. No system changes will be made."
echo "[*] Report will be saved to: ${REPORT_FILE}"
echo ""

mkdir -p "${REPORT_DIR}"

# ─── Begin Report ────────────────────────────────────────────────────────────
{
    banner

    # 1. System Information
    echo ""
    echo "  >> [1/13] System Information"
    run_section "OS Release" "cat /etc/os-release 2>/dev/null || cat /etc/lsb-release 2>/dev/null"
    run_section "Kernel & Architecture" "uname -a"
    run_section "Uptime" "uptime"
    run_section "CPU Info" "lscpu | head -n 20"
    run_section "Memory Info" "free -h"

    # 2. Network Configuration
    echo ""
    echo "  >> [2/13] Network Configuration"
    run_section "IPv4 Addresses" "ip -4 addr show"
    run_section "IPv4 Routes" "ip -4 route show"
    run_section "DNS Servers" "cat /etc/resolv.conf | grep -v '^#'"

    # 3. Network Connectivity Tests
    echo ""
    echo "  >> [3/13] Network Connectivity"
    run_section "Ping 8.8.8.8 (3 packets)" "ping -c 3 -W 3 8.8.8.8"
    run_section "DNS Resolution (google.com)" "host google.com 2>/dev/null || dig +short google.com 2>/dev/null || nslookup google.com 2>/dev/null"
    run_section "Public IP" "curl -sS --max-time 5 https://ifconfig.co/ip 2>/dev/null || echo 'Could not retrieve public IP'"
    run_section "Traceroute 8.8.8.8 (max 10 hops)" "traceroute -m 10 -q 1 -w 2 8.8.8.8 2>/dev/null || echo 'traceroute not installed - skipped'"

    # 4. Listening & Connections
    echo ""
    echo "  >> [4/13] Connections & Listening"
    run_section "TCP/UDP Listening (ss -tuln)" "ss -tuln"
    run_section "Established TCP (ss -tun state established)" "ss -tun state established"

    # 5. Process Inspection
    echo ""
    echo "  >> [5/13] Process Inspection"
    run_section "Top 25 by CPU" "ps aux --sort=-%cpu | head -n 26"
    run_section "Top 25 by Memory" "ps aux --sort=-%mem | head -n 26"
    run_section "Process Tree (depth 3)" "ps axjf | head -n 80"

    # 6. Startup & Persistence
    echo ""
    echo "  >> [6/13] Startup & Persistence"
    run_section "Running Services" "systemctl list-units --type=service --state=running --no-pager 2>/dev/null || echo 'systemctl unavailable'"
    run_section "Enabled Services" "systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null || echo 'systemctl unavailable'"
    run_section "User Cron Jobs" "crontab -l 2>/dev/null || echo 'No cron jobs for current user'"
    run_section "System Cron (/etc/crontab)" "cat /etc/crontab 2>/dev/null || echo '/etc/crontab not readable'"

    # 7. Users & Login History
    echo ""
    echo "  >> [7/13] Users & Login History"
    run_section "Passwd List (non-system)" "awk -F: '\$3 >= 1000 {print \$1, \$3, \$6, \$7}' /etc/passwd"
    run_section "Currently Logged In" "who 2>/dev/null || w 2>/dev/null"
    run_section "Last 20 Logins" "last -n 20 2>/dev/null || echo 'last command unavailable'"
    run_section "Failed Login Attempts" "lastb -n 20 2>/dev/null || echo 'lastb requires elevated privileges - skipped'"

    # 8. Package & Update Status
    echo ""
    echo "  >> [8/13] Package Updates"
    run_section "Upgradable Packages" "apt list --upgradable 2>/dev/null | head -n 40"

    # 9. Firewall Status
    echo ""
    echo "  >> [9/13] Firewall"
    run_section "UFW Status" "ufw status verbose 2>/dev/null || echo 'UFW not available or requires elevated privileges - skipped'"
    run_section "nftables Rules (read-only)" "nft list ruleset 2>/dev/null || echo 'nft not available or requires elevated privileges - skipped'"

    # 10. Disk & Storage
    echo ""
    echo "  >> [10/13] Disk & Storage"
    run_section "Filesystem Usage" "df -hT"
    run_section "Mount Points" "findmnt --notruncate -t notmpfs,nodevtmpfs,nosquashfs 2>/dev/null || mount"
    run_section "Large Files in /home (top 20)" "find /home -xdev -type f -readable -printf '%s %p\n' 2>/dev/null | sort -rn | head -n 20 | awk '{printf \"%.2f MB  %s\n\", \$1/1048576, \$2}'"

    # 11. Suspicious File Scan
    echo ""
    echo "  >> [11/13] Suspicious File Scan"

    SCAN_DIRS=("/tmp" "${HOME}/Downloads" "${HOME}/Desktop" "${HOME}")
    FIND_EXTS=""
    for ext in "${SUSPICIOUS_EXTS[@]}"; do
        if [ -n "$FIND_EXTS" ]; then
            FIND_EXTS="${FIND_EXTS} -o"
        fi
        FIND_EXTS="${FIND_EXTS} -iname '*.${ext}'"
    done

    for sdir in "${SCAN_DIRS[@]}"; do
        if [ -d "$sdir" ]; then
            run_section "Suspicious in ${sdir}" \
                "find '${sdir}' -maxdepth 3 -type f -readable \\( ${FIND_EXTS} \\) -printf '%T+ %s %p\n' 2>/dev/null | sort -r | head -n 30 || echo 'No suspicious files found'"
        fi
    done

    # 12. Log Summary
    echo ""
    echo "  >> [12/13] Log Summary"
    run_section "Journal Errors (last 50)" "journalctl -p err -n 50 --no-pager 2>/dev/null || echo 'journalctl unavailable or requires privileges - skipped'"
    run_section "Auth Log (last 50)" "tail -n 50 /var/log/auth.log 2>/dev/null || echo '/var/log/auth.log not readable - skipped'"
    run_section "Syslog (last 50)" "tail -n 50 /var/log/syslog 2>/dev/null || echo '/var/log/syslog not readable - skipped'"

    # 13. Container / VM Detection
    echo ""
    echo "  >> [13/13] Virtualization Detection"
    run_section "Container Check" "
        if grep -qE '/docker|/kubepods|/lxc' /proc/1/cgroup 2>/dev/null; then
            echo '[Container] Running inside a container.'
            cat /proc/1/cgroup 2>/dev/null | head -n 10
        elif [ -f /.dockerenv ]; then
            echo '[Container] Docker container detected (.dockerenv exists).'
        else
            echo '[Not a container] No container indicators found.'
        fi
    "
    run_section "VM Detection" "
        if command -v systemd-detect-virt &>/dev/null; then
            result=\$(systemd-detect-virt 2>/dev/null)
            echo \"Detected: \${result:-none}\"
        else
            product=\$(cat /sys/class/dmi/id/product_name 2>/dev/null || echo 'unknown')
            vendor=\$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null || echo 'unknown')
            echo \"Product: \${product}\"
            echo \"Vendor:  \${vendor}\"
        fi
    "

    # Footer
    echo ""
    echo "================================================================================"
    echo "  Scan completed : $(date +'%Y-%m-%d %H:%M:%S')"
    echo "  Report saved to: ${REPORT_FILE}"
    echo "================================================================================"

} > "${REPORT_FILE}" 2>&1

echo ""
echo "[+] Scan complete! Report saved to:"
echo "    ${REPORT_FILE}"
echo ""
