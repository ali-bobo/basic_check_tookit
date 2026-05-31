#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# SysKit Scanner v2.0  —  macOS Edition (Non-Root, Safe Mode)
# ═══════════════════════════════════════════════════════════════════════════════
# - 絕不使用 sudo 或任何需要管理員權限的指令。
# - 所有命令皆為唯讀 (READ-ONLY)，不會修改系統。
# - 報告以繁體中文摘要表頭開頭 (UTF-8)。
# - 包含 CIS-like 10 項安全基準檢查與計分（macOS 專屬）。
# - 同時產出 TXT 與 JSON 報告。
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail
export LANG=en_US.UTF-8

VERSION="2.0.0"
CMD_TIMEOUT=10
MAX_LINES=60
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPORT_DIR="${SCRIPT_DIR}/reports"
REPORT_FILE="${REPORT_DIR}/syskit_report_${TIMESTAMP}.txt"
JSON_FILE="${REPORT_DIR}/syskit_report_${TIMESTAMP}.json"
DETAIL_TMP=$(mktemp)
trap 'rm -f "$DETAIL_TMP"' EXIT

SUSPICIOUS_EXTS=("hta" "scr" "pif" "wsf" "vbe" "vbs" "jse" "gadget" "url"
                 "docm" "xlsm" "lnk" "bat" "cmd" "reg" "cpl" "msi")
MASK_PATTERNS=("password=" "pwd=" "secret=" "token=" "apikey=")

# ─── Load Thresholds ─────────────────────────────────────────────────────────
MEM_WARN_MB=300; MEM_CRIT_MB=100
DISK_WARN_PERCENT=80; DISK_CRIT_PERCENT=90
LOAD_WARN="0.8"; LOAD_CRIT="1.5"
DANGEROUS_PORTS="21,23,25,69,111,135,139,445,514,631,1433,1434,3306,3389,5432,5900,6379,8080,9200,27017"

CONF_FILE="${SCRIPT_DIR}/config/thresholds.conf"
if [ -f "$CONF_FILE" ]; then
    while IFS='=' read -r key val; do
        key=$(echo "$key" | xargs 2>/dev/null || true)
        val=$(echo "$val" | xargs 2>/dev/null || true)
        [[ "$key" =~ ^#.*$ || -z "$key" ]] && continue
        declare "$key=$val" 2>/dev/null || true
    done < "$CONF_FILE"
fi

# ─── Collectors ──────────────────────────────────────────────────────────────
declare -a CRITICAL_FINDINGS=()
declare -a WARN_FINDINGS=()
declare -a SKIPPED_CHECKS=()
declare -a CIS_RESULTS=()
CIS_PASS=0; CIS_FAIL=0; CIS_SKIP=0
OVERALL_STATUS="🟢 正常"
HOST_NAME=$(hostname 2>/dev/null || echo "unknown")
OS_INFO=$(sw_vers 2>/dev/null | awk '/ProductName/{n=$NF} /ProductVersion/{v=$NF} END{print n, v}' || echo "macOS")
UPTIME_STR=$(uptime | sed 's/.*up /up /' | cut -d, -f1 2>/dev/null || echo "N/A")
LOAD_AVG=$(uptime | awk -F'load averages?:' '{print $2}' | awk '{print $1}' | tr -d ',' 2>/dev/null || echo "0.00")
USER_COUNT=$(who 2>/dev/null | wc -l | tr -d ' ' || echo "0")
MEM_FREE_MB=0; DISK_USE_PCT=0
declare -a TOP_PROCS=()
declare -a OPEN_PORTS_LIST=()
PRIVATE_IP="N/A"; PUBLIC_IP="N/A"
SIP_STATUS="N/A"; GATEKEEPER_STATUS="N/A"; FILEVAULT_STATUS="N/A"; FW_STATUS="N/A"

# ─── Helpers ─────────────────────────────────────────────────────────────────
mask_sensitive() {
    local text="$1"
    for pat in "${MASK_PATTERNS[@]}"; do
        text=$(echo "$text" | sed -E "s/(${pat})[^ ;\"']*/\1****/gi" 2>/dev/null || echo "$text")
    done
    echo "$text"
}

truncate_output() {
    local output="$1"; local max="$2"; local count
    count=$(echo "$output" | wc -l)
    if [ "$count" -gt "$max" ]; then
        echo "$output" | head -n "$max"
        echo "  ... (已截斷，顯示前 ${max} / 共 ${count} 行)"
    else
        echo "$output"
    fi
}

run_section() {
    local label="$1"; shift; local cmd_str="$*"
    {
        echo ""
        echo "────────────────────────────────────────────────────────────────"
        echo "  [${label}]"
        echo "  Time: $(date +'%H:%M:%S')"
        echo "  Command: ${cmd_str}"
        echo "────────────────────────────────────────────────────────────────"
    } >> "$DETAIL_TMP"
    local raw
    if raw=$(timeout "${CMD_TIMEOUT}" bash -c "$cmd_str" 2>&1); then
        raw=$(mask_sensitive "$raw")
        truncate_output "$raw" "$MAX_LINES" >> "$DETAIL_TMP"
    else
        local rc=$?
        if [ $rc -eq 124 ]; then
            echo "  [TIMEOUT] 指令未能在 ${CMD_TIMEOUT}s 內完成 — 已跳過。" >> "$DETAIL_TMP"
        else
            raw=$(mask_sensitive "${raw:-}")
            [ -n "$raw" ] && truncate_output "$raw" "$MAX_LINES" >> "$DETAIL_TMP"
            echo "  [NOTE] 指令回傳碼 ${rc}。" >> "$DETAIL_TMP"
        fi
    fi
}

skip_section() {
    local label="$1"; local reason="$2"; local admin_cmd="$3"
    {
        echo ""
        echo "────────────────────────────────────────────────────────────────"
        echo "  [${label}]"
        echo "  [SKIPPED] ${reason}"
        echo "  建議由管理員執行："
        echo "    ${admin_cmd}"
        echo "────────────────────────────────────────────────────────────────"
    } >> "$DETAIL_TMP"
    SKIPPED_CHECKS+=("${label}")
}

add_cis() {
    local name="$1" status="$2" evidence="$3" advice="$4"
    CIS_RESULTS+=("${name}|${status}|${evidence}|${advice}")
    case "$status" in
        PASS) CIS_PASS=$((CIS_PASS + 1)) ;;
        FAIL) CIS_FAIL=$((CIS_FAIL + 1)) ;;
        SKIPPED) CIS_SKIP=$((CIS_SKIP + 1)) ;;
    esac
}

# ─── Pre-flight ──────────────────────────────────────────────────────────────
if [ "$(id -u)" -eq 0 ]; then
    echo "[!] 此工具禁止以 root 執行。請使用一般使用者帳號。"
    exit 1
fi

echo ""
echo "========================================"
echo "  SysKit Scanner v${VERSION} - macOS"
echo "========================================"
echo "[*] 所有指令皆為唯讀，不使用 sudo。"
echo "[*] 報告: ${REPORT_FILE}"
echo "[*] JSON: ${JSON_FILE}"
echo ""

mkdir -p "${REPORT_DIR}"

# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION SCANS
# ═══════════════════════════════════════════════════════════════════════════════

echo "[1/13] 系統資訊..." >&2
echo "" >> "$DETAIL_TMP"; echo "  >> [1/13] 系統資訊 (System Information)" >> "$DETAIL_TMP"
run_section "macOS Version" "sw_vers"
run_section "Kernel & Architecture" "uname -a"
run_section "Uptime" "uptime"
run_section "CPU Info" "sysctl -n machdep.cpu.brand_string 2>/dev/null && sysctl -n hw.physicalcpu 2>/dev/null && sysctl -n hw.logicalcpu 2>/dev/null || echo 'sysctl CPU 資訊不可用'"
run_section "Memory Info" "vm_stat 2>/dev/null | head -n 15"

# 從 vm_stat 推算 free MB（近似值）
PAGE_SIZE=$(getconf PAGE_SIZE 2>/dev/null || echo "4096")
FREE_PAGES=$(vm_stat 2>/dev/null | awk '/Pages free/{gsub(/\./,"",$NF); print $NF}' || echo "0")
MEM_FREE_MB=$(echo "$FREE_PAGES $PAGE_SIZE" | awk '{printf "%d", ($1 * $2) / 1048576}' || echo "0")

if [ "${MEM_FREE_MB:-0}" -lt "$MEM_CRIT_MB" ] 2>/dev/null; then
    CRITICAL_FINDINGS+=("[RAM] 剩餘約 ${MEM_FREE_MB}MiB! 低於臨界值 ${MEM_CRIT_MB}MiB。")
    OVERALL_STATUS="🔴 需注意 - 記憶體不足"
elif [ "${MEM_FREE_MB:-0}" -lt "$MEM_WARN_MB" ] 2>/dev/null; then
    WARN_FINDINGS+=("[RAM] 剩餘約 ${MEM_FREE_MB}MiB，接近警告閾值。")
    [ "$OVERALL_STATUS" = "🟢 正常" ] && OVERALL_STATUS="🟡 注意"
fi

echo "[2/13] 網路設定..." >&2
echo "" >> "$DETAIL_TMP"; echo "  >> [2/13] 網路設定 (Network Configuration)" >> "$DETAIL_TMP"
run_section "IPv4 Addresses" "ifconfig 2>/dev/null | grep -A 4 'inet ' | grep -v '127.0.0.1' | head -n 20 || echo 'ifconfig 不可用'"
run_section "IPv4 Routes" "netstat -rn -f inet 2>/dev/null | head -n 30 || echo 'netstat 不可用'"
run_section "DNS Servers" "grep -v '^#' /etc/resolv.conf 2>/dev/null || cat /var/run/resolv.conf 2>/dev/null || echo 'DNS 設定不可讀'"
PRIVATE_IP=$(ifconfig 2>/dev/null | awk '/inet / && !/127.0.0.1/{print $2; exit}' || echo "N/A")

echo "[3/13] 網路連線測試..." >&2
echo "" >> "$DETAIL_TMP"; echo "  >> [3/13] 網路連線 (Network Connectivity)" >> "$DETAIL_TMP"
run_section "Ping 8.8.8.8 (3 packets)" "ping -c 3 -W 3000 8.8.8.8 2>/dev/null || echo 'ping 失敗 — 請確認網路'"
run_section "DNS Resolution (google.com)" "dig +short google.com 2>/dev/null || nslookup google.com 2>/dev/null || echo 'DNS 解析工具不可用'"
PUBLIC_IP=$(curl -sS --max-time 5 https://ifconfig.co/ip 2>/dev/null | tr -d '[:space:]' || echo "N/A")
run_section "Public IP" "echo '${PUBLIC_IP}'"
run_section "Traceroute 8.8.8.8 (max 10 hops)" "traceroute -m 10 -q 1 -w 2 8.8.8.8 2>/dev/null || echo 'traceroute 不可用'"

echo "[4/13] 連線與監聽埠..." >&2
echo "" >> "$DETAIL_TMP"; echo "  >> [4/13] 連線與監聽 (Connections & Listening)" >> "$DETAIL_TMP"
run_section "TCP/UDP Listening (lsof)" "lsof -i -P -n -sTCP:LISTEN 2>/dev/null | head -n 60 || echo 'lsof 不可用'"
run_section "Established TCP" "lsof -i -P -n -sTCP:ESTABLISHED 2>/dev/null | head -n 40 || echo 'lsof 不可用'"

OPEN_PORTS_RAW=$(lsof -i -P -n -sTCP:LISTEN 2>/dev/null | awk 'NR>1{split($9,a,":"); if(a[length(a)] ~ /^[0-9]+$/) print a[length(a)]}' | sort -un || true)
while IFS= read -r p; do [ -n "$p" ] && OPEN_PORTS_LIST+=("$p"); done <<< "$OPEN_PORTS_RAW"

echo "[5/13] 程序檢查..." >&2
echo "" >> "$DETAIL_TMP"; echo "  >> [5/13] 程序檢查 (Process Inspection)" >> "$DETAIL_TMP"
run_section "Top 25 by CPU" "ps aux -r | head -n 26"
run_section "Top 25 by Memory" "ps aux -m | head -n 26"
run_section "Process Tree" "ps axjf 2>/dev/null | head -n 60 || ps aux | head -n 60"

TOP_PROCS_RAW=$(ps aux -m 2>/dev/null | awk 'NR>1 && NR<=4 {printf "%s (%.1f%% MEM)\n", $11, $4}' || true)
while IFS= read -r line; do [ -n "$line" ] && TOP_PROCS+=("$line"); done <<< "$TOP_PROCS_RAW"

echo "[6/13] 啟動項目..." >&2
echo "" >> "$DETAIL_TMP"; echo "  >> [6/13] 啟動與持久化 (Startup & Persistence)" >> "$DETAIL_TMP"
run_section "Launch Agents (User)" "ls -la ~/Library/LaunchAgents/ 2>/dev/null || echo '~/Library/LaunchAgents/ 不存在或不可讀'"
run_section "Launch Agents (System)" "ls -la /Library/LaunchAgents/ 2>/dev/null || echo '/Library/LaunchAgents/ 不可讀'"
run_section "Launch Daemons (System)" "ls -la /Library/LaunchDaemons/ 2>/dev/null || echo '/Library/LaunchDaemons/ 不可讀'"
run_section "Launchctl List (running)" "launchctl list 2>/dev/null | head -n 60 || echo 'launchctl 不可用'"
run_section "User Cron Jobs" "crontab -l 2>/dev/null || echo '當前使用者無 cron 工作'"
run_section "Login Items (CIM)" "osascript -e 'tell application \"System Events\" to get the name of every login item' 2>/dev/null || echo '無法讀取 Login Items（沙箱限制）'"

echo "[7/13] 使用者與登入紀錄..." >&2
echo "" >> "$DETAIL_TMP"; echo "  >> [7/13] 使用者與登入 (Users & Login History)" >> "$DETAIL_TMP"
run_section "Local Users (dscl)" "dscl . -list /Users UniqueID 2>/dev/null | awk '\$2 >= 500' || echo 'dscl 不可用'"
run_section "Currently Logged In" "who 2>/dev/null || echo 'who 不可用'"
run_section "Last 20 Logins" "last -n 20 2>/dev/null || echo 'last 指令不可用'"
skip_section "Failed Login Attempts" "需要管理員讀取 /var/log/authd.log" "sudo log show --predicate 'eventMessage contains \"authentication failed\"' --last 1h"

echo "[8/13] 套件管理..." >&2
echo "" >> "$DETAIL_TMP"; echo "  >> [8/13] 套件管理 (Package Management)" >> "$DETAIL_TMP"
run_section "Homebrew Installed Formulae" "brew list 2>/dev/null | head -n 40 || echo 'Homebrew 未安裝 — 已跳過'"
run_section "Homebrew Installed Casks" "brew list --cask 2>/dev/null | head -n 30 || echo 'Homebrew 未安裝 — 已跳過'"
run_section "Homebrew Outdated Packages" "brew outdated 2>/dev/null | head -n 30 || echo 'Homebrew 未安裝 — 已跳過'"
run_section "System Software Updates" "softwareupdate -l 2>/dev/null | head -n 30 || echo 'softwareupdate 不可用'"

echo "[9/13] 安全設定..." >&2
echo "" >> "$DETAIL_TMP"; echo "  >> [9/13] 安全設定 (Security Settings)" >> "$DETAIL_TMP"
# SIP（System Integrity Protection）
SIP_STATUS=$(csrutil status 2>/dev/null || echo "N/A")
run_section "SIP Status" "csrutil status 2>/dev/null || echo 'csrutil 不可用（非 Recovery Mode）'"
# Gatekeeper
GATEKEEPER_STATUS=$(spctl --status 2>/dev/null || echo "N/A")
run_section "Gatekeeper Status" "spctl --status 2>/dev/null || echo 'spctl 不可用'"
# FileVault
FILEVAULT_STATUS=$(fdesetup status 2>/dev/null || echo "N/A")
run_section "FileVault Status" "fdesetup status 2>/dev/null || echo 'fdesetup 不可用'"
# Application Firewall
FW_STATUS=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "N/A")
run_section "Application Firewall" "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo '防火牆狀態不可讀'"

echo "[10/13] 磁碟..." >&2
echo "" >> "$DETAIL_TMP"; echo "  >> [10/13] 磁碟與儲存 (Disk & Storage)" >> "$DETAIL_TMP"
run_section "Filesystem Usage" "df -h"
run_section "Disk List" "diskutil list 2>/dev/null || echo 'diskutil 不可用'"
run_section "Large Files in ~/Downloads (top 20)" "find ~/Downloads -maxdepth 2 -type f 2>/dev/null | xargs stat -f '%z %N' 2>/dev/null | sort -rn | head -n 20 | awk '{printf \"%.2f MB  %s\n\", \$1/1048576, \$2}' || echo '~/Downloads 不存在或不可讀'"

DISK_USE_PCT=$(df / 2>/dev/null | awk 'NR==2{gsub(/%/,""); print $5}' || echo "0")
if [ "${DISK_USE_PCT:-0}" -gt "$DISK_CRIT_PERCENT" ] 2>/dev/null; then
    CRITICAL_FINDINGS+=("[DISK] / 使用率 ${DISK_USE_PCT}%! 超過臨界值 ${DISK_CRIT_PERCENT}%。")
    OVERALL_STATUS="🔴 需注意 - 磁碟空間不足"
elif [ "${DISK_USE_PCT:-0}" -gt "$DISK_WARN_PERCENT" ] 2>/dev/null; then
    WARN_FINDINGS+=("[DISK] / 使用率 ${DISK_USE_PCT}%，接近警告閾值。")
    [ "$OVERALL_STATUS" = "🟢 正常" ] && OVERALL_STATUS="🟡 注意"
fi

echo "[11/13] 可疑檔案掃描..." >&2
echo "" >> "$DETAIL_TMP"; echo "  >> [11/13] 可疑檔案掃描 (Suspicious File Scan)" >> "$DETAIL_TMP"
SCAN_DIRS=("/tmp" "${HOME}/Downloads" "${HOME}/Desktop" "${HOME}/Library/LaunchAgents" "${HOME}")
FIND_EXTS=""
for ext in "${SUSPICIOUS_EXTS[@]}"; do
    [ -n "$FIND_EXTS" ] && FIND_EXTS="${FIND_EXTS} -o"
    FIND_EXTS="${FIND_EXTS} -iname '*.${ext}'"
done
for sdir in "${SCAN_DIRS[@]}"; do
    [ -d "$sdir" ] && run_section "Suspicious in ${sdir}" \
        "find '${sdir}' -maxdepth 3 -type f \\( ${FIND_EXTS} \\) -print 2>/dev/null | head -n 30 || echo '未發現可疑檔案'"
done

echo "[12/13] 日誌摘要..." >&2
echo "" >> "$DETAIL_TMP"; echo "  >> [12/13] 日誌摘要 (Log Summary)" >> "$DETAIL_TMP"
run_section "System Log Errors (last 50)" "log show --last 1h --predicate 'eventType == logEvent && messageType == error' --style compact 2>/dev/null | tail -n 50 || echo 'log 指令不可用'"
run_section "Console Log (last 30)" "tail -n 30 /var/log/system.log 2>/dev/null || echo '/var/log/system.log 不可讀（需管理員）— 已跳過'"
skip_section "Auth Log" "/var/log/authd.log 需要管理員權限" "sudo log show --predicate 'eventMessage contains \"authentication\"' --last 1h"

echo "[13/13] 虛擬化偵測..." >&2
echo "" >> "$DETAIL_TMP"; echo "  >> [13/13] 虛擬化偵測 (Virtualization Detection)" >> "$DETAIL_TMP"
run_section "Hardware Profile" "system_profiler SPHardwareDataType 2>/dev/null | grep -E 'Model|Identifier|Serial|Processor|Memory|Chip' | head -n 15 || echo 'system_profiler 不可用'"
run_section "VM Detection" "
    model=\$(system_profiler SPHardwareDataType 2>/dev/null | awk '/Model Name/{print \$NF}' || echo 'unknown')
    for ind in 'VMware' 'VirtualBox' 'QEMU' 'Parallels' 'Xen' 'HyperKit'; do
        if echo \"\${model}\" | grep -qi \"\${ind}\"; then
            echo \"[VM] 偵測到虛擬化: \${ind}  Model=\${model}\"
            exit 0
        fi
    done
    echo \"[Physical/Unknown] 未偵測到明顯虛擬化指標。Model=\${model}\"
"

# ═══════════════════════════════════════════════════════════════════════════════
#  CIS-LIKE 10 項安全基準檢查（macOS 專屬）
# ═══════════════════════════════════════════════════════════════════════════════
echo "[CIS] 執行安全基準檢查 (macOS)..." >&2

# 1 SIP（System Integrity Protection）
if echo "$SIP_STATUS" | grep -qi "enabled"; then
    add_cis "SIP 狀態" "PASS" "System Integrity Protection enabled" ""
elif [ "$SIP_STATUS" = "N/A" ]; then
    add_cis "SIP 狀態" "SKIPPED" "無法取得（非 Recovery Mode 無法完整確認）" ""
else
    add_cis "SIP 狀態" "FAIL" "${SIP_STATUS}" "管理員: 確認 SIP 未被停用"
    WARN_FINDINGS+=("[SIP] System Integrity Protection 可能未啟用。")
    [ "$OVERALL_STATUS" = "🟢 正常" ] && OVERALL_STATUS="🟡 注意"
fi

# 2 Gatekeeper
if echo "$GATEKEEPER_STATUS" | grep -qi "enabled\|assessments enabled"; then
    add_cis "Gatekeeper" "PASS" "assessments enabled" ""
elif [ "$GATEKEEPER_STATUS" = "N/A" ]; then
    add_cis "Gatekeeper" "SKIPPED" "無法取得" ""
else
    add_cis "Gatekeeper" "FAIL" "${GATEKEEPER_STATUS}" "管理員: sudo spctl --master-enable"
    WARN_FINDINGS+=("[Gatekeeper] 未啟用，可能執行未驗證的應用程式。")
    [ "$OVERALL_STATUS" = "🟢 正常" ] && OVERALL_STATUS="🟡 注意"
fi

# 3 FileVault
if echo "$FILEVAULT_STATUS" | grep -qi "FileVault is On"; then
    add_cis "FileVault 磁碟加密" "PASS" "FileVault is On" ""
elif [ "$FILEVAULT_STATUS" = "N/A" ]; then
    add_cis "FileVault 磁碟加密" "SKIPPED" "無法取得" ""
else
    add_cis "FileVault 磁碟加密" "FAIL" "${FILEVAULT_STATUS}" "建議啟用 FileVault（系統偏好設定 → 安全性與隱私）"
    WARN_FINDINGS+=("[FileVault] 磁碟加密未啟用。")
    [ "$OVERALL_STATUS" = "🟢 正常" ] && OVERALL_STATUS="🟡 注意"
fi

# 4 Application Firewall
if echo "$FW_STATUS" | grep -qi "enabled"; then
    add_cis "Application Firewall" "PASS" "Firewall enabled" ""
elif [ "$FW_STATUS" = "N/A" ]; then
    add_cis "Application Firewall" "SKIPPED" "無法取得" ""
else
    add_cis "Application Firewall" "FAIL" "${FW_STATUS}" "建議啟用防火牆（系統偏好設定 → 安全性與隱私 → 防火牆）"
    WARN_FINDINGS+=("[Firewall] macOS Application Firewall 未啟用。")
    [ "$OVERALL_STATUS" = "🟢 正常" ] && OVERALL_STATUS="🟡 注意"
fi

# 5 危險埠
IFS=',' read -ra DP_ARRAY <<< "$DANGEROUS_PORTS"
FOUND_DANGEROUS=""
for dp in "${DP_ARRAY[@]}"; do
    for op in "${OPEN_PORTS_LIST[@]}"; do
        [ "$op" = "$dp" ] && FOUND_DANGEROUS="${FOUND_DANGEROUS} ${dp}"
    done
done
if [ -n "$FOUND_DANGEROUS" ]; then
    add_cis "不安全公開埠" "FAIL" "偵測到危險埠:${FOUND_DANGEROUS}" "建議管理員關閉或限制防火牆"
    WARN_FINDINGS+=("[PORT] 偵測到可能不安全的埠:${FOUND_DANGEROUS}")
else
    add_cis "不安全公開埠" "PASS" "未偵測到常見危險埠" ""
fi

# 6 記憶體
if [ "${MEM_FREE_MB:-0}" -lt "$MEM_CRIT_MB" ] 2>/dev/null; then
    add_cis "記憶體（近似）" "FAIL" "空閒約 ${MEM_FREE_MB}MiB" "釋放記憶體或增加 RAM"
elif [ "${MEM_FREE_MB:-0}" -lt "$MEM_WARN_MB" ] 2>/dev/null; then
    add_cis "記憶體（近似）" "FAIL" "空閒約 ${MEM_FREE_MB}MiB — 偏低" "考慮釋放記憶體"
else
    add_cis "記憶體（近似）" "PASS" "空閒約 ${MEM_FREE_MB}MiB" ""
fi

# 7 磁碟
if [ "${DISK_USE_PCT:-0}" -gt "$DISK_CRIT_PERCENT" ] 2>/dev/null; then
    add_cis "磁碟使用率" "FAIL" "/ 使用率 ${DISK_USE_PCT}%" "清理磁碟或擴充儲存"
elif [ "${DISK_USE_PCT:-0}" -gt "$DISK_WARN_PERCENT" ] 2>/dev/null; then
    add_cis "磁碟使用率" "FAIL" "/ 使用率 ${DISK_USE_PCT}% — 偏高" "考慮清理磁碟"
else
    add_cis "磁碟使用率" "PASS" "/ 使用率 ${DISK_USE_PCT}%" ""
fi

# 8 家目錄權限
home_perms=$(stat -f '%Lp' "$HOME" 2>/dev/null || echo "unknown")
if [ "$home_perms" = "700" ] || [ "$home_perms" = "750" ]; then
    add_cis "家目錄權限" "PASS" "權限 ${home_perms}" ""
elif [ "$home_perms" = "unknown" ]; then
    add_cis "家目錄權限" "SKIPPED" "無法讀取" ""
else
    add_cis "家目錄權限" "FAIL" "權限 ${home_perms} — 過於開放" "chmod 750 \$HOME"
fi

# 9 使用者 Crontab
user_cron=$(crontab -l 2>/dev/null || echo "")
if [ -z "$user_cron" ]; then
    add_cis "使用者 Crontab" "PASS" "無排程工作" ""
else
    cron_count=$(echo "$user_cron" | grep -cv '^#' || echo "0")
    add_cis "使用者 Crontab" "PASS" "${cron_count} 項排程（請人工 Review）" "確認排程皆為預期"
fi

# 10 程序數量
proc_count=$(ps aux 2>/dev/null | wc -l | tr -d ' ' || echo "0")
if [ "${proc_count:-0}" -gt 500 ] 2>/dev/null; then
    add_cis "程序數量" "FAIL" "共 ${proc_count} 個 — 過多" "檢查不必要程序"
else
    add_cis "程序數量" "PASS" "共 ${proc_count} 個" ""
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  GENERATE 繁體中文摘要表頭 + COMBINE REPORT
# ═══════════════════════════════════════════════════════════════════════════════

CIS_TOTAL=$((CIS_PASS + CIS_FAIL + CIS_SKIP))
CIS_SCORE="${CIS_PASS}/${CIS_TOTAL}"

PORTS_DISPLAY=""
for p in "${OPEN_PORTS_LIST[@]:0:8}"; do
    [ -n "$p" ] && PORTS_DISPLAY="${PORTS_DISPLAY}${p}, "
done
PORTS_DISPLAY="${PORTS_DISPLAY%, }"

{
    echo "================================================================================"
    echo "  SysKit Scanner v${VERSION}  |  系統健檢摘要表"
    echo "================================================================================"
    echo "  [狀態] ${OVERALL_STATUS}"
    echo "  [主機] ${HOST_NAME} (${OS_INFO})"
    echo "  [負載] ${UPTIME_STR} | Load: ${LOAD_AVG} | Users: ${USER_COUNT}"
    echo "  [時間] $(date +'%Y-%m-%d %H:%M:%S')"
    echo "--------------------------------------------------------------------------------"
    echo "  ▶ 關鍵警示 (Critical Findings)"
    if [ ${#CRITICAL_FINDINGS[@]} -eq 0 ] && [ ${#WARN_FINDINGS[@]} -eq 0 ]; then
        echo "    - 無重大發現。"
    fi
    for f in "${CRITICAL_FINDINGS[@]}"; do echo "    - ${f}"; done
    for f in "${WARN_FINDINGS[@]}"; do echo "    - ${f}"; done
    echo ""
    echo "  ▶ 網路與安全 (Network & Security)"
    echo "    - IP: ${PRIVATE_IP} | Public: ${PUBLIC_IP}"
    echo "    - Open Ports: ${PORTS_DISPLAY:-無}"
    echo "    - SIP: ${SIP_STATUS} | Gatekeeper: ${GATEKEEPER_STATUS}"
    echo "    - FileVault: ${FILEVAULT_STATUS} | Firewall: ${FW_STATUS}"
    echo ""
    echo "  ▶ 資源佔用 TOP 3 (Resource Hogs)"
    idx=1
    for tp in "${TOP_PROCS[@]:0:3}"; do echo "    ${idx}. ${tp}"; idx=$((idx + 1)); done
    echo ""
    echo "  ▶ CIS-like 安全基準 (Security Benchmark)"
    echo "    - 通過: ${CIS_PASS} / 未通過: ${CIS_FAIL} / 跳過: ${CIS_SKIP} — 分數: ${CIS_SCORE}"
    echo "--------------------------------------------------------------------------------"
    echo ""
    echo "  ▶ CIS-like 10 項逐項結果"
    idx=1
    for entry in "${CIS_RESULTS[@]}"; do
        IFS='|' read -r cn cs ce ca <<< "$entry"
        icon="✅"; [ "$cs" = "FAIL" ] && icon="❌"; [ "$cs" = "SKIPPED" ] && icon="⏭️"
        echo "    ${idx}. ${icon} ${cn}｜${cs}｜${ce}"
        [ -n "$ca" ] && echo "       建議: ${ca}"
        idx=$((idx + 1))
    done
    if [ ${#SKIPPED_CHECKS[@]} -gt 0 ]; then
        echo ""
        echo "  ▶ 被跳過的檢查（需管理員權限）"
        for sc in "${SKIPPED_CHECKS[@]}"; do echo "    - ${sc}"; done
    fi
    echo ""
    echo "  ▶ 取證指令建議 (Forensic Reference)"
    echo "    非管理員可執行："
    echo "      vm_stat | uptime | lsof -i -P -n | ps aux -m | head | df -h | who"
    echo "    管理員專用（此工具不會執行，僅供參考）："
    echo "      sudo log show --predicate 'eventMessage contains \"authentication failed\"' --last 1h"
    echo "      sudo log show --predicate 'eventType == logEvent && messageType == error' --last 6h"
    echo "      sudo find / -perm +6000 -type f -ls 2>/dev/null"
    echo "      sudo /usr/libexec/ApplicationFirewall/socketfilterfw --listapps"
    echo "      sudo lastb -n 20"
    echo ""
    echo "  ( 完整日誌: ${REPORT_FILE} )"
    echo "  ( JSON 報告: ${JSON_FILE} )"
    echo "================================================================================"
} > "${REPORT_FILE}"

cat "$DETAIL_TMP" >> "${REPORT_FILE}"

{
    echo ""
    echo "================================================================================"
    echo "  掃描完成 : $(date +'%Y-%m-%d %H:%M:%S')"
    echo "  報告存至 : ${REPORT_FILE}"
    echo "================================================================================"
} >> "${REPORT_FILE}"

# ═══════════════════════════════════════════════════════════════════════════════
#  GENERATE JSON
# ═══════════════════════════════════════════════════════════════════════════════

je() { local s="$1"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/\\n}"; s="${s//$'\r'/}"; echo "$s"; }

{
    echo "{"
    echo "  \"host\": \"$(je "$HOST_NAME")\","
    echo "  \"os\": \"$(je "$OS_INFO")\","
    echo "  \"timestamp\": \"$(date -u +'%Y-%m-%dT%H:%M:%SZ')\","
    echo "  \"scanner_version\": \"${VERSION}\","
    echo "  \"overall_status\": \"$(je "$OVERALL_STATUS")\","
    echo "  \"load_avg\": \"${LOAD_AVG}\","
    echo "  \"mem_free_mb\": ${MEM_FREE_MB},"
    echo "  \"disk_use_percent\": ${DISK_USE_PCT},"
    echo "  \"network\": {"
    echo "    \"private_ip\": \"$(je "$PRIVATE_IP")\","
    echo "    \"public_ip\": \"$(je "$PUBLIC_IP")\","
    echo -n "    \"open_ports\": ["
    f=true; for p in "${OPEN_PORTS_LIST[@]}"; do [ -n "$p" ] || continue; $f || echo -n ","; echo -n "${p}"; f=false; done
    echo "]"
    echo "  },"
    echo -n "  \"critical_findings\": ["; f=true; for x in "${CRITICAL_FINDINGS[@]}"; do $f || echo -n ","; echo -n "\"$(je "$x")\""; f=false; done; echo "],"
    echo -n "  \"warn_findings\": ["; f=true; for x in "${WARN_FINDINGS[@]}"; do $f || echo -n ","; echo -n "\"$(je "$x")\""; f=false; done; echo "],"
    echo "  \"cis_score\": {\"passed\":${CIS_PASS},\"failed\":${CIS_FAIL},\"skipped\":${CIS_SKIP},\"total\":${CIS_TOTAL}},"
    echo "  \"cis_checks\": ["
    f=true
    for entry in "${CIS_RESULTS[@]}"; do
        IFS='|' read -r cn cs ce ca <<< "$entry"
        $f || echo ","
        echo -n "    {\"name\":\"$(je "$cn")\",\"status\":\"${cs}\",\"evidence\":\"$(je "$ce")\",\"advice\":\"$(je "$ca")\"}"
        f=false
    done
    echo ""
    echo "  ],"
    echo -n "  \"skipped_checks\": ["; f=true; for x in "${SKIPPED_CHECKS[@]}"; do $f || echo -n ","; echo -n "\"$(je "$x")\""; f=false; done; echo "],"
    echo "  \"sip\": \"$(je "$SIP_STATUS")\","
    echo "  \"gatekeeper\": \"$(je "$GATEKEEPER_STATUS")\","
    echo "  \"filevault\": \"$(je "$FILEVAULT_STATUS")\","
    echo "  \"firewall\": \"$(je "$FW_STATUS")\","
    echo "  \"full_log_path\": \"$(je "$REPORT_FILE")\""
    echo "}"
} > "${JSON_FILE}"

echo ""
echo "[+] 掃描完成！"
echo "    報告: ${REPORT_FILE}"
echo "    JSON: ${JSON_FILE}"
echo ""
