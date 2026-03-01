<#
.SYNOPSIS
    SysKit Scanner v2.0 — Windows PowerShell Edition (Non-Elevated, Safe Mode)
.DESCRIPTION
    - 絕不使用管理員權限或提權指令。
    - 所有命令皆為唯讀 (READ-ONLY)，不會修改系統。
    - 報告以繁體中文摘要表頭開頭 (UTF-8)。
    - 包含 CIS-like 10 項安全基準檢查與計分。
    - 同時產出 TXT 與 JSON 報告。
#>

#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ─── Constants ───────────────────────────────────────────────────────────────
$SCRIPT_VERSION  = "2.0.0"
$CMD_TIMEOUT_SEC = 10
$MAX_LINES       = 60
$TIMESTAMP       = Get-Date -Format "yyyyMMdd_HHmmss"
$REPORT_DIR      = Join-Path $PSScriptRoot "reports"
$REPORT_FILE     = Join-Path $REPORT_DIR "syskit_report_${TIMESTAMP}.txt"
$JSON_FILE       = Join-Path $REPORT_DIR "syskit_report_${TIMESTAMP}.json"

$SUSPICIOUS_EXTS = @(
    "*.hta","*.scr","*.pif","*.wsf","*.vbe","*.vbs","*.jse",
    "*.gadget","*.url","*.docm","*.xlsm","*.reg"
)

$MASK_PATTERNS = @("password\s*=", "pwd\s*=", "secret\s*=", "token\s*=", "apikey\s*=")

# ─── Load Thresholds ────────────────────────────────────────────────────────
$MEM_WARN_MB       = 300
$MEM_CRIT_MB       = 100
$DISK_WARN_PERCENT = 80
$DISK_CRIT_PERCENT = 90
$DANGEROUS_PORTS   = @(21,23,25,69,111,135,139,445,514,631,1433,1434,3306,3389,5432,5900,6379,8080,9200,27017)

$confPath = Join-Path $PSScriptRoot "config\thresholds.conf"
if (Test-Path $confPath) {
    Get-Content $confPath | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith('#')) {
            $parts = $line -split '=', 2
            if ($parts.Count -eq 2) {
                $k = $parts[0].Trim(); $v = $parts[1].Trim()
                switch ($k) {
                    'MEM_WARN_MB'       { $MEM_WARN_MB       = [int]$v }
                    'MEM_CRIT_MB'       { $MEM_CRIT_MB       = [int]$v }
                    'DISK_WARN_PERCENT' { $DISK_WARN_PERCENT = [int]$v }
                    'DISK_CRIT_PERCENT' { $DISK_CRIT_PERCENT = [int]$v }
                    'DANGEROUS_PORTS'   { $DANGEROUS_PORTS   = ($v -split ',') | ForEach-Object { [int]$_.Trim() } }
                }
            }
        }
    }
}

# ─── Collectors ──────────────────────────────────────────────────────────────
$CriticalFindings = [System.Collections.ArrayList]::new()
$WarnFindings     = [System.Collections.ArrayList]::new()
$SkippedChecks    = [System.Collections.ArrayList]::new()
$CisResults       = [System.Collections.ArrayList]::new()
$CisPass = 0; $CisFail = 0; $CisSkip = 0
$OverallStatus    = "🟢 正常"

# ─── Helpers ─────────────────────────────────────────────────────────────────

function Mask-Sensitive {
    param([string]$Text)
    foreach ($p in $MASK_PATTERNS) {
        $Text = [regex]::Replace($Text, "(?i)($p)[^\s;`"']+", '$1****')
    }
    return $Text
}

function Run-SafeCommand {
    param(
        [string]$Label,
        [scriptblock]$Command,
        [int]$MaxLines = $MAX_LINES,
        [int]$Timeout  = $CMD_TIMEOUT_SEC
    )
    $section  = "`n`n"
    $section += "----------------------------------------------------------------`n"
    $section += "  [$Label]`n"
    $section += "  Time: $(Get-Date -Format 'HH:mm:ss')`n"
    $section += "----------------------------------------------------------------`n"
    try {
        $job = Start-Job -ScriptBlock $Command
        $finished = $job | Wait-Job -Timeout $Timeout
        if ($null -eq $finished) {
            $job | Stop-Job -ErrorAction SilentlyContinue
            $job | Remove-Job -Force -ErrorAction SilentlyContinue
            $section += "  [TIMEOUT] 指令未能在 ${Timeout}s 內完成 — 已跳過。`n"
        } else {
            $raw = $job | Receive-Job 2>&1 | Out-String
            $job | Remove-Job -Force -ErrorAction SilentlyContinue
            $raw = Mask-Sensitive -Text $raw
            $lines = $raw -split "`n"
            if ($lines.Count -gt $MaxLines) {
                $section += ($lines[0..($MaxLines - 1)] -join "`n") + "`n"
                $section += "  ... (已截斷，顯示前 $MaxLines / 共 $($lines.Count) 行)`n"
            } else {
                $section += $raw + "`n"
            }
        }
    } catch {
        $section += "  [ERROR] $($_.Exception.Message)`n"
    }
    return $section
}

function Run-DirectCommand {
    param(
        [string]$Label,
        [scriptblock]$Command,
        [int]$MaxLines = $MAX_LINES
    )
    $section  = "`n`n"
    $section += "----------------------------------------------------------------`n"
    $section += "  [$Label]`n"
    $section += "  Time: $(Get-Date -Format 'HH:mm:ss')`n"
    $section += "----------------------------------------------------------------`n"
    try {
        $raw = & $Command 2>&1 | Out-String
        $raw = Mask-Sensitive -Text $raw
        $lines = $raw -split "`n"
        if ($lines.Count -gt $MaxLines) {
            $section += ($lines[0..($MaxLines - 1)] -join "`n") + "`n"
            $section += "  ... (已截斷，顯示前 $MaxLines / 共 $($lines.Count) 行)`n"
        } else {
            $section += $raw + "`n"
        }
    } catch {
        $section += "  [ERROR] $($_.Exception.Message)`n"
    }
    return $section
}

function Skip-Section {
    param([string]$Label, [string]$Reason, [string]$AdminCmd)
    $section  = "`n`n"
    $section += "----------------------------------------------------------------`n"
    $section += "  [$Label]`n"
    $section += "  [SKIPPED] $Reason`n"
    $section += "  建議由管理員執行：`n"
    $section += "    $AdminCmd`n"
    $section += "----------------------------------------------------------------`n"
    $null = $SkippedChecks.Add($Label)
    return $section
}

function Add-Cis {
    param([string]$Name, [string]$Status, [string]$Evidence, [string]$Advice)
    $null = $CisResults.Add([PSCustomObject]@{name=$Name;status=$Status;evidence=$Evidence;advice=$Advice})
    switch ($Status) {
        'PASS'    { $script:CisPass++ }
        'FAIL'    { $script:CisFail++ }
        'SKIPPED' { $script:CisSkip++ }
    }
}

# ─── Pre-flight ──────────────────────────────────────────────────────────────

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] 此工具禁止以管理員身分執行。請以一般使用者執行。" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SysKit Scanner v$SCRIPT_VERSION - Windows" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "[*] 所有指令皆為唯讀，不使用管理員權限。"
Write-Host "[*] 報告: $REPORT_FILE"
Write-Host "[*] JSON: $JSON_FILE"
Write-Host ""

if (-not (Test-Path $REPORT_DIR)) {
    New-Item -ItemType Directory -Path $REPORT_DIR -Force | Out-Null
}

$detailReport = ""

# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION SCANS
# ═══════════════════════════════════════════════════════════════════════════════

# ─── 1. System Information ───────────────────────────────────────────────────
Write-Host "[1/12] 系統資訊..." -ForegroundColor Yellow

$detailReport += "`n  >> [1/12] 系統資訊 (System Information)`n"

$osObj = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$csObj = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue

$hostName   = $env:COMPUTERNAME
$osCaption  = if ($osObj) { $osObj.Caption } else { "Windows" }
$osVersion  = if ($osObj) { $osObj.Version } else { "N/A" }
$uptime     = if ($osObj) { ((Get-Date) - $osObj.LastBootUpTime).ToString("d' days 'hh\:mm\:ss") } else { "N/A" }
$totalMemMB = if ($csObj) { [math]::Round($csObj.TotalPhysicalMemory / 1MB) } else { 0 }

$detailReport += Run-DirectCommand -Label "OS & Build" -Command {
    Get-CimInstance Win32_OperatingSystem |
        Select-Object Caption, Version, BuildNumber, OSArchitecture, LastBootUpTime |
        Format-List
}

$detailReport += Run-DirectCommand -Label "Computer System" -Command {
    Get-CimInstance Win32_ComputerSystem |
        Select-Object Name, Domain, Manufacturer, Model, TotalPhysicalMemory |
        Format-List
}

$detailReport += Run-DirectCommand -Label "BIOS / Firmware" -Command {
    Get-CimInstance Win32_BIOS |
        Select-Object Manufacturer, SMBIOSBIOSVersion, ReleaseDate |
        Format-List
}

# Memory metrics
$freeMemMB = 0
try {
    $perfOS = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $freeMemMB = [math]::Round($perfOS.FreePhysicalMemory / 1024)  # KB -> MB
} catch { $freeMemMB = 0 }

if ($freeMemMB -lt $MEM_CRIT_MB) {
    $null = $CriticalFindings.Add("[RAM] 剩餘 ${freeMemMB}MiB! 低於臨界值 ${MEM_CRIT_MB}MiB。")
    $OverallStatus = "🔴 需注意 - 記憶體不足"
} elseif ($freeMemMB -lt $MEM_WARN_MB) {
    $null = $WarnFindings.Add("[RAM] 剩餘 ${freeMemMB}MiB，接近警告閾值。")
    if ($OverallStatus -eq "🟢 正常") { $OverallStatus = "🟡 注意" }
}

# ─── 2. Network Configuration ───────────────────────────────────────────────
Write-Host "[2/12] 網路設定..." -ForegroundColor Yellow
$detailReport += "`n  >> [2/12] 網路設定 (Network Configuration)`n"

$detailReport += Run-DirectCommand -Label "IP Configuration" -Command {
    Get-NetIPConfiguration -ErrorAction SilentlyContinue | Format-List
}
$detailReport += Run-DirectCommand -Label "Routing Table" -Command {
    Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Select-Object DestinationPrefix, NextHop, RouteMetric, InterfaceAlias |
        Format-Table -AutoSize
}
$detailReport += Run-DirectCommand -Label "DNS Client Settings" -Command {
    Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Select-Object InterfaceAlias, ServerAddresses |
        Format-Table -AutoSize
}

$privateIP = "N/A"
try {
    $iface = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown' } | Select-Object -First 1
    if ($iface) { $privateIP = $iface.IPAddress }
} catch {}

# ─── 3. Network Connectivity ────────────────────────────────────────────────
Write-Host "[3/12] 網路連線測試..." -ForegroundColor Yellow
$detailReport += "`n  >> [3/12] 網路連線 (Network Connectivity)`n"

$detailReport += Run-SafeCommand -Label "Ping 8.8.8.8" -Command {
    Test-NetConnection -ComputerName 8.8.8.8 -InformationLevel Detailed
}
$detailReport += Run-SafeCommand -Label "DNS Resolution (google.com)" -Command {
    Resolve-DnsName google.com -Type A -ErrorAction Stop | Format-Table
}

$publicIP = "N/A"
try { $publicIP = (Invoke-RestMethod -Uri "https://ifconfig.co/ip" -TimeoutSec 5).Trim() } catch {}
$detailReport += "`n  [Public IP] $publicIP`n"

$detailReport += Run-SafeCommand -Label "Traceroute to 8.8.8.8 (max 10 hops)" -Command {
    Test-NetConnection -ComputerName 8.8.8.8 -TraceRoute -InformationLevel Detailed |
        Select-Object -ExpandProperty TraceRoute
}

# ─── 4. Listening & Connections ──────────────────────────────────────────────
Write-Host "[4/12] 連線與監聽埠..." -ForegroundColor Yellow
$detailReport += "`n  >> [4/12] 連線與監聽 (Connections & Listening)`n"

$listenPorts = @()
try {
    $tcpListen = Get-NetTCPConnection -State Listen -ErrorAction Stop
    $listenPorts = $tcpListen.LocalPort | Sort-Object -Unique
} catch {
    $null = $SkippedChecks.Add("TCP Listen Ports (Get-NetTCPConnection)")
}

$detailReport += Run-DirectCommand -Label "TCP Listening Ports" -Command {
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort, OwningProcess |
        Sort-Object LocalPort | Format-Table -AutoSize
}
$detailReport += Run-DirectCommand -Label "Established TCP" -Command {
    Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess |
        Sort-Object RemoteAddress | Format-Table -AutoSize
}
$detailReport += Run-DirectCommand -Label "UDP Endpoints" -Command {
    Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort, OwningProcess |
        Sort-Object LocalPort | Format-Table -AutoSize
}

# ─── 5. Process Inspection ───────────────────────────────────────────────────
Write-Host "[5/12] 程序檢查..." -ForegroundColor Yellow
$detailReport += "`n  >> [5/12] 程序檢查 (Process Inspection)`n"

$detailReport += Run-DirectCommand -Label "Top 25 Processes by Memory" -Command {
    Get-Process | Sort-Object -Descending WorkingSet64 | Select-Object -First 25 Id, ProcessName,
        @{N='WS(MB)';E={[math]::Round($_.WorkingSet64/1MB,1)}},
        @{N='CPU(s)';E={[math]::Round($_.CPU,2)}} |
        Format-Table -AutoSize
}

$topProcs = @()
try {
    $topProcs = Get-Process -ErrorAction Stop | Sort-Object -Descending WorkingSet64 | Select-Object -First 3 |
        ForEach-Object { "$($_.ProcessName) ($([math]::Round($_.WorkingSet64/1MB,1))MB MEM)" }
} catch {}

$detailReport += Run-DirectCommand -Label "Processes with Network" -Command {
    $pids = (Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue).OwningProcess | Sort-Object -Unique
    Get-Process -Id $pids -ErrorAction SilentlyContinue |
        Select-Object Id, ProcessName, Path | Format-Table -AutoSize
}

# ─── 6. Startup & Services ──────────────────────────────────────────────────
Write-Host "[6/12] 啟動項目與服務..." -ForegroundColor Yellow
$detailReport += "`n  >> [6/12] 啟動與服務 (Startup & Services)`n"

$detailReport += Run-DirectCommand -Label "Auto-Start Services" -Command {
    # some services can only be queried by administrators; avoid noisy errors
    Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.StartType -eq 'Automatic' } |
        Select-Object Name, DisplayName, Status | Sort-Object Status -Descending |
        Format-Table -AutoSize
}
$detailReport += Run-DirectCommand -Label "Startup Commands (CIM)" -Command {
    Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue |
        Select-Object Name, Command, Location, User | Format-Table -AutoSize
}
$detailReport += Run-DirectCommand -Label "Scheduled Tasks (non-Microsoft)" -Command {
    Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.TaskPath -notlike "\Microsoft\*" -and $_.State -ne "Disabled" } |
        Select-Object TaskName, TaskPath, State | Format-Table -AutoSize
} -MaxLines 80

# ─── 7. User Accounts ───────────────────────────────────────────────────────
Write-Host "[7/12] 使用者帳號..." -ForegroundColor Yellow
$detailReport += "`n  >> [7/12] 使用者帳號 (User Accounts)`n"

$detailReport += Run-DirectCommand -Label "Local User Accounts" -Command {
    Get-LocalUser -ErrorAction SilentlyContinue |
        Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet |
        Format-Table -AutoSize
}

# Security event log requires admin → SKIPPED
$detailReport += Skip-Section -Label "Security Log (Logon Events)" `
    -Reason "Security 事件記錄需要管理員權限" `
    -AdminCmd "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 50"

# ─── 8. Firewall ────────────────────────────────────────────────────────────
Write-Host "[8/12] 防火牆..." -ForegroundColor Yellow
$detailReport += "`n  >> [8/12] 防火牆 (Firewall)`n"

$fwProfiles = $null
try {
    $fwProfiles = Get-NetFirewallProfile -ErrorAction Stop
    $detailReport += Run-DirectCommand -Label "Firewall Profiles" -Command {
        Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction |
            Format-Table -AutoSize
    }
} catch {
    $detailReport += "  [SKIPPED] 防火牆設定檔讀取失敗。`n"
    $null = $SkippedChecks.Add("Firewall Profiles")
}

$detailReport += Run-DirectCommand -Label "Inbound Allow Rules (Enabled)" -Command {
    Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue |
        Select-Object -First 40 DisplayName, Profile, Direction, Action |
        Format-Table -AutoSize
}

# ─── 9. Disk & Storage ──────────────────────────────────────────────────────
Write-Host "[9/12] 磁碟..." -ForegroundColor Yellow
$detailReport += "`n  >> [9/12] 磁碟與儲存 (Disk & Storage)`n"

$detailReport += Run-DirectCommand -Label "Disk Volumes" -Command {
    Get-Volume -ErrorAction SilentlyContinue |
        Where-Object { $_.DriveLetter } |
        Select-Object DriveLetter, FileSystemLabel, FileSystem, SizeRemaining, Size |
        Format-Table -AutoSize
}
$detailReport += Run-DirectCommand -Label "Disk Space Summary" -Command {
    Get-PSDrive -PSProvider FileSystem |
        Select-Object Name, Used, Free,
            @{N='Total(GB)';E={[math]::Round(($_.Used + $_.Free) / 1GB, 2)}},
            @{N='Free(GB)';E={[math]::Round($_.Free / 1GB, 2)}} |
        Format-Table -AutoSize
}

# Disk metrics for C:
$diskUsePct = 0
try {
    $cDrive = Get-PSDrive C -ErrorAction Stop
    $total = $cDrive.Used + $cDrive.Free
    if ($total -gt 0) { $diskUsePct = [math]::Round($cDrive.Used / $total * 100) }
} catch {}

if ($diskUsePct -gt $DISK_CRIT_PERCENT) {
    $null = $CriticalFindings.Add("[DISK] C: 使用率 ${diskUsePct}%! 超過臨界值 ${DISK_CRIT_PERCENT}%。")
    $OverallStatus = "🔴 需注意 - 磁碟空間不足"
} elseif ($diskUsePct -gt $DISK_WARN_PERCENT) {
    $null = $WarnFindings.Add("[DISK] C: 使用率 ${diskUsePct}%，接近警告閾值。")
    if ($OverallStatus -eq "🟢 正常") { $OverallStatus = "🟡 注意" }
}

# ─── 10. Suspicious File Scan ───────────────────────────────────────────────
Write-Host "[10/12] 可疑檔案掃描..." -ForegroundColor Yellow
$detailReport += "`n  >> [10/12] 可疑檔案掃描 (Suspicious File Scan)`n"

$detailReport += Run-DirectCommand -Label "Suspicious Files" -Command {
    $results = @()
    foreach ($dir in @( $env:TEMP, "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop",
                        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" )) {
        if (Test-Path $dir) {
            foreach ($ext in @("*.hta","*.scr","*.pif","*.wsf","*.vbe","*.vbs","*.jse","*.gadget","*.url","*.docm","*.xlsm","*.reg")) {
                $found = Get-ChildItem -Path $dir -Filter $ext -Recurse -ErrorAction SilentlyContinue -Force
                foreach ($f in $found) {
                    $results += [PSCustomObject]@{
                        Dir=$dir; Name=$f.Name; Ext=$f.Extension;
                        SizeKB=[math]::Round($f.Length/1KB,2); Modified=$f.LastWriteTime; Path=$f.FullName
                    }
                }
            }
        }
    }
    if ($results.Count -gt 0) {
        "  [!] 發現 $($results.Count) 個可疑檔案：`n"
        $results | Format-Table -AutoSize
    } else {
        "  [OK] 未發現可疑檔案。"
    }
}

$detailReport += Run-DirectCommand -Label "Suspicious Process Names" -Command {
    $patterns = @("svch0st","scvhost","svchos t","lssas","lsas s","explore.exe","explor3r","taskmgr32","winlogln","dllhst","spoolsrv")
    $procs = Get-Process -ErrorAction SilentlyContinue
    $hits = @()
    foreach ($p in $procs) {
        foreach ($pat in $patterns) {
            if ($p.ProcessName -like "*$pat*") {
                $hits += [PSCustomObject]@{PID=$p.Id;Name=$p.ProcessName;Path=$p.Path}
            }
        }
    }
    if ($hits.Count -gt 0) {
        "  [!] 發現 $($hits.Count) 個可疑程序名稱：`n"; $hits | Format-Table -AutoSize
    } else {
        "  [OK] 未偵測到明顯可疑的程序名稱。"
    }
}

# ─── 11. Event Log Summary ──────────────────────────────────────────────────
Write-Host "[11/12] 事件日誌摘要..." -ForegroundColor Yellow
$detailReport += "`n  >> [11/12] 事件日誌摘要 (Event Log Summary)`n"

$detailReport += Run-SafeCommand -Label "System Log — Errors (last 30)" -Command {
    Get-WinEvent -FilterHashtable @{LogName='System'; Level=2} -MaxEvents 30 -ErrorAction Stop |
        Select-Object TimeCreated, Id, ProviderName, Message | Format-Table -Wrap -AutoSize
}
$detailReport += Run-SafeCommand -Label "Application Log — Errors (last 30)" -Command {
    Get-WinEvent -FilterHashtable @{LogName='Application'; Level=2} -MaxEvents 30 -ErrorAction Stop |
        Select-Object TimeCreated, Id, ProviderName, Message | Format-Table -Wrap -AutoSize
}

# ─── 12. VM Detection ───────────────────────────────────────────────────────
Write-Host "[12/12] 虛擬化偵測..." -ForegroundColor Yellow
$detailReport += "`n  >> [12/12] 虛擬化偵測 (Virtualization Detection)`n"

$detailReport += Run-DirectCommand -Label "VM Detection" -Command {
    $cs = Get-CimInstance Win32_ComputerSystem; $bios = Get-CimInstance Win32_BIOS
    $model = $cs.Model; $mfg = $cs.Manufacturer; $biosVer = $bios.SMBIOSBIOSVersion
    $vmInds = @("Virtual","VMware","VirtualBox","Hyper-V","QEMU","Xen","KVM","Parallels")
    $detected = $false
    foreach ($ind in $vmInds) {
        if ("$model $mfg $biosVer" -match $ind) {
            "  [VM] 偵測到虛擬化: $ind"; "       Model=$model  Manufacturer=$mfg  BIOS=$biosVer"
            $detected = $true; break
        }
    }
    if (-not $detected) {
        "  [Physical] 未偵測到虛擬化指標。"; "       Model=$model  Manufacturer=$mfg  BIOS=$biosVer"
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
#  CIS-LIKE 10 項安全基準檢查
# ═══════════════════════════════════════════════════════════════════════════════
Write-Host "[CIS] 執行安全基準檢查..." -ForegroundColor Yellow

# 1 RDP/遠端埠
$rdpOpen = $listenPorts -contains 3389
if ($rdpOpen) {
    Add-Cis "RDP 監聽 (3389)" "FAIL" "Port 3389 LISTEN" "建議管理員確認 RDP 是否應開放"
    $null = $WarnFindings.Add("[PORT] RDP (3389) 正在監聽。")
} else {
    Add-Cis "RDP 監聽 (3389)" "PASS" "Port 3389 未監聽" ""
}

# 2 危險埠
$foundDangerous = @()
foreach ($dp in $DANGEROUS_PORTS) {
    if ($listenPorts -contains $dp) { $foundDangerous += $dp }
}
if ($foundDangerous.Count -gt 0) {
    Add-Cis "不安全公開埠" "FAIL" "偵測到: $($foundDangerous -join ', ')" "建議管理員關閉或限制"
    $null = $WarnFindings.Add("[PORT] 偵測到可能不安全的埠: $($foundDangerous -join ', ')")
} else {
    Add-Cis "不安全公開埠" "PASS" "未偵測到常見危險埠" ""
}

# 3 記憶體
if ($freeMemMB -lt $MEM_CRIT_MB) {
    Add-Cis "記憶體使用" "FAIL" "剩餘 ${freeMemMB}MiB" "釋放記憶體或增加 RAM"
} elseif ($freeMemMB -lt $MEM_WARN_MB) {
    Add-Cis "記憶體使用" "FAIL" "剩餘 ${freeMemMB}MiB — 偏低" "考慮釋放記憶體"
} else {
    Add-Cis "記憶體使用" "PASS" "剩餘 ${freeMemMB}MiB" ""
}

# 4 磁碟
if ($diskUsePct -gt $DISK_CRIT_PERCENT) {
    Add-Cis "磁碟使用率 (C:)" "FAIL" "使用率 ${diskUsePct}%" "清理磁碟"
} elseif ($diskUsePct -gt $DISK_WARN_PERCENT) {
    Add-Cis "磁碟使用率 (C:)" "FAIL" "使用率 ${diskUsePct}% — 偏高" "考慮清理磁碟"
} else {
    Add-Cis "磁碟使用率 (C:)" "PASS" "使用率 ${diskUsePct}%" ""
}

# 5 防火牆
$fwAllEnabled = $true
if ($fwProfiles) {
    foreach ($p in $fwProfiles) { if (-not $p.Enabled) { $fwAllEnabled = $false } }
    if ($fwAllEnabled) {
        Add-Cis "防火牆狀態" "PASS" "所有設定檔已啟用" ""
    } else {
        Add-Cis "防火牆狀態" "FAIL" "部分設定檔未啟用" "管理員: 啟用所有防火牆設定檔"
    }
} else {
    Add-Cis "防火牆狀態" "SKIPPED" "無法讀取" ""
}

# 6 Windows Defender
$defenderStatus = "N/A"
try {
    $mpStatus = Get-MpComputerStatus -ErrorAction Stop
    if ($mpStatus.RealTimeProtectionEnabled) {
        Add-Cis "Windows Defender" "PASS" "即時保護已啟用" ""
        $defenderStatus = "Enabled"
    } else {
        Add-Cis "Windows Defender" "FAIL" "即時保護未啟用" "管理員: 啟用 Windows Defender"
        $defenderStatus = "Disabled"
    }
} catch {
    Add-Cis "Windows Defender" "SKIPPED" "無法讀取 Defender 狀態" ""
}

# 7 自動啟動服務數量
$autoSvcCount = 0
# run as non-admin will trigger "PermissionDenied" warnings for some protected services
# the count is still gathered but errors are suppressed here to keep the report clean
try { $autoSvcCount = (Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.StartType -eq 'Automatic' }).Count } catch {}
if ($autoSvcCount -gt 100) {
    Add-Cis "自動啟動服務" "FAIL" "共 ${autoSvcCount} 個 — 偏多" "檢查不必要的自動啟動服務"
} else {
    Add-Cis "自動啟動服務" "PASS" "共 ${autoSvcCount} 個" ""
}

# 8 可疑啟動項
$startupItems = @()
try { $startupItems = Get-CimInstance Win32_StartupCommand -ErrorAction Stop } catch {}
if ($startupItems.Count -gt 10) {
    Add-Cis "啟動項目數量" "FAIL" "共 $($startupItems.Count) 項 — 請人工檢查" "Review 不明啟動項"
} else {
    Add-Cis "啟動項目數量" "PASS" "共 $($startupItems.Count) 項" ""
}

# 9 Guest 帳戶
$guestEnabled = $false
try { $guest = Get-LocalUser -Name "Guest" -ErrorAction Stop; $guestEnabled = $guest.Enabled } catch {}
if ($guestEnabled) {
    Add-Cis "Guest 帳戶" "FAIL" "Guest 已啟用" "管理員: Disable-LocalUser -Name Guest"
} else {
    Add-Cis "Guest 帳戶" "PASS" "Guest 已停用或不存在" ""
}

# 10 程序數量
$procCount = (Get-Process -ErrorAction SilentlyContinue).Count
if ($procCount -gt 300) {
    Add-Cis "程序數量" "FAIL" "共 ${procCount} 個 — 過多" "檢查不必要程序"
} else {
    Add-Cis "程序數量" "PASS" "共 ${procCount} 個" ""
}

# ═══════════════════════════════════════════════════════════════════════════════
#  GENERATE 繁體中文摘要表頭
# ═══════════════════════════════════════════════════════════════════════════════

$cisTotal = $CisPass + $CisFail + $CisSkip
$cisScore = "${CisPass}/${cisTotal}"

$portsDisplay = if ($listenPorts.Count -gt 0) { ($listenPorts | Select-Object -First 8) -join ", " } else { "無" }

$summary = @"
================================================================================
  SysKit Scanner v$SCRIPT_VERSION  |  系統健檢摘要表
================================================================================
  [狀態] $OverallStatus
  [主機] $hostName ($osCaption)
  [負載] Uptime: $uptime | Processes: $procCount
  [時間] $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
--------------------------------------------------------------------------------
  ▶ 關鍵警示 (Critical Findings)
"@

if ($CriticalFindings.Count -eq 0 -and $WarnFindings.Count -eq 0) {
    $summary += "    - 無重大發現。`n"
}
foreach ($f in $CriticalFindings) { $summary += "    - $f`n" }
foreach ($f in $WarnFindings) { $summary += "    - $f`n" }

$summary += @"

  ▶ 網路與安全 (Network & Security)
    - IP: $privateIP | Public: $publicIP
    - Open Ports: $portsDisplay
    - Defender: $defenderStatus

  ▶ 資源佔用 TOP 3 (Resource Hogs)
"@

$idx = 1
foreach ($tp in $topProcs) { $summary += "    ${idx}. $tp`n"; $idx++ }

$summary += @"

  ▶ CIS-like 安全基準 (Security Benchmark)
    - 通過: $CisPass / 未通過: $CisFail / 跳過: $CisSkip — 分數: $cisScore
--------------------------------------------------------------------------------

  ▶ CIS-like 10 項逐項結果
"@

$idx = 1
foreach ($c in $CisResults) {
    $icon = switch ($c.status) { 'PASS' { '✅' } 'FAIL' { '❌' } 'SKIPPED' { '⏭️' } default { '❓' } }
    $summary += "    ${idx}. $icon $($c.name)｜$($c.status)｜$($c.evidence)`n"
    if ($c.advice) { $summary += "       建議: $($c.advice)`n" }
    $idx++
}

if ($SkippedChecks.Count -gt 0) {
    $summary += "`n  ▶ 被跳過的檢查（需管理員權限）`n"
    foreach ($sc in $SkippedChecks) { $summary += "    - $sc`n" }
}

$summary += @"

  ▶ 取證指令建議 (Forensic Reference)
    非管理員可執行：
      Get-Process | Sort WS -Desc | Select -First 10
      Get-NetTCPConnection -State Listen
      Get-Service | Where Status -eq Running
    管理員專用（此工具不會執行，僅供參考）：
      Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 50
      Get-MpThreatDetection
      netsh advfirewall show allprofiles

  ( 完整日誌: $REPORT_FILE )
  ( JSON 報告: $JSON_FILE )
================================================================================
"@

# ═══════════════════════════════════════════════════════════════════════════════
#  COMBINE & WRITE REPORT (UTF-8)
# ═══════════════════════════════════════════════════════════════════════════════

$fullReport = $summary + $detailReport

$fullReport += @"

================================================================================
  掃描完成 : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  報告存至 : $REPORT_FILE
================================================================================
"@

[System.IO.File]::WriteAllText($REPORT_FILE, $fullReport, [System.Text.UTF8Encoding]::new($false))

# ═══════════════════════════════════════════════════════════════════════════════
#  GENERATE JSON
# ═══════════════════════════════════════════════════════════════════════════════

$jsonObj = [ordered]@{
    host             = $hostName
    os               = $osCaption
    timestamp        = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
    scanner_version  = $SCRIPT_VERSION
    overall_status   = $OverallStatus
    mem_free_mb      = $freeMemMB
    disk_use_percent = $diskUsePct
    network          = [ordered]@{
        private_ip = $privateIP
        public_ip  = $publicIP
        open_ports = @($listenPorts | Select-Object -First 20)
    }
    critical_findings = @($CriticalFindings)
    warn_findings     = @($WarnFindings)
    cis_score         = [ordered]@{ passed=$CisPass; failed=$CisFail; skipped=$CisSkip; total=$cisTotal }
    cis_checks        = @($CisResults | ForEach-Object {
        [ordered]@{ name=$_.name; status=$_.status; evidence=$_.evidence; advice=$_.advice }
    })
    skipped_checks   = @($SkippedChecks)
    defender         = $defenderStatus
    full_log_path    = $REPORT_FILE
}

$jsonText = $jsonObj | ConvertTo-Json -Depth 5
[System.IO.File]::WriteAllText($JSON_FILE, $jsonText, [System.Text.UTF8Encoding]::new($false))

Write-Host ""
Write-Host "[+] 掃描完成！" -ForegroundColor Green
Write-Host "    報告: $REPORT_FILE" -ForegroundColor Green
Write-Host "    JSON: $JSON_FILE" -ForegroundColor Green
Write-Host ""
