<#
.SYNOPSIS
    SysKit Scanner - Windows PowerShell Edition (Non-Elevated, Safe Mode)
.DESCRIPTION
    Collects read-only system diagnostics: network, processes, services,
    startup items, firewall status, disk usage, suspicious files, and more.
    Outputs a human-readable TXT report to ./reports/.
.NOTES
    - Runs WITHOUT administrator privileges.
    - All commands are read-only; nothing is modified.
    - Dangerous/destructive commands are explicitly forbidden.
    - Deprecated tools (wmic, netstat) are avoided.
#>

#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ─── Constants ───────────────────────────────────────────────────────────────
$SCRIPT_VERSION  = "1.0.0"
$CMD_TIMEOUT_SEC = 10
$MAX_LINES       = 60
$TIMESTAMP       = Get-Date -Format "yyyyMMdd_HHmmss"
$REPORT_DIR      = Join-Path $PSScriptRoot "reports"
$REPORT_FILE     = Join-Path $REPORT_DIR "syskit_report_${TIMESTAMP}.txt"

# Suspicious file extensions commonly abused by malware
$SUSPICIOUS_EXTS = @(
    "*.hta","*.scr","*.pif","*.wsf","*.vbe","*.vbs","*.jse",
    "*.gadget","*.url","*.docm","*.xlsm","*.lnk","*.bat","*.cmd",
    "*.ps1","*.reg"
)

# Directories to scan for suspicious files (non-elevated accessible)
$SCAN_DIRS = @(
    "$env:TEMP",
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Desktop",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
)

# Sensitive patterns to mask in output
$MASK_PATTERNS = @("password\s*=", "pwd\s*=", "secret\s*=", "token\s*=", "apikey\s*=")

# ─── Helpers ─────────────────────────────────────────────────────────────────

function Write-Banner {
    $banner = @"
================================================================================
  SysKit Scanner v$SCRIPT_VERSION  |  Windows PowerShell (Non-Elevated Safe Mode)
  Scan started : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
  Hostname     : $env:COMPUTERNAME
  User         : $env:USERNAME
================================================================================
"@
    return $banner
}

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
            $section += "  [TIMEOUT] Command did not complete within ${Timeout}s - skipped.`n"
        } else {
            $raw = $job | Receive-Job 2>&1 | Out-String
            $job | Remove-Job -Force -ErrorAction SilentlyContinue
            $raw = Mask-Sensitive -Text $raw
            $lines = $raw -split "`n"
            if ($lines.Count -gt $MaxLines) {
                $section += ($lines[0..($MaxLines - 1)] -join "`n") + "`n"
                $section += "  ... (truncated, showing first $MaxLines of $($lines.Count) lines)`n"
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
            $section += "  ... (truncated, showing first $MaxLines of $($lines.Count) lines)`n"
        } else {
            $section += $raw + "`n"
        }
    } catch {
        $section += "  [ERROR] $($_.Exception.Message)`n"
    }

    return $section
}

# ─── Pre-flight ──────────────────────────────────────────────────────────────

# Refuse to run as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] This tool must NOT run as Administrator. Please run as a normal user." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SysKit Scanner - Windows Safe Mode"     -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[*] All commands are READ-ONLY. No system changes will be made."
Write-Host "[*] Report will be saved to: $REPORT_FILE"
Write-Host ""

if (-not (Test-Path $REPORT_DIR)) {
    New-Item -ItemType Directory -Path $REPORT_DIR -Force | Out-Null
}

$report = Write-Banner

# ─── 1. System Information ───────────────────────────────────────────────────
Write-Host "[1/12] System Information..." -ForegroundColor Yellow

$report += Run-DirectCommand -Label "OS & Build" -Command {
    Get-CimInstance Win32_OperatingSystem |
        Select-Object Caption, Version, BuildNumber, OSArchitecture,
                      LastBootUpTime, InstallDate |
        Format-List
}

$report += Run-DirectCommand -Label "Computer System" -Command {
    Get-CimInstance Win32_ComputerSystem |
        Select-Object Name, Domain, Manufacturer, Model, TotalPhysicalMemory |
        Format-List
}

$report += Run-DirectCommand -Label "BIOS / Firmware" -Command {
    Get-CimInstance Win32_BIOS |
        Select-Object Manufacturer, SMBIOSBIOSVersion, ReleaseDate |
        Format-List
}

# ─── 2. Network Configuration ───────────────────────────────────────────────
Write-Host "[2/12] Network Configuration..." -ForegroundColor Yellow

$report += Run-DirectCommand -Label "IP Configuration" -Command {
    Get-NetIPConfiguration | Format-List
}

$report += Run-DirectCommand -Label "Routing Table" -Command {
    Get-NetRoute -AddressFamily IPv4 |
        Select-Object DestinationPrefix, NextHop, RouteMetric, InterfaceAlias |
        Format-Table -AutoSize
}

$report += Run-DirectCommand -Label "DNS Client Settings" -Command {
    Get-DnsClientServerAddress -AddressFamily IPv4 |
        Select-Object InterfaceAlias, ServerAddresses |
        Format-Table -AutoSize
}

# ─── 3. Network Connectivity Tests ──────────────────────────────────────────
Write-Host "[3/12] Network Connectivity Tests..." -ForegroundColor Yellow

$report += Run-SafeCommand -Label "Ping 8.8.8.8 (Google DNS)" -Command {
    Test-NetConnection -ComputerName 8.8.8.8 -InformationLevel Detailed
}

$report += Run-SafeCommand -Label "DNS Resolution Test (google.com)" -Command {
    Resolve-DnsName google.com -Type A -ErrorAction Stop | Format-Table
}

$report += Run-SafeCommand -Label "Public IP (ifconfig.co)" -Command {
    try {
        $ip = Invoke-RestMethod -Uri "https://ifconfig.co/ip" -TimeoutSec 5
        "Public IP: $($ip.Trim())"
    } catch { "Could not retrieve public IP: $_" }
}

$report += Run-SafeCommand -Label "Traceroute to 8.8.8.8 (max 10 hops)" -Command {
    Test-NetConnection -ComputerName 8.8.8.8 -TraceRoute -InformationLevel Detailed |
        Select-Object -ExpandProperty TraceRoute
}

# ─── 4. Listening & Established Connections ──────────────────────────────────
Write-Host "[4/12] Connections & Listening Ports..." -ForegroundColor Yellow

$report += Run-DirectCommand -Label "TCP Listening Ports" -Command {
    Get-NetTCPConnection -State Listen |
        Select-Object LocalAddress, LocalPort, OwningProcess |
        Sort-Object LocalPort |
        Format-Table -AutoSize
}

$report += Run-DirectCommand -Label "Established TCP Connections" -Command {
    Get-NetTCPConnection -State Established |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess |
        Sort-Object RemoteAddress |
        Format-Table -AutoSize
}

$report += Run-DirectCommand -Label "UDP Endpoints" -Command {
    Get-NetUDPEndpoint |
        Select-Object LocalAddress, LocalPort, OwningProcess |
        Sort-Object LocalPort |
        Format-Table -AutoSize
}

# ─── 5. Process Inspection ───────────────────────────────────────────────────
Write-Host "[5/12] Process Inspection..." -ForegroundColor Yellow

$report += Run-DirectCommand -Label "Top 25 Processes by CPU" -Command {
    Get-CimInstance Win32_Process |
        Select-Object ProcessId, Name,
            @{N='CPU(s)';E={[math]::Round($_.KernelModeTime/10000000 + $_.UserModeTime/10000000, 2)}},
            @{N='WS(MB)';E={[math]::Round($_.WorkingSetSize/1MB, 1)}},
            ExecutablePath |
        Sort-Object -Descending 'CPU(s)' |
        Select-Object -First 25 |
        Format-Table -AutoSize
}

$report += Run-DirectCommand -Label "Processes with Network Connections" -Command {
    $pids = (Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue).OwningProcess |
        Sort-Object -Unique
    Get-Process -Id $pids -ErrorAction SilentlyContinue |
        Select-Object Id, ProcessName, Path |
        Format-Table -AutoSize
}

# ─── 6. Startup Items & Auto-run ────────────────────────────────────────────
Write-Host "[6/12] Startup & Scheduled Tasks..." -ForegroundColor Yellow

$report += Run-DirectCommand -Label "Auto-Start Services" -Command {
    Get-Service |
        Where-Object { $_.StartType -eq 'Automatic' } |
        Select-Object Name, DisplayName, Status |
        Sort-Object Status -Descending |
        Format-Table -AutoSize
}

$report += Run-DirectCommand -Label "Startup Commands (CIM)" -Command {
    Get-CimInstance Win32_StartupCommand |
        Select-Object Name, Command, Location, User |
        Format-Table -AutoSize
}

$report += Run-DirectCommand -Label "Scheduled Tasks (non-Microsoft)" -Command {
    Get-ScheduledTask |
        Where-Object { $_.TaskPath -notlike "\Microsoft\*" -and $_.State -ne "Disabled" } |
        Select-Object TaskName, TaskPath, State |
        Format-Table -AutoSize
} -MaxLines 80

# ─── 7. User Accounts & Logins ──────────────────────────────────────────────
Write-Host "[7/12] Users & Login History..." -ForegroundColor Yellow

$report += Run-DirectCommand -Label "Local User Accounts" -Command {
    Get-LocalUser |
        Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet |
        Format-Table -AutoSize
}

$report += Run-SafeCommand -Label "Recent Logon Events (last 50)" -Command {
    try {
        Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 50 -ErrorAction Stop |
            Select-Object TimeCreated, Id,
                @{N='User';E={$_.Properties[5].Value}},
                @{N='LogonType';E={$_.Properties[8].Value}} |
            Format-Table -AutoSize
    } catch {
        "Could not read Security log (requires elevation) - SKIPPED"
    }
}

# ─── 8. Firewall Status ─────────────────────────────────────────────────────
Write-Host "[8/12] Firewall Status..." -ForegroundColor Yellow

$report += Run-DirectCommand -Label "Firewall Profiles" -Command {
    Get-NetFirewallProfile |
        Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction |
        Format-Table -AutoSize
}

$report += Run-DirectCommand -Label "Inbound Allow Rules (Enabled)" -Command {
    Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue |
        Select-Object -First 40 DisplayName, Profile, Direction, Action |
        Format-Table -AutoSize
}

# ─── 9. Disk & File System ──────────────────────────────────────────────────
Write-Host "[9/12] Disk & Storage..." -ForegroundColor Yellow

$report += Run-DirectCommand -Label "Disk Volumes" -Command {
    Get-Volume |
        Where-Object { $_.DriveLetter } |
        Select-Object DriveLetter, FileSystemLabel, FileSystem, SizeRemaining, Size |
        Format-Table -AutoSize
}

$report += Run-DirectCommand -Label "Disk Space Summary" -Command {
    Get-PSDrive -PSProvider FileSystem |
        Select-Object Name, Used, Free,
            @{N='Total(GB)';E={[math]::Round(($_.Used + $_.Free) / 1GB, 2)}},
            @{N='Free(GB)';E={[math]::Round($_.Free / 1GB, 2)}} |
        Format-Table -AutoSize
}

# ─── 10. Suspicious File Scan ───────────────────────────────────────────────
Write-Host "[10/12] Suspicious File Scan..." -ForegroundColor Yellow

$report += Run-DirectCommand -Label "Suspicious Files in Key Directories" -Command {
    $results = @()
    foreach ($dir in @(
        $env:TEMP,
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )) {
        if (Test-Path $dir) {
            foreach ($ext in @(
                "*.hta","*.scr","*.pif","*.wsf","*.vbe","*.vbs","*.jse",
                "*.gadget","*.url","*.docm","*.xlsm","*.reg"
            )) {
                $found = Get-ChildItem -Path $dir -Filter $ext -Recurse -ErrorAction SilentlyContinue -Force
                foreach ($f in $found) {
                    $results += [PSCustomObject]@{
                        Directory    = $dir
                        FileName     = $f.Name
                        Extension    = $f.Extension
                        SizeKB       = [math]::Round($f.Length / 1KB, 2)
                        LastModified = $f.LastWriteTime
                        FullPath     = $f.FullName
                    }
                }
            }
        }
    }
    if ($results.Count -gt 0) {
        "  [!] Found $($results.Count) suspicious file(s):`n"
        $results | Format-Table -AutoSize
    } else {
        "  [OK] No suspicious files found in scanned directories."
    }
}

# Fake-name process check
$report += Run-DirectCommand -Label "Processes with Suspicious Names" -Command {
    $suspectPatterns = @("svch0st", "scvhost", "svchos t", "lssas", "lsas s",
                         "explore.exe", "explor3r", "taskmgr32",
                         "winlogln", "dllhst", "spoolsrv")
    $procs = Get-Process -ErrorAction SilentlyContinue
    $hits = @()
    foreach ($p in $procs) {
        foreach ($pat in $suspectPatterns) {
            if ($p.ProcessName -like "*$pat*") {
                $hits += [PSCustomObject]@{
                    PID  = $p.Id
                    Name = $p.ProcessName
                    Path = $p.Path
                    CPU  = $p.CPU
                }
            }
        }
    }
    if ($hits.Count -gt 0) {
        "  [!] Found $($hits.Count) process(es) with suspicious names:`n"
        $hits | Format-Table -AutoSize
    } else {
        "  [OK] No obviously suspicious process names detected."
    }
}

# ─── 11. System Event Log Summary ───────────────────────────────────────────
Write-Host "[11/12] Event Log Summary..." -ForegroundColor Yellow

$report += Run-SafeCommand -Label "System Log - Errors (last 30)" -Command {
    Get-WinEvent -FilterHashtable @{LogName='System'; Level=2} -MaxEvents 30 -ErrorAction Stop |
        Select-Object TimeCreated, Id, ProviderName, Message |
        Format-Table -Wrap -AutoSize
}

$report += Run-SafeCommand -Label "Application Log - Errors (last 30)" -Command {
    Get-WinEvent -FilterHashtable @{LogName='Application'; Level=2} -MaxEvents 30 -ErrorAction Stop |
        Select-Object TimeCreated, Id, ProviderName, Message |
        Format-Table -Wrap -AutoSize
}

# ─── 12. Container / VM Detection ───────────────────────────────────────────
Write-Host "[12/12] Virtualization Detection..." -ForegroundColor Yellow

$report += Run-DirectCommand -Label "Virtualization Environment" -Command {
    $cs = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS
    $model = $cs.Model
    $mfg   = $cs.Manufacturer
    $biosVer = $bios.SMBIOSBIOSVersion

    $vmIndicators = @("Virtual", "VMware", "VirtualBox", "Hyper-V", "QEMU", "Xen", "KVM", "Parallels")
    $detected = $false
    foreach ($ind in $vmIndicators) {
        if ("$model $mfg $biosVer" -match $ind) {
            "  [VM] Detected virtualization: $ind"
            "       Model=$model  Manufacturer=$mfg  BIOS=$biosVer"
            $detected = $true
            break
        }
    }
    if (-not $detected) {
        "  [Physical] No virtualization indicators found."
        "       Model=$model  Manufacturer=$mfg  BIOS=$biosVer"
    }
}

# ─── Footer ──────────────────────────────────────────────────────────────────
$report += "`n`n"
$report += "================================================================================`n"
$report += "  Scan completed : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"
$report += "  Report saved to: $REPORT_FILE`n"
$report += "================================================================================`n"

# ─── Write Report ────────────────────────────────────────────────────────────
$report | Out-File -FilePath $REPORT_FILE -Encoding UTF8
Write-Host ""
Write-Host "[+] Scan complete! Report saved to:" -ForegroundColor Green
Write-Host "    $REPORT_FILE" -ForegroundColor Green
Write-Host ""
