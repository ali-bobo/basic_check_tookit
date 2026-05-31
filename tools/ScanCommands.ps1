<#
PowerShell helper to load `reports/scan_commands.json` and show/invoke commands.
Default behavior: show commands; use -Execute to actually run (WhatIf supported).
#>

param()

function Get-ScanCommands {
    param(
        [string]$Path = "$(Split-Path -Parent $MyInvocation.MyCommand.Path)\..\reports\scan_commands.json",
        [string]$Platform
    )
    $json = Get-Content -Path $Path -Raw | ConvertFrom-Json
    if ($Platform) {
        return $json | Where-Object { $_.platform -eq $Platform }
    }
    return $json
}

function Get-ScanCommandById {
    param(
        [string]$Id,
        [string]$Path = "$(Split-Path -Parent $MyInvocation.MyCommand.Path)\..\reports\scan_commands.json"
    )
    $json = Get-ScanCommands -Path $Path
    return $json | Where-Object { $_.id -eq $Id }
}

function Invoke-ScanCommand {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)] [string]$Id,
        [string]$Path = "$(Split-Path -Parent $MyInvocation.MyCommand.Path)\..\reports\scan_commands.json"
    )
    $cmd = Get-ScanCommandById -Id $Id -Path $Path
    if (-not $cmd) {
        Write-Error "Command id $Id not found"
        return
    }
    if ($cmd.requires_admin) {
        Write-Warning "This command is marked as requiring admin privileges. Execution not recommended in non-admin mode."
        return
    }
    $commandString = $cmd.command

    # Security: allowlist 驗證可執行檔名，防止指令注入 (CWE-78)
    $ALLOWED_EXECUTABLES = @(
        'free','ps','ss','df','uptime','who','last','uname','cat','find','grep',
        'awk','sed','sort','head','tail','ls','stat','id','hostname','ip','ping',
        'netstat','lsof','top','pgrep','date','lscpu','mount','df','du','file',
        'lsmod','dmesg','journalctl','systemctl','hostnamectl','timedatectl',
        'Get-Process','Get-Service','Get-NetTCPConnection','Get-NetFirewallProfile',
        'Get-CimInstance','Get-LocalUser','Get-Volume','Get-PSDrive',
        'Get-ScheduledTask','Get-WinEvent','Test-NetConnection','Get-MpComputerStatus'
    )

    # 取得第一個 token（可執行檔名稱）
    $parts = $commandString -split '\s+', 2
    $executable = [System.IO.Path]::GetFileNameWithoutExtension($parts[0])

    if ($executable -notin $ALLOWED_EXECUTABLES) {
        Write-Error "Security: executable '$executable' is not in the allowed list. Execution blocked."
        return
    }

    if ($PSCmdlet.ShouldProcess("Invoke command", $commandString)) {
        # 使用 & 運算子而非 Invoke-Expression，避免 shell injection
        $argString = if ($parts.Count -gt 1) { $parts[1] } else { '' }
        $argList = if ($argString) { $argString -split '\s+' } else { @() }
        & $parts[0] @argList
    } else {
        Write-Output "Dry-run: $commandString"
    }
}

<# Usage examples:
Get-ScanCommands -Platform linux
Get-ScanCommandById -Id linux_free
Invoke-ScanCommand -Id linux_free -WhatIf   # dry-run
#>
