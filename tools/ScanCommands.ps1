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
    if ($PSCmdlet.ShouldProcess("Invoke command", $commandString)) {
        Invoke-Expression $commandString
    } else {
        Write-Output "Dry-run: $commandString"
    }
}

<# Usage examples:
Get-ScanCommands -Platform linux
Get-ScanCommandById -Id linux_free
Invoke-ScanCommand -Id linux_free -WhatIf   # dry-run
#>
